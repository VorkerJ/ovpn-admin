package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type CommonRouteEntry struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"` // "ip" | "domain"
	Address        string   `json:"address,omitempty"`
	Mask           string   `json:"mask,omitempty"`
	Domain         string   `json:"domain,omitempty"`
	Description    string   `json:"description"`
	ResolvedIPs    []string `json:"resolved_ips,omitempty"`
	LastResolveAt  string   `json:"last_resolve_at,omitempty"`
	LastResolveErr string   `json:"last_resolve_err,omitempty"`
}

type CommonRoutesConfig struct {
	Routes []CommonRouteEntry `json:"routes"`
}

type ccdCommonRoute struct {
	Address     string
	Mask        string
	Tag         string
	Description string
}

var domainRegexp = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

func validateCommonRoute(e CommonRouteEntry) error {
	if len(e.Description) > 200 {
		return fmt.Errorf("description too long (max 200)")
	}
	if strings.ContainsAny(e.Description, "\n\r") {
		return fmt.Errorf("description must not contain newline characters")
	}
	if strings.Contains(e.Description, `"`) {
		return fmt.Errorf("description must not contain double-quote characters")
	}
	// Reserved CCD markers in a description would let a crafted route be
	// re-parsed as a control directive on round-trip. See parseCcd.
	if descriptionHasReservedMarker(e.Description) {
		return fmt.Errorf("description must not contain reserved markers (__redirect_gateway__, __exclusion_*, __common__, __user_domain__)")
	}
	switch e.Kind {
	case "ip":
		if e.Domain != "" {
			return fmt.Errorf("domain must be empty for kind=ip")
		}
		if net.ParseIP(e.Address) == nil {
			return fmt.Errorf("address %q is not a valid IP", e.Address)
		}
		if net.ParseIP(e.Mask) == nil {
			return fmt.Errorf("mask %q is not a valid IP-format netmask", e.Mask)
		}
		return nil
	case "domain":
		if e.Address != "" || e.Mask != "" {
			return fmt.Errorf("address/mask must be empty for kind=domain")
		}
		if !domainRegexp.MatchString(e.Domain) {
			return fmt.Errorf("domain %q is not a valid RFC1035 hostname", e.Domain)
		}
		return nil
	default:
		return fmt.Errorf("unknown kind %q (expected ip|domain)", e.Kind)
	}
}

// commonRoutesStore — потокобезопасный держатель CommonRoutesConfig.
type commonRoutesStore struct {
	mu  sync.RWMutex
	cfg CommonRoutesConfig
}

// copyCommonRoutesConfig возвращает глубокую копию конфига (включая срезы
// ResolvedIPs), чтобы изменения в копии не затрагивали оригинал.
func copyCommonRoutesConfig(cfg CommonRoutesConfig) CommonRoutesConfig {
	out := CommonRoutesConfig{Routes: make([]CommonRouteEntry, len(cfg.Routes))}
	for i, r := range cfg.Routes {
		c := r
		if r.ResolvedIPs != nil {
			c.ResolvedIPs = append([]string(nil), r.ResolvedIPs...)
		}
		out.Routes[i] = c
	}
	return out
}

// snapshot возвращает deep-copy конфига, безопасную для чтения без блокировки.
func (s *commonRoutesStore) snapshot() CommonRoutesConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return copyCommonRoutesConfig(s.cfg)
}

// replace заменяет конфиг целиком под write-lock'ом.
func (s *commonRoutesStore) replace(cfg CommonRoutesConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.Routes == nil {
		cfg.Routes = []CommonRouteEntry{}
	}
	s.cfg = cfg
}

// commonRouteError несёт HTTP-статус вместе с сообщением, чтобы mutate-замыкания
// внутри update() могли сигнализировать об ошибках валидации (дубликат, не найдено),
// которые нужно отобразить конкретным кодом ответа. Ошибки persist в это не
// заворачиваются и трактуются вызывающим кодом как 500.
type commonRouteError struct {
	status int
	msg    string
}

func (e *commonRouteError) Error() string { return e.msg }

// update атомарно применяет mutate к рабочей копии конфига под write-lock'ом,
// СНАЧАЛА сохраняет результат через persist и только ПОСЛЕ успешного сохранения
// публикует новое состояние в памяти. Это сериализует весь цикл
// read-modify-write, поэтому конкурентные обработчики не могут потерять правки
// друг друга (lost update), и гарантирует, что состояния в памяти и на диске
// никогда не расходятся: если mutate или persist вернули ошибку, сохранённый
// конфиг остаётся нетронутым.
//
// mutate получает указатель на глубокую копию, которую волен изменять. При
// успехе update возвращает свежую копию зафиксированного конфига.
func (s *commonRoutesStore) update(
	mutate func(cfg *CommonRoutesConfig) error,
	persist func(cfg CommonRoutesConfig) error,
) (CommonRoutesConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	working := copyCommonRoutesConfig(s.cfg)
	if err := mutate(&working); err != nil {
		return CommonRoutesConfig{}, err
	}
	if working.Routes == nil {
		working.Routes = []CommonRouteEntry{}
	}
	// Persist FIRST — публикуем в памяти только после успешного сохранения,
	// иначе провал записи оставил бы память и диск в расходящихся состояниях.
	if persist != nil {
		if err := persist(working); err != nil {
			return CommonRoutesConfig{}, err
		}
	}
	s.cfg = working
	return copyCommonRoutesConfig(working), nil
}

// writeCommonRouteError отображает ошибку из update() в HTTP-ответ: типизированный
// commonRouteError несёт свой статус/сообщение, всё остальное — ошибка persist,
// отдаётся как 500 "persist failed".
func writeCommonRouteError(w http.ResponseWriter, err error, logCtx string) {
	var cre *commonRouteError
	if errors.As(err, &cre) {
		writeJSONError(w, cre.status, cre.msg)
		return
	}
	log.Errorf("%s: %v", logCtx, err)
	writeJSONError(w, http.StatusInternalServerError, "persist failed")
}

// newCommonRoutesStoreForTesting — конструктор для тестов; в проде создаётся в main.go.
func newCommonRoutesStoreForTesting() *commonRoutesStore {
	return &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}
}

// File-level lock на запись CCD-файлов (используется в задаче с rerenderAllCcds).
var ccdMu sync.Mutex

const commonRoutesSecretName = "ovpn-admin-common-routes"
const commonRoutesSecretDataKey = "data"

func serializeCommonRoutes(cfg CommonRoutesConfig) ([]byte, error) {
	if cfg.Routes == nil {
		cfg.Routes = []CommonRouteEntry{}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func deserializeCommonRoutes(data []byte) (CommonRoutesConfig, error) {
	if len(data) == 0 {
		return CommonRoutesConfig{Routes: []CommonRouteEntry{}}, nil
	}
	var cfg CommonRoutesConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return CommonRoutesConfig{}, err
	}
	if cfg.Routes == nil {
		cfg.Routes = []CommonRouteEntry{}
	}
	return cfg, nil
}

func sortedIPv4Strings(ips []string) []string {
	out := append([]string(nil), ips...)
	sort.Strings(out)
	return out
}

func sameIPSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := sortedIPv4Strings(a)
	bc := sortedIPv4Strings(b)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

// activeDomainResolver is swapped at startup once --domain-resolver / OVPN_DOMAIN_RESOLVER
// is read. Tests override `domainResolver` directly to bypass DNS entirely.
var activeDomainResolver = net.DefaultResolver

// configureDomainResolver wires `activeDomainResolver` to dial the operator's
// chosen DNS server (e.g. 8.8.8.8) instead of the container's /etc/resolv.conf.
// addr can be either `host` (port 53 assumed) or `host:port`. Empty string
// keeps the Go default resolver. Returns the effective address used.
func configureDomainResolver(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		activeDomainResolver = net.DefaultResolver
		return "system (/etc/resolv.conf)"
	}
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	chosen := addr
	activeDomainResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", chosen)
		},
	}
	return chosen
}

// resolveOneDomain выполняет один LookupIP с таймаутом и возвращает только IPv4.
func resolveOneDomain(ctx context.Context, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := activeDomainResolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no A records")
	}
	out := make([]string, 0, len(addrs))
	for _, ip := range addrs {
		out = append(out, ip.String())
	}
	return sortedIPv4Strings(out), nil
}

// domainResolver — переменная для возможности подмены в тестах.
var domainResolver = resolveOneDomain

// refreshAllDomains итерирует cfg, резолвит каждый kind=domain.
// Возвращает: (изменённый cfg, changed?, resolvedCount, failedCount).
func refreshAllDomains(ctx context.Context, cfg CommonRoutesConfig, now time.Time) (CommonRoutesConfig, bool, int, int) {
	changed := false
	resolved, failed := 0, 0
	for i, r := range cfg.Routes {
		if r.Kind != "domain" {
			continue
		}
		ips, err := domainResolver(ctx, r.Domain)
		cfg.Routes[i].LastResolveAt = now.UTC().Format(time.RFC3339)
		if err != nil {
			cfg.Routes[i].LastResolveErr = err.Error()
			failed++
			continue
		}
		cfg.Routes[i].LastResolveErr = ""
		if !sameIPSet(r.ResolvedIPs, ips) {
			cfg.Routes[i].ResolvedIPs = ips
			changed = true
		}
		resolved++
	}
	return cfg, changed, resolved, failed
}

const commonRoutesRefreshIntervalHours = 24

// commonRoutesHandler dispatches GET (list) and POST (create) on /api/common-routes.
// Multi-method routes can't use requireMethod, so per-handler dispatch stays here.
func (oAdmin *OvpnAdmin) commonRoutesHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	switch r.Method {
	case http.MethodGet:
		snap := oAdmin.commonRoutes.snapshot()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"routes":               snap.Routes,
			"refreshIntervalHours": commonRoutesRefreshIntervalHours,
		})
	case http.MethodPost:
		// Multi-method route — MFA gate cannot be applied at the route level
		// (GET reads must remain accessible without MFA). Inline-check here.
		if !oAdmin.adminHasMfa(r) {
			writeJSONError(w, http.StatusPreconditionFailed, "MFA must be enabled to perform this action")
			return
		}
		oAdmin.handleCreateCommonRoute(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// commonRoutesItemHandler dispatches PUT/DELETE on /api/common-routes/{id}.
// Same multi-method pattern as commonRoutesHandler.
func (oAdmin *OvpnAdmin) commonRoutesItemHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	// Strip prefix to extract id. listenBaseUrl may add a prefix.
	id := strings.TrimPrefix(r.URL.Path, "/api/common-routes/")
	if idx := strings.Index(id, "/"); idx != -1 {
		id = id[:idx]
	}
	if id == "" || id == "refresh" {
		writeJSONError(w, http.StatusBadRequest, "missing id")
		return
	}
	// All branches here are writes (PUT/DELETE) — gate MFA before dispatch.
	if !oAdmin.adminHasMfa(r) {
		writeJSONError(w, http.StatusPreconditionFailed, "MFA must be enabled to perform this action")
		return
	}
	switch r.Method {
	case http.MethodPut:
		oAdmin.handleUpdateCommonRoute(w, r, id)
	case http.MethodDelete:
		oAdmin.handleDeleteCommonRoute(w, r, id)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// commonRoutesImportHandler POST /api/common-routes/import.
// Body: { "text": "<file contents — one route per line>" }.
// Parses every line; valid entries are appended to common routes;
// duplicates (vs. existing routes AND vs. each other within the same
// payload) are skipped; parse errors are returned with line numbers
// so the user can fix and retry. Always commits the partial result —
// the user can see what went in.
func (oAdmin *OvpnAdmin) commonRoutesImportHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	parsed, errs := parseImportText(req.Text)

	added := []ImportedRoute{}
	skipped := []ImportedRoute{}

	committed, err := oAdmin.commonRoutes.update(func(cfg *CommonRoutesConfig) error {
		// Build dedup set against existing common routes.
		existing := map[string]struct{}{}
		for _, e := range cfg.Routes {
			var k string
			if e.Kind == "domain" {
				k = "d:" + strings.ToLower(strings.TrimSpace(e.Domain))
			} else {
				k = "i:" + e.Address + "/" + e.Mask
			}
			existing[k] = struct{}{}
		}

		for _, p := range parsed {
			key := routeDedupKey(p)
			if _, dup := existing[key]; dup {
				skipped = append(skipped, p)
				continue
			}
			entry := CommonRouteEntry{
				ID:     uuid.New().String(),
				Kind:   p.Kind,
				Domain: p.Domain,
			}
			if p.Kind == "ip" {
				entry.Address = p.Address
				entry.Mask = p.Mask
			}
			if verr := validateCommonRoute(entry); verr != nil {
				errs = append(errs, ImportLineError{Source: importDescribe(p), Reason: verr.Error()})
				continue
			}
			// Resolve domain synchronously so the first connect after import
			// already has the IPs.
			if entry.Kind == "domain" {
				ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				ips, derr := domainResolver(ctx, entry.Domain)
				cancel()
				entry.LastResolveAt = time.Now().UTC().Format(time.RFC3339)
				if derr != nil {
					entry.LastResolveErr = derr.Error()
				} else {
					entry.ResolvedIPs = ips
				}
			}
			cfg.Routes = append(cfg.Routes, entry)
			existing[key] = struct{}{}
			added = append(added, p)
		}
		return nil
	}, oAdmin.persistCommonRoutes)
	if err != nil {
		log.Errorf("commonRoutesImport: persist: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "persist failed")
		return
	}
	expanded := expandCommonRoutes(committed)
	go oAdmin.rerenderAllCcds(expanded)
	if oAdmin.firewall != nil {
		oAdmin.firewall.push(fwEvent{Kind: EvCommonChanged})
	}

	writeJSON(w, http.StatusOK, ImportResult{Added: added, Skipped: skipped, Errors: errs})
}

// importDescribe formats a parsed route for error-message context.
func importDescribe(r ImportedRoute) string {
	if r.Kind == "domain" {
		return r.Domain
	}
	return r.Address + " " + r.Mask
}

// commonRoutesRefreshHandler POST /api/common-routes/refresh.
// Method check is enforced by middleware at route registration.
func (oAdmin *OvpnAdmin) commonRoutesRefreshHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	var changed bool
	var okCount, failed int
	committed, err := oAdmin.commonRoutes.update(func(cfg *CommonRoutesConfig) error {
		updated, ch, ok, f := refreshAllDomains(r.Context(), *cfg, time.Now())
		*cfg = updated
		changed, okCount, failed = ch, ok, f
		return nil
	}, oAdmin.persistCommonRoutes)
	if err != nil {
		// Persist failed — in-memory state left unchanged (no divergence with
		// disk). Report the resolution counts we gathered, but do not publish.
		log.Errorf("persistCommonRoutes: %v", err)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"resolved": okCount,
			"failed":   failed,
			"changed":  false,
		})
		return
	}

	if changed {
		expanded := expandCommonRoutes(committed)
		go oAdmin.rerenderAllCcds(expanded)
		if oAdmin.firewall != nil {
			oAdmin.firewall.push(fwEvent{Kind: EvCommonChanged})
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"resolved": okCount,
		"failed":   failed,
		"changed":  changed,
	})
}

func (oAdmin *OvpnAdmin) handleCreateCommonRoute(w http.ResponseWriter, r *http.Request) {
	var in CommonRouteEntry
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		log.Debugf("common-routes: decode body: %v", err)
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	in.ID = uuid.New().String()
	if err := validateCommonRoute(in); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	committed, err := oAdmin.commonRoutes.update(func(cfg *CommonRoutesConfig) error {
		if isDuplicateCommonRoute(*cfg, in) {
			return &commonRouteError{http.StatusConflict, "duplicate entry"}
		}
		if in.Kind == "domain" {
			ips, derr := domainResolver(r.Context(), in.Domain)
			in.LastResolveAt = time.Now().UTC().Format(time.RFC3339)
			if derr != nil {
				in.LastResolveErr = derr.Error()
			} else {
				in.ResolvedIPs = ips
				in.LastResolveErr = ""
			}
		}
		cfg.Routes = append(cfg.Routes, in)
		return nil
	}, oAdmin.persistCommonRoutes)
	if err != nil {
		writeCommonRouteError(w, err, "persist")
		return
	}

	expanded := expandCommonRoutes(committed)
	go oAdmin.rerenderAllCcds(expanded)
	if oAdmin.firewall != nil {
		oAdmin.firewall.push(fwEvent{Kind: EvCommonChanged})
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{"route": in})
}

func (oAdmin *OvpnAdmin) handleUpdateCommonRoute(w http.ResponseWriter, r *http.Request, id string) {
	var in CommonRouteEntry
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		log.Debugf("common-routes: decode body: %v", err)
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	in.ID = id
	if err := validateCommonRoute(in); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	committed, err := oAdmin.commonRoutes.update(func(cfg *CommonRoutesConfig) error {
		idx := -1
		for i, rt := range cfg.Routes {
			if rt.ID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			return &commonRouteError{http.StatusNotFound, "not found"}
		}

		// preserve DNS state if domain didn't change
		if in.Kind == "domain" && cfg.Routes[idx].Kind == "domain" && cfg.Routes[idx].Domain == in.Domain {
			in.ResolvedIPs = cfg.Routes[idx].ResolvedIPs
			in.LastResolveAt = cfg.Routes[idx].LastResolveAt
			in.LastResolveErr = cfg.Routes[idx].LastResolveErr
		} else if in.Kind == "domain" {
			ips, derr := domainResolver(r.Context(), in.Domain)
			in.LastResolveAt = time.Now().UTC().Format(time.RFC3339)
			if derr != nil {
				in.LastResolveErr = derr.Error()
			} else {
				in.ResolvedIPs = ips
			}
		}

		if isDuplicateCommonRoute(removeAt(*cfg, idx), in) {
			return &commonRouteError{http.StatusConflict, "duplicate entry"}
		}

		cfg.Routes[idx] = in
		return nil
	}, oAdmin.persistCommonRoutes)
	if err != nil {
		writeCommonRouteError(w, err, "persist")
		return
	}

	expanded := expandCommonRoutes(committed)
	go oAdmin.rerenderAllCcds(expanded)
	if oAdmin.firewall != nil {
		oAdmin.firewall.push(fwEvent{Kind: EvCommonChanged})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"route": in})
}

func (oAdmin *OvpnAdmin) handleDeleteCommonRoute(w http.ResponseWriter, r *http.Request, id string) {
	committed, err := oAdmin.commonRoutes.update(func(cfg *CommonRoutesConfig) error {
		idx := -1
		for i, rt := range cfg.Routes {
			if rt.ID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			return &commonRouteError{http.StatusNotFound, "not found"}
		}
		cfg.Routes = append(cfg.Routes[:idx], cfg.Routes[idx+1:]...)
		return nil
	}, oAdmin.persistCommonRoutes)
	if err != nil {
		writeCommonRouteError(w, err, "persist")
		return
	}

	expanded := expandCommonRoutes(committed)
	go oAdmin.rerenderAllCcds(expanded)
	if oAdmin.firewall != nil {
		oAdmin.firewall.push(fwEvent{Kind: EvCommonChanged})
	}

	w.WriteHeader(http.StatusNoContent)
}

func isDuplicateCommonRoute(cfg CommonRoutesConfig, e CommonRouteEntry) bool {
	for _, r := range cfg.Routes {
		if r.ID == e.ID {
			continue
		}
		switch e.Kind {
		case "ip":
			if r.Kind == "ip" && r.Address == e.Address && r.Mask == e.Mask {
				return true
			}
		case "domain":
			if r.Kind == "domain" && r.Domain == e.Domain {
				return true
			}
		}
	}
	return false
}

func removeAt(cfg CommonRoutesConfig, idx int) CommonRoutesConfig {
	out := CommonRoutesConfig{Routes: make([]CommonRouteEntry, 0, len(cfg.Routes)-1)}
	for i, r := range cfg.Routes {
		if i == idx {
			continue
		}
		out.Routes = append(out.Routes, r)
	}
	return out
}

// persistCommonRoutes saves config to the configured backend.
func (oAdmin *OvpnAdmin) persistCommonRoutes(cfg CommonRoutesConfig) error {
	data, err := serializeCommonRoutes(cfg)
	if err != nil {
		return err
	}
	return oAdmin.store.SaveCommonRoutes(data)
}

func expandCommonRoutes(cfg CommonRoutesConfig) []ccdCommonRoute {
	out := make([]ccdCommonRoute, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		switch r.Kind {
		case "ip":
			out = append(out, ccdCommonRoute{
				Address:     r.Address,
				Mask:        r.Mask,
				Tag:         "static",
				Description: r.Description,
			})
		case "domain":
			for _, ip := range r.ResolvedIPs {
				out = append(out, ccdCommonRoute{
					Address:     ip,
					Mask:        "255.255.255.255",
					Tag:         r.Domain,
					Description: r.Description,
				})
			}
		}
	}
	return out
}

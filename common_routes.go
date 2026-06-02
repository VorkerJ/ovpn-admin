package main

import (
	"context"
	"encoding/json"
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

// snapshot возвращает deep-copy конфига, безопасную для чтения без блокировки.
func (s *commonRoutesStore) snapshot() CommonRoutesConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := CommonRoutesConfig{Routes: make([]CommonRouteEntry, len(s.cfg.Routes))}
	for i, r := range s.cfg.Routes {
		c := r
		if r.ResolvedIPs != nil {
			c.ResolvedIPs = append([]string(nil), r.ResolvedIPs...)
		}
		out.Routes[i] = c
	}
	return out
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

// withWrite берёт write-lock, передаёт указатель на cfg в callback (внутри — модификации).
// Возвращает копию изменённого конфига, чтобы можно было сохранить наружу без удержания lock'а.
func (s *commonRoutesStore) withWrite(fn func(cfg *CommonRoutesConfig) error) (CommonRoutesConfig, error) {
	s.mu.Lock()
	if err := fn(&s.cfg); err != nil {
		s.mu.Unlock()
		return CommonRoutesConfig{}, err
	}
	cfgCopy := s.cfg
	s.mu.Unlock()
	return cfgCopy, nil
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

// resolveOneDomain выполняет один LookupIP с таймаутом и возвращает только IPv4.
func resolveOneDomain(ctx context.Context, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
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

// commonRoutesRefreshHandler POST /api/common-routes/refresh.
// Method check is enforced by middleware at route registration.
func (oAdmin *OvpnAdmin) commonRoutesRefreshHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	current := oAdmin.commonRoutes.snapshot()
	updated, changed, okCount, failed := refreshAllDomains(r.Context(), current, time.Now())

	oAdmin.commonRoutes.replace(updated)
	if err := oAdmin.persistCommonRoutes(updated); err != nil {
		log.Errorf("persistCommonRoutes: %v", err)
	}

	if changed {
		expanded := expandCommonRoutes(updated)
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

	current := oAdmin.commonRoutes.snapshot()
	if isDuplicateCommonRoute(current, in) {
		writeJSONError(w, http.StatusConflict, "duplicate entry")
		return
	}

	if in.Kind == "domain" {
		ips, err := domainResolver(r.Context(), in.Domain)
		in.LastResolveAt = time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			in.LastResolveErr = err.Error()
		} else {
			in.ResolvedIPs = ips
			in.LastResolveErr = ""
		}
	}

	current.Routes = append(current.Routes, in)
	oAdmin.commonRoutes.replace(current)
	if err := oAdmin.persistCommonRoutes(current); err != nil {
		log.Errorf("persist: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "persist failed")
		return
	}

	expanded := expandCommonRoutes(current)
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

	current := oAdmin.commonRoutes.snapshot()
	idx := -1
	for i, rt := range current.Routes {
		if rt.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}

	// preserve DNS state if domain didn't change
	if in.Kind == "domain" && current.Routes[idx].Kind == "domain" && current.Routes[idx].Domain == in.Domain {
		in.ResolvedIPs = current.Routes[idx].ResolvedIPs
		in.LastResolveAt = current.Routes[idx].LastResolveAt
		in.LastResolveErr = current.Routes[idx].LastResolveErr
	} else if in.Kind == "domain" {
		ips, err := domainResolver(r.Context(), in.Domain)
		in.LastResolveAt = time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			in.LastResolveErr = err.Error()
		} else {
			in.ResolvedIPs = ips
		}
	}

	if isDuplicateCommonRoute(removeAt(current, idx), in) {
		writeJSONError(w, http.StatusConflict, "duplicate entry")
		return
	}

	current.Routes[idx] = in
	oAdmin.commonRoutes.replace(current)
	if err := oAdmin.persistCommonRoutes(current); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "persist failed")
		return
	}

	expanded := expandCommonRoutes(current)
	go oAdmin.rerenderAllCcds(expanded)
	if oAdmin.firewall != nil {
		oAdmin.firewall.push(fwEvent{Kind: EvCommonChanged})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"route": in})
}

func (oAdmin *OvpnAdmin) handleDeleteCommonRoute(w http.ResponseWriter, r *http.Request, id string) {
	current := oAdmin.commonRoutes.snapshot()
	idx := -1
	for i, rt := range current.Routes {
		if rt.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	current.Routes = append(current.Routes[:idx], current.Routes[idx+1:]...)
	oAdmin.commonRoutes.replace(current)
	if err := oAdmin.persistCommonRoutes(current); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "persist failed")
		return
	}

	expanded := expandCommonRoutes(current)
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

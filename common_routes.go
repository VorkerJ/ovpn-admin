package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"sync"
	"time"
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

func loadCommonRoutesFromFile(path string) (CommonRoutesConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return CommonRoutesConfig{Routes: []CommonRouteEntry{}}, nil
		}
		return CommonRoutesConfig{}, err
	}
	var cfg CommonRoutesConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return CommonRoutesConfig{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Routes == nil {
		cfg.Routes = []CommonRouteEntry{}
	}
	return cfg, nil
}

func saveCommonRoutesToFile(path string, cfg CommonRoutesConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

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

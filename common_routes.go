package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sync"
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

// Concurrency primitives — будут использоваться в следующих задачах.
type commonRoutesStore struct {
	mu  sync.RWMutex
	cfg CommonRoutesConfig
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

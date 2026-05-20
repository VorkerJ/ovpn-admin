package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestValidateCommonRoute_IP_OK(t *testing.T) {
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.0.0", Description: "lan"}
	if err := validateCommonRoute(e); err != nil {
		t.Fatalf("expected ok, got: %v", err)
	}
}

func TestValidateCommonRoute_IP_BadAddress(t *testing.T) {
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.999", Mask: "255.255.0.0"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on bad address")
	}
}

func TestValidateCommonRoute_IP_BadMask(t *testing.T) {
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "not-a-mask"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on bad mask")
	}
}

func TestValidateCommonRoute_IP_DomainFieldNotEmpty(t *testing.T) {
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.0.0", Domain: "leak"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error when domain set for kind=ip")
	}
}

func TestValidateCommonRoute_Domain_OK(t *testing.T) {
	e := CommonRouteEntry{Kind: "domain", Domain: "youtube.com"}
	if err := validateCommonRoute(e); err != nil {
		t.Fatalf("expected ok, got: %v", err)
	}
}

func TestValidateCommonRoute_Domain_BadDomain(t *testing.T) {
	cases := []string{"", "no_underscore_allowed.com", "-leading-dash.com", "trailing-.com", "single"}
	for _, d := range cases {
		e := CommonRouteEntry{Kind: "domain", Domain: d}
		if err := validateCommonRoute(e); err == nil {
			t.Errorf("expected error for domain %q", d)
		}
	}
}

func TestValidateCommonRoute_Domain_IPFieldNotEmpty(t *testing.T) {
	e := CommonRouteEntry{Kind: "domain", Domain: "youtube.com", Address: "1.1.1.1"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error when address set for kind=domain")
	}
}

func TestValidateCommonRoute_BadKind(t *testing.T) {
	e := CommonRouteEntry{Kind: "weird"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on bad kind")
	}
}

func TestValidateCommonRoute_DescriptionTooLong(t *testing.T) {
	long := make([]byte, 201)
	for i := range long {
		long[i] = 'x'
	}
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.0.0", Description: string(long)}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on description > 200")
	}
}

func TestCommonRoutesFileStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "_common_routes.json")

	original := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "abc", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0", Description: "lan"},
		{ID: "def", Kind: "domain", Domain: "x.io", ResolvedIPs: []string{"1.2.3.4"}},
	}}

	if err := saveCommonRoutesToFile(path, original); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := loadCommonRoutesFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(loaded.Routes))
	}
	if loaded.Routes[1].Domain != "x.io" || loaded.Routes[1].ResolvedIPs[0] != "1.2.3.4" {
		t.Fatalf("data mismatch: %+v", loaded.Routes[1])
	}
}

func TestCommonRoutesFileStore_LoadMissingReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.json")

	cfg, err := loadCommonRoutesFromFile(path)
	if err != nil {
		t.Fatalf("expected no error on missing, got: %v", err)
	}
	if len(cfg.Routes) != 0 {
		t.Fatalf("expected empty routes, got: %+v", cfg.Routes)
	}
}

func TestCommonRoutesFileStore_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "_common_routes.json")

	// Первая запись
	if err := saveCommonRoutesToFile(path, CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "1"}}}); err != nil {
		t.Fatal(err)
	}
	// Вторая запись
	if err := saveCommonRoutesToFile(path, CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "2"}}}); err != nil {
		t.Fatal(err)
	}
	// .tmp файла быть не должно после успеха
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file not cleaned: %v", err)
	}
}

func TestCommonRoutesSecret_KeyName(t *testing.T) {
	if commonRoutesSecretName != "ovpn-admin-common-routes" {
		t.Fatalf("unexpected secret name: %s", commonRoutesSecretName)
	}
}

func TestCommonRoutesSerialize(t *testing.T) {
	cfg := CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "x", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"}}}
	data, err := serializeCommonRoutes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := deserializeCommonRoutes(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Routes[0].ID != "x" {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestCommonRoutesDeserialize_EmptyInput(t *testing.T) {
	cfg, err := deserializeCommonRoutes(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 0 {
		t.Fatalf("expected empty, got %+v", cfg)
	}
}

func TestCommonRoutesStore_ConcurrentReadWrite(t *testing.T) {
	store := newCommonRoutesStoreForTesting()
	store.replace(CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "a", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"}}})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = store.snapshot()
		}()
		go func() {
			defer wg.Done()
			store.replace(CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "b", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"}}})
		}()
	}
	wg.Wait()
}

func TestCommonRoutesStore_SnapshotIsCopy(t *testing.T) {
	store := newCommonRoutesStoreForTesting()
	store.replace(CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "a", Kind: "domain", Domain: "x.io", ResolvedIPs: []string{"1.1.1.1"}}}})

	snap := store.snapshot()
	snap.Routes[0].ResolvedIPs[0] = "9.9.9.9"

	again := store.snapshot()
	if again.Routes[0].ResolvedIPs[0] == "9.9.9.9" {
		t.Fatal("snapshot must not share underlying slice")
	}
}

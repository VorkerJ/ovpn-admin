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

func TestExpandCommonRoutes_IP(t *testing.T) {
	cfg := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "a", Kind: "ip", Address: "10.0.0.0", Mask: "255.255.0.0", Description: "lan"},
	}}
	out := expandCommonRoutes(cfg)
	if len(out) != 1 {
		t.Fatalf("want 1, got %d", len(out))
	}
	if out[0].Address != "10.0.0.0" || out[0].Mask != "255.255.0.0" || out[0].Tag != "static" {
		t.Fatalf("got %+v", out[0])
	}
}

func TestExpandCommonRoutes_Domain_MultipleIPs(t *testing.T) {
	cfg := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "b", Kind: "domain", Domain: "yt.com", ResolvedIPs: []string{"1.1.1.1", "2.2.2.2"}, Description: "youtube"},
	}}
	out := expandCommonRoutes(cfg)
	if len(out) != 2 {
		t.Fatalf("want 2, got %d", len(out))
	}
	for _, r := range out {
		if r.Mask != "255.255.255.255" {
			t.Errorf("expected /32 mask, got %s", r.Mask)
		}
		if r.Tag != "yt.com" {
			t.Errorf("expected tag=yt.com, got %s", r.Tag)
		}
	}
}

func TestExpandCommonRoutes_Domain_EmptyResolved(t *testing.T) {
	cfg := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "c", Kind: "domain", Domain: "fail.com", ResolvedIPs: nil},
	}}
	out := expandCommonRoutes(cfg)
	if len(out) != 0 {
		t.Fatalf("expected nothing for unresolved domain, got %d", len(out))
	}
}

func TestExpandCommonRoutes_Mixed(t *testing.T) {
	cfg := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"},
		{Kind: "domain", Domain: "yt.com", ResolvedIPs: []string{"1.1.1.1"}},
		{Kind: "domain", Domain: "unresolved.com"},
	}}
	out := expandCommonRoutes(cfg)
	if len(out) != 2 {
		t.Fatalf("want 2, got %d", len(out))
	}
}

func TestParseCcd_FiltersCommonMarker(t *testing.T) {
	dir := t.TempDir()
	username := "alice"
	path := dir + "/" + username
	content := `ifconfig-push 10.0.0.5 255.255.255.0
push "route 192.168.1.0 255.255.255.0" # corp
push "route 142.250.1.1 255.255.255.255" # __common__:yt.com youtube
push "route 142.250.1.2 255.255.255.255" # __common__:yt.com youtube
push "route 8.8.8.8 255.255.255.255" # dns
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	original := *ccdDir
	tmp := dir
	ccdDir = &tmp
	defer func() { ccdDir = &original }()

	// We also need to force storage backend to filesystem (in case it was changed by other tests)
	originalStorage := *storageBackend
	fs := "filesystem"
	storageBackend = &fs
	defer func() { storageBackend = &originalStorage }()

	oAdmin := &OvpnAdmin{}
	ccd := oAdmin.parseCcd(username)
	if ccd.ClientAddress != "10.0.0.5" {
		t.Errorf("ClientAddress: got %s", ccd.ClientAddress)
	}
	if len(ccd.CustomRoutes) != 2 {
		t.Fatalf("expected 2 user routes (192.168.x and 8.8.8.8), got %d: %+v", len(ccd.CustomRoutes), ccd.CustomRoutes)
	}
	for _, r := range ccd.CustomRoutes {
		if r.Address == "142.250.1.1" || r.Address == "142.250.1.2" {
			t.Errorf("__common__ route leaked into user routes: %+v", r)
		}
	}
}

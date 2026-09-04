package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"io/fs"
)

// TestMain mirrors production startup: main() calls kingpin.Parse(), which
// applies the "/" default to --listen.base-url. Tests never call Parse(), so
// without this the flag pointer holds "" and prefix-stripping (which now uses
// the configured *listenBaseUrl) would not match the "/api/..." request paths
// the handler tests build. Set it once for the whole package.
func TestMain(m *testing.M) {
	*listenBaseUrl = "/"
	os.Exit(m.Run())
}

func TestValidateCommonRoute_IP_OK(t *testing.T) {
	t.Parallel()
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.0.0", Description: "lan"}
	if err := validateCommonRoute(e); err != nil {
		t.Fatalf("expected ok, got: %v", err)
	}
}

func TestValidateCommonRoute_IP_BadAddress(t *testing.T) {
	t.Parallel()
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.999", Mask: "255.255.0.0"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on bad address")
	}
}

func TestValidateCommonRoute_IP_BadMask(t *testing.T) {
	t.Parallel()
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "not-a-mask"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on bad mask")
	}
}

func TestValidateCommonRoute_IP_DomainFieldNotEmpty(t *testing.T) {
	t.Parallel()
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.0.0", Domain: "leak"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error when domain set for kind=ip")
	}
}

func TestValidateCommonRoute_Domain_OK(t *testing.T) {
	t.Parallel()
	e := CommonRouteEntry{Kind: "domain", Domain: "youtube.com"}
	if err := validateCommonRoute(e); err != nil {
		t.Fatalf("expected ok, got: %v", err)
	}
}

func TestValidateCommonRoute_Domain_BadDomain(t *testing.T) {
	t.Parallel()
	cases := []string{"", "no_underscore_allowed.com", "-leading-dash.com", "trailing-.com", "single"}
	for _, d := range cases {
		e := CommonRouteEntry{Kind: "domain", Domain: d}
		if err := validateCommonRoute(e); err == nil {
			t.Errorf("expected error for domain %q", d)
		}
	}
}

func TestValidateCommonRoute_Domain_IPFieldNotEmpty(t *testing.T) {
	t.Parallel()
	e := CommonRouteEntry{Kind: "domain", Domain: "youtube.com", Address: "1.1.1.1"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error when address set for kind=domain")
	}
}

func TestValidateCommonRoute_BadKind(t *testing.T) {
	t.Parallel()
	e := CommonRouteEntry{Kind: "weird"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on bad kind")
	}
}

func TestValidateCommonRoute_DescriptionTooLong(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	dir := t.TempDir()
	store := testFilesystemStore(dir)

	original := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "abc", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0", Description: "lan"},
		{ID: "def", Kind: "domain", Domain: "x.io", ResolvedIPs: []string{"1.2.3.4"}},
	}}

	data, err := serializeCommonRoutes(original)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if err := store.SaveCommonRoutes(data); err != nil {
		t.Fatalf("save: %v", err)
	}

	raw, err := store.LoadCommonRoutes()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	loaded, err := deserializeCommonRoutes(raw)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(loaded.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(loaded.Routes))
	}
	if loaded.Routes[1].Domain != "x.io" || loaded.Routes[1].ResolvedIPs[0] != "1.2.3.4" {
		t.Fatalf("data mismatch: %+v", loaded.Routes[1])
	}
}

func TestCommonRoutesFileStore_LoadMissingReturnsEmpty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := testFilesystemStore(dir)

	raw, err := store.LoadCommonRoutes()
	if err != nil {
		t.Fatalf("expected no error on missing, got: %v", err)
	}
	cfg, err := deserializeCommonRoutes(raw)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(cfg.Routes) != 0 {
		t.Fatalf("expected empty routes, got: %+v", cfg.Routes)
	}
}

func TestCommonRoutesFileStore_AtomicWrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := testFilesystemStore(dir)
	path := filepath.Join(dir, "_common_routes.json")

	mustSave := func(cfg CommonRoutesConfig) {
		t.Helper()
		data, err := serializeCommonRoutes(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SaveCommonRoutes(data); err != nil {
			t.Fatal(err)
		}
	}

	// Первая запись
	mustSave(CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "1"}}})
	// Вторая запись
	mustSave(CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "2"}}})
	// .tmp файла быть не должно после успеха
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file not cleaned: %v", err)
	}
}

func TestCommonRoutesSecret_KeyName(t *testing.T) {
	t.Parallel()
	if commonRoutesSecretName != "ovpn-admin-common-routes" {
		t.Fatalf("unexpected secret name: %s", commonRoutesSecretName)
	}
}

func TestCommonRoutesSerialize(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	cfg, err := deserializeCommonRoutes(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 0 {
		t.Fatalf("expected empty, got %+v", cfg)
	}
}

func TestCommonRoutesStore_ConcurrentReadWrite(t *testing.T) {
	t.Parallel()
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

// TestCommonRoutes_ConcurrentAdds_NoLostUpdate fires N concurrent POST /api/common-routes
// each adding a distinct route through the atomic update path, and asserts all N survive.
// Before the atomic read-modify-write fix this raced: two handlers could both read the
// same snapshot and the last write would clobber the earlier ones (lost update).
func TestCommonRoutes_ConcurrentAdds_NoLostUpdate(t *testing.T) {
	t.Parallel()
	app := newTestAdmin(t)

	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := []byte(fmt.Sprintf(
				`{"kind":"ip","address":"10.%d.%d.0","mask":"255.255.255.0","description":"r%d"}`,
				i/256, i%256, i))
			req := httptest.NewRequest(http.MethodPost, "/api/common-routes", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			app.commonRoutesHandler(rec, req)
			if rec.Code != http.StatusCreated {
				t.Errorf("add %d: status %d body=%s", i, rec.Code, rec.Body.String())
			}
		}(i)
	}
	wg.Wait()

	snap := app.commonRoutes.snapshot()
	if len(snap.Routes) != n {
		t.Fatalf("lost update: expected %d routes, got %d", n, len(snap.Routes))
	}
	seen := map[string]bool{}
	for _, r := range snap.Routes {
		seen[r.Address] = true
	}
	for i := 0; i < n; i++ {
		addr := fmt.Sprintf("10.%d.%d.0", i/256, i%256)
		if !seen[addr] {
			t.Errorf("route %s lost", addr)
		}
	}

	// The persisted config on disk must also carry all N (persist happens under
	// the same lock, before the in-memory commit).
	raw, err := app.store.LoadCommonRoutes()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	loaded, err := deserializeCommonRoutes(raw)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(loaded.Routes) != n {
		t.Fatalf("persisted config lost updates: expected %d routes, got %d", n, len(loaded.Routes))
	}
}

// TestCommonRoutesStore_Update_PersistFailureLeavesMemoryUnchanged verifies that
// when persistence fails the in-memory state is NOT mutated, so memory and disk
// never diverge (persist-before-publish).
func TestCommonRoutesStore_Update_PersistFailureLeavesMemoryUnchanged(t *testing.T) {
	t.Parallel()
	store := newCommonRoutesStoreForTesting()
	store.replace(CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "keep", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"},
	}})

	persistErr := fmt.Errorf("disk full")
	_, err := store.update(func(cfg *CommonRoutesConfig) error {
		cfg.Routes = append(cfg.Routes, CommonRouteEntry{ID: "new", Kind: "ip", Address: "10.1.0.0", Mask: "255.0.0.0"})
		return nil
	}, func(cfg CommonRoutesConfig) error {
		// persist sees the would-be new state...
		if len(cfg.Routes) != 2 {
			t.Errorf("persist should see the mutated (2-route) config, got %d", len(cfg.Routes))
		}
		return persistErr
	})
	if err == nil {
		t.Fatal("expected persist error")
	}
	snap := store.snapshot()
	if len(snap.Routes) != 1 || snap.Routes[0].ID != "keep" {
		t.Fatalf("in-memory state must be unchanged on persist failure, got %+v", snap.Routes)
	}
}

// TestCommonRoutesStore_Update_MutateErrorNoPersist verifies that if the mutate
// closure returns an error, persist is never called and state is unchanged.
func TestCommonRoutesStore_Update_MutateErrorNoPersist(t *testing.T) {
	t.Parallel()
	store := newCommonRoutesStoreForTesting()
	store.replace(CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "keep"}}})

	persisted := false
	_, err := store.update(func(cfg *CommonRoutesConfig) error {
		cfg.Routes = append(cfg.Routes, CommonRouteEntry{ID: "new"})
		return &commonRouteError{http.StatusConflict, "duplicate entry"}
	}, func(cfg CommonRoutesConfig) error {
		persisted = true
		return nil
	})
	if err == nil {
		t.Fatal("expected mutate error")
	}
	var cre *commonRouteError
	if !errors.As(err, &cre) || cre.status != http.StatusConflict {
		t.Fatalf("expected commonRouteError(409), got %v", err)
	}
	if persisted {
		t.Fatal("persist must not run when mutate fails")
	}
	if len(store.snapshot().Routes) != 1 {
		t.Fatal("state must be unchanged when mutate fails")
	}
}

func TestCommonRoutesStore_SnapshotIsCopy(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	cfg := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "c", Kind: "domain", Domain: "fail.com", ResolvedIPs: nil},
	}}
	out := expandCommonRoutes(cfg)
	if len(out) != 0 {
		t.Fatalf("expected nothing for unresolved domain, got %d", len(out))
	}
}

func TestExpandCommonRoutes_Mixed(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

	oAdmin := &OvpnAdmin{store: testFilesystemStore(dir)}
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

func TestModifyCcd_RendersCommonRoutes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	app := &OvpnAdmin{store: testFilesystemStore(dir)}
	tplSub, err := fs.Sub(templatesFS, "templates")
	if err != nil {
		t.Fatalf("cannot create sub-FS for templates: %v", err)
	}
	app.templates = tplSub

	ccd := Ccd{
		User:          "bob",
		ClientAddress: "dynamic",
		CustomRoutes:  []ccdRoute{{Address: "10.0.0.0", Mask: "255.255.255.0", Description: "lan"}},
	}
	common := []ccdCommonRoute{
		{Address: "1.1.1.1", Mask: "255.255.255.255", Tag: "yt.com", Description: "youtube"},
	}

	ok, msg := app.modifyCcd(ccd, common)
	if !ok {
		t.Fatalf("modifyCcd failed: %s", msg)
	}

	data, err := os.ReadFile(dir + "/bob")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, `push "route 10.0.0.0 255.255.255.0"`) {
		t.Errorf("user route missing:\n%s", content)
	}
	if !strings.Contains(content, `push "route 1.1.1.1 255.255.255.255" # __common__:yt.com`) {
		t.Errorf("common route missing:\n%s", content)
	}
}

func TestSameIPSet(t *testing.T) {
	t.Parallel()
	if !sameIPSet([]string{"1.1.1.1", "2.2.2.2"}, []string{"2.2.2.2", "1.1.1.1"}) {
		t.Fatal("set equality must ignore order")
	}
	if sameIPSet([]string{"1.1.1.1"}, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Fatal("different lengths must differ")
	}
	if sameIPSet([]string{"1.1.1.1"}, []string{"2.2.2.2"}) {
		t.Fatal("different values must differ")
	}
}

func TestSortedIPv4Strings(t *testing.T) {
	t.Parallel()
	out := sortedIPv4Strings([]string{"10.0.0.1", "1.1.1.1", "192.168.1.1"})
	want := []string{"1.1.1.1", "10.0.0.1", "192.168.1.1"} // lexicographic
	for i := range out {
		if out[i] != want[i] {
			t.Fatalf("got %v, want %v", out, want)
		}
	}
}

func TestRefreshAllDomains_MarksChangedAndStatus(t *testing.T) {
	// Cannot be parallel: mutates package-level domainResolver.
	original := domainResolver
	defer func() { domainResolver = original }()

	domainResolver = func(ctx context.Context, d string) ([]string, error) {
		switch d {
		case "good.com":
			return []string{"1.1.1.1"}, nil
		case "fail.com":
			return nil, fmt.Errorf("dns timeout")
		}
		return nil, fmt.Errorf("unexpected domain %s", d)
	}

	cfg := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "a", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"},
		{ID: "b", Kind: "domain", Domain: "good.com", ResolvedIPs: []string{"9.9.9.9"}},
		{ID: "c", Kind: "domain", Domain: "fail.com", ResolvedIPs: []string{"7.7.7.7"}},
	}}

	out, changed, ok, failed := refreshAllDomains(context.Background(), cfg, time.Now())
	if !changed {
		t.Errorf("expected changed=true (good.com IPs changed)")
	}
	if ok != 1 || failed != 1 {
		t.Errorf("counters wrong: ok=%d failed=%d", ok, failed)
	}
	if out.Routes[1].ResolvedIPs[0] != "1.1.1.1" {
		t.Errorf("good.com IP not updated")
	}
	if out.Routes[2].ResolvedIPs[0] != "7.7.7.7" {
		t.Errorf("fail.com IPs should be preserved on error")
	}
	if out.Routes[2].LastResolveErr == "" {
		t.Errorf("fail.com LastResolveErr should be set")
	}
}

func newTestAdmin(t *testing.T) *OvpnAdmin {
	t.Helper()
	dir := t.TempDir()
	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}},
		store:        testFilesystemStore(dir),
	}
	return app
}

func TestCommonRoutesHandler_GET_Empty(t *testing.T) {
	t.Parallel()
	app := newTestAdmin(t)
	req := httptest.NewRequest(http.MethodGet, "/api/common-routes", nil)
	rec := httptest.NewRecorder()
	app.commonRoutesHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	var got struct {
		Routes []CommonRouteEntry `json:"routes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Routes == nil {
		t.Fatal("routes must be non-nil slice")
	}
}

func TestCommonRoutesHandler_POST_CreatesEntry(t *testing.T) {
	t.Parallel()
	app := newTestAdmin(t)
	body := []byte(`{"kind":"ip","address":"10.0.0.0","mask":"255.255.0.0","description":"lan"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/common-routes", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.commonRoutesHandler(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
	}
	snap := app.commonRoutes.snapshot()
	if len(snap.Routes) != 1 || snap.Routes[0].ID == "" {
		t.Fatalf("entry not stored: %+v", snap)
	}
}

func TestCommonRoutesHandler_POST_RejectsDuplicate(t *testing.T) {
	t.Parallel()
	app := newTestAdmin(t)
	body := []byte(`{"kind":"ip","address":"10.0.0.0","mask":"255.255.0.0"}`)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/common-routes", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		app.commonRoutesHandler(rec, req)
		if i == 1 && rec.Code != http.StatusConflict {
			t.Fatalf("expected 409 on duplicate, got %d", rec.Code)
		}
	}
}

// TestCommonRoutesItemHandler_BaseURL verifies the route id is extracted from
// the request path by stripping the CONFIGURED --listen.base-url prefix, not a
// hardcoded "/api/common-routes/". Under a non-root base URL (e.g. "/admin/")
// the real path is "/admin/api/common-routes/<id>"; a hardcoded strip left the
// id as "admin/api/common-routes/<id>" and the update/delete silently failed.
//
// Not parallel: it mutates the package-level *listenBaseUrl flag. Non-parallel
// tests run to completion before any t.Parallel() test starts, so this cannot
// race the parallel handler tests that also read *listenBaseUrl.
func TestCommonRoutesItemHandler_BaseURL(t *testing.T) {
	orig := *listenBaseUrl
	defer func() { *listenBaseUrl = orig }()

	cases := []struct {
		name    string
		baseURL string
	}{
		{"root", "/"},
		{"subpath", "/admin/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			*listenBaseUrl = tc.baseURL
			app := newTestAdmin(t)
			id := "route-42"
			app.commonRoutes.replace(CommonRoutesConfig{Routes: []CommonRouteEntry{
				{ID: id, Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0", Description: "old"},
			}})

			// PUT under the configured base URL updates the right entry.
			path := tc.baseURL + "api/common-routes/" + id
			body := []byte(`{"kind":"ip","address":"10.0.0.0","mask":"255.255.0.0","description":"new"}`)
			req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(body))
			rec := httptest.NewRecorder()
			app.commonRoutesItemHandler(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("PUT %s: expected 200, got %d body=%s", path, rec.Code, rec.Body.String())
			}
			if got := app.commonRoutes.snapshot().Routes[0].Description; got != "new" {
				t.Fatalf("PUT %s: update not applied, description=%q", path, got)
			}

			// DELETE under the same base URL removes it.
			req = httptest.NewRequest(http.MethodDelete, path, nil)
			rec = httptest.NewRecorder()
			app.commonRoutesItemHandler(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("DELETE %s: expected 204, got %d body=%s", path, rec.Code, rec.Body.String())
			}
			if n := len(app.commonRoutes.snapshot().Routes); n != 0 {
				t.Fatalf("DELETE %s: entry not deleted, %d remain", path, n)
			}
		})
	}
}

func TestCommonRoutesItemHandler_DELETE(t *testing.T) {
	t.Parallel()
	app := newTestAdmin(t)
	id := "test-uuid"
	app.commonRoutes.replace(CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: id, Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"}}})

	req := httptest.NewRequest(http.MethodDelete, "/api/common-routes/"+id, nil)
	rec := httptest.NewRecorder()
	app.commonRoutesItemHandler(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if len(app.commonRoutes.snapshot().Routes) != 0 {
		t.Fatal("entry not deleted")
	}
}

func TestCommonRoutesItemHandler_PUT(t *testing.T) {
	t.Parallel()
	app := newTestAdmin(t)
	id := "test-uuid"
	app.commonRoutes.replace(CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: id, Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0", Description: "old"}}})

	body := []byte(`{"kind":"ip","address":"10.0.0.0","mask":"255.255.0.0","description":"new"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/common-routes/"+id, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.commonRoutesItemHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	snap := app.commonRoutes.snapshot()
	if snap.Routes[0].Description != "new" || snap.Routes[0].Mask != "255.255.0.0" {
		t.Fatalf("update not applied: %+v", snap.Routes[0])
	}
}

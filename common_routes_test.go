package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	t.Parallel()
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
	t.Parallel()
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
		role:         "master",
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}},
		store:        testFilesystemStore(dir),
	}
	app.commonRoutesPath = dir + "/_common_routes.json"
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

func TestCommonRoutesHandler_Slave_Locked(t *testing.T) {
	t.Parallel()
	app := newTestAdmin(t)
	app.role = "slave"
	body := []byte(`{"kind":"ip","address":"10.0.0.0","mask":"255.0.0.0"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/common-routes", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.commonRoutesHandler(rec, req)
	if rec.Code != http.StatusLocked {
		t.Fatalf("expected 423, got %d", rec.Code)
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

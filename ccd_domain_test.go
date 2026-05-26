package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gobuffalo/packr/v2"
)

// withTempCcdEnv устанавливает временные ccdDir + filesystem-backend для теста.
// Возвращает каталог + cleanup-функцию.
func withTempCcdEnv(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()

	origCcdDir := *ccdDir
	tmp := dir
	ccdDir = &tmp

	origStorage := *storageBackend
	fs := "filesystem"
	storageBackend = &fs

	return dir, func() {
		ccdDir = &origCcdDir
		storageBackend = &origStorage
	}
}

// newTestAdminCcd возвращает OvpnAdmin с packr templates и пустым commonRoutes-store.
func newTestAdminCcd(t *testing.T) *OvpnAdmin {
	t.Helper()
	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}},
	}
	app.templates = packr.New("template", "./templates")
	return app
}

// withMockResolver подменяет глобальный domainResolver на функцию, возвращающую
// заданный набор IP. Возвращает cleanup-функцию.
func withMockResolver(t *testing.T, mapping map[string][]string) func() {
	t.Helper()
	orig := domainResolver
	domainResolver = func(ctx context.Context, d string) ([]string, error) {
		if ips, ok := mapping[d]; ok {
			return ips, nil
		}
		return nil, fmt.Errorf("unmocked domain: %s", d)
	}
	return func() { domainResolver = orig }
}

// --- parseCcd: схлопывание __user_domain__:DOMAIN маркеров ---

func TestParseCcd_CollapsesUserDomainMarker(t *testing.T) {
	dir, cleanup := withTempCcdEnv(t)
	defer cleanup()

	content := `ifconfig-push 10.0.0.5 255.255.255.0
push "route 192.168.1.0 255.255.255.0" # corp
push "route 1.1.1.1 255.255.255.255" # __user_domain__:youtube.com yt-traffic
push "route 2.2.2.2 255.255.255.255" # __user_domain__:youtube.com yt-traffic
push "route 3.3.3.3 255.255.255.255" # __user_domain__:google.com google
push "route 8.8.8.8 255.255.255.255" # __common__:static common-dns
`
	if err := os.WriteFile(dir+"/alice", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	app := &OvpnAdmin{}
	ccd := app.parseCcd("alice")

	if ccd.ClientAddress != "10.0.0.5" {
		t.Errorf("ClientAddress: got %q, want 10.0.0.5", ccd.ClientAddress)
	}
	if len(ccd.CustomRoutes) != 3 {
		t.Fatalf("expected 3 routes (1 IP + 2 domains), got %d: %+v", len(ccd.CustomRoutes), ccd.CustomRoutes)
	}

	// IP route ordered first
	if ccd.CustomRoutes[0].Kind != "ip" || ccd.CustomRoutes[0].Address != "192.168.1.0" {
		t.Errorf("first route should be IP 192.168.1.0, got %+v", ccd.CustomRoutes[0])
	}

	// Domain entries — find by name (order = first-seen)
	var ytEntry, googleEntry *ccdRoute
	for i := range ccd.CustomRoutes {
		switch ccd.CustomRoutes[i].Domain {
		case "youtube.com":
			ytEntry = &ccd.CustomRoutes[i]
		case "google.com":
			googleEntry = &ccd.CustomRoutes[i]
		}
	}
	if ytEntry == nil {
		t.Fatal("youtube.com entry missing")
	}
	if ytEntry.Kind != "domain" {
		t.Errorf("youtube.com kind: got %q", ytEntry.Kind)
	}
	if len(ytEntry.ResolvedIPs) != 2 || ytEntry.ResolvedIPs[0] != "1.1.1.1" || ytEntry.ResolvedIPs[1] != "2.2.2.2" {
		t.Errorf("youtube.com ResolvedIPs: got %v", ytEntry.ResolvedIPs)
	}
	if ytEntry.Description != "yt-traffic" {
		t.Errorf("youtube.com Description: got %q", ytEntry.Description)
	}
	if googleEntry == nil || len(googleEntry.ResolvedIPs) != 1 || googleEntry.ResolvedIPs[0] != "3.3.3.3" {
		t.Errorf("google.com entry wrong: %+v", googleEntry)
	}

	// __common__ line must NOT leak into user CCD
	for _, r := range ccd.CustomRoutes {
		if r.Address == "8.8.8.8" || r.Domain == "static" {
			t.Errorf("__common__ route leaked into user routes: %+v", r)
		}
	}
}

// --- validateCcd ---

func TestValidateCcd_AcceptsDomain(t *testing.T) {
	ccd := Ccd{
		User:          "bob",
		ClientAddress: "dynamic",
		CustomRoutes: []ccdRoute{
			{Kind: "domain", Domain: "youtube.com", Description: "yt"},
		},
	}
	ok, msg := validateCcd(ccd)
	if !ok {
		t.Errorf("expected ok, got msg=%q", msg)
	}
}

func TestValidateCcd_RejectsBadDomain(t *testing.T) {
	cases := []string{"", "no_underscore.com", "-bad.com", "single"}
	for _, d := range cases {
		ccd := Ccd{
			User:          "bob",
			ClientAddress: "dynamic",
			CustomRoutes:  []ccdRoute{{Kind: "domain", Domain: d}},
		}
		ok, _ := validateCcd(ccd)
		if ok {
			t.Errorf("expected validation failure for domain %q", d)
		}
	}
}

func TestValidateCcd_RejectsUnknownKind(t *testing.T) {
	ccd := Ccd{
		User:          "bob",
		ClientAddress: "dynamic",
		CustomRoutes:  []ccdRoute{{Kind: "weird", Address: "10.0.0.0", Mask: "255.255.255.0"}},
	}
	if ok, _ := validateCcd(ccd); ok {
		t.Fatal("expected validation failure for unknown kind")
	}
}

func TestValidateCcd_BackwardCompat_EmptyKindTreatedAsIP(t *testing.T) {
	ccd := Ccd{
		User:          "bob",
		ClientAddress: "dynamic",
		CustomRoutes:  []ccdRoute{{Address: "10.0.0.0", Mask: "255.255.255.0"}}, // no Kind
	}
	if ok, msg := validateCcd(ccd); !ok {
		t.Fatalf("empty kind must be backward-compat ip, got msg=%q", msg)
	}
}

// --- modifyCcd render ---

func TestModifyCcd_RendersDomainAsMultipleLines(t *testing.T) {
	dir, cleanup := withTempCcdEnv(t)
	defer cleanup()

	app := newTestAdminCcd(t)

	ccd := Ccd{
		User:          "alice",
		ClientAddress: "dynamic",
		CustomRoutes: []ccdRoute{
			{Kind: "ip", Address: "192.168.0.0", Mask: "255.255.0.0", Description: "lan"},
			{Kind: "domain", Domain: "yt.com", Description: "youtube",
				ResolvedIPs: []string{"5.5.5.5", "6.6.6.6"}},
		},
	}

	ok, msg := app.modifyCcd(ccd, nil)
	if !ok {
		t.Fatalf("modifyCcd: %s", msg)
	}
	data, err := os.ReadFile(dir + "/alice")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, `push "route 192.168.0.0 255.255.0.0" # lan`) {
		t.Errorf("ip route missing:\n%s", content)
	}
	if !strings.Contains(content, `push "route 5.5.5.5 255.255.255.255" # __user_domain__:yt.com youtube`) {
		t.Errorf("domain route line 1 missing:\n%s", content)
	}
	if !strings.Contains(content, `push "route 6.6.6.6 255.255.255.255" # __user_domain__:yt.com youtube`) {
		t.Errorf("domain route line 2 missing:\n%s", content)
	}
}

func TestModifyCcd_RoundTripDomainEntry(t *testing.T) {
	dir, cleanup := withTempCcdEnv(t)
	defer cleanup()
	_ = dir

	app := newTestAdminCcd(t)

	original := Ccd{
		User:          "carol",
		ClientAddress: "dynamic",
		CustomRoutes: []ccdRoute{
			{Kind: "domain", Domain: "example.com", Description: "ex",
				ResolvedIPs: []string{"7.7.7.7", "8.8.8.8"}},
		},
	}
	if ok, msg := app.modifyCcd(original, nil); !ok {
		t.Fatalf("modifyCcd: %s", msg)
	}

	reparsed := app.parseCcd("carol")
	if len(reparsed.CustomRoutes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(reparsed.CustomRoutes))
	}
	got := reparsed.CustomRoutes[0]
	if got.Kind != "domain" || got.Domain != "example.com" {
		t.Errorf("kind/domain wrong: %+v", got)
	}
	if len(got.ResolvedIPs) != 2 || got.ResolvedIPs[0] != "7.7.7.7" || got.ResolvedIPs[1] != "8.8.8.8" {
		t.Errorf("ResolvedIPs not preserved: %v", got.ResolvedIPs)
	}
	if got.Description != "ex" {
		t.Errorf("Description not preserved: %q", got.Description)
	}
}

// --- userApplyCcdHandler with mock DNS ---

func TestUserApplyCcdHandler_ResolvesNewDomainSynchronously(t *testing.T) {
	dir, cleanup := withTempCcdEnv(t)
	defer cleanup()

	app := newTestAdminCcd(t)
	app.role = "master"

	resolverCleanup := withMockResolver(t, map[string][]string{
		"youtube.com": {"1.2.3.4", "5.6.7.8"},
	})
	defer resolverCleanup()

	payload := `{
		"User": "alice",
		"ClientAddress": "dynamic",
		"CustomRoutes": [
			{"Kind": "domain", "Domain": "youtube.com", "Description": "yt"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/user/ccd/apply", bytes.NewBufferString(payload))
	rec := httptest.NewRecorder()
	app.userApplyCcdHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	data, err := os.ReadFile(dir + "/alice")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, `push "route 1.2.3.4 255.255.255.255" # __user_domain__:youtube.com yt`) {
		t.Errorf("resolved IP 1.2.3.4 missing in CCD:\n%s", content)
	}
	if !strings.Contains(content, `push "route 5.6.7.8 255.255.255.255" # __user_domain__:youtube.com yt`) {
		t.Errorf("resolved IP 5.6.7.8 missing in CCD:\n%s", content)
	}
}

func TestUserApplyCcdHandler_PreservesIPsOnUnchangedDomain(t *testing.T) {
	dir, cleanup := withTempCcdEnv(t)
	defer cleanup()

	app := newTestAdminCcd(t)
	app.role = "master"

	// Pre-seed CCD with a domain entry that already has resolved IPs.
	existing := `push "route 9.9.9.9 255.255.255.255" # __user_domain__:example.com test
push "route 9.9.9.10 255.255.255.255" # __user_domain__:example.com test
`
	if err := os.WriteFile(dir+"/bob", []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	// Mock that would resolve to DIFFERENT IPs — but since payload sends same
	// domain (no ResolvedIPs in body), backend should reuse existing rather
	// than re-resolve.
	mockCalls := 0
	orig := domainResolver
	domainResolver = func(ctx context.Context, d string) ([]string, error) {
		mockCalls++
		return []string{"4.4.4.4"}, nil
	}
	defer func() { domainResolver = orig }()

	payload := `{
		"User": "bob",
		"ClientAddress": "dynamic",
		"CustomRoutes": [
			{"Kind": "domain", "Domain": "example.com", "Description": "test"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/user/ccd/apply", bytes.NewBufferString(payload))
	rec := httptest.NewRecorder()
	app.userApplyCcdHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	if mockCalls != 0 {
		t.Errorf("resolver should NOT be called for unchanged domain, but was called %d times", mockCalls)
	}

	data, _ := os.ReadFile(dir + "/bob")
	content := string(data)
	if !strings.Contains(content, "9.9.9.9") || !strings.Contains(content, "9.9.9.10") {
		t.Errorf("existing resolved IPs not preserved:\n%s", content)
	}
	if strings.Contains(content, "4.4.4.4") {
		t.Errorf("backend re-resolved when it should have preserved:\n%s", content)
	}
}

func TestUserApplyCcdHandler_SlaveLocked(t *testing.T) {
	_, cleanup := withTempCcdEnv(t)
	defer cleanup()

	app := newTestAdminCcd(t)
	app.role = "slave"

	req := httptest.NewRequest(http.MethodPost, "/api/user/ccd/apply",
		strings.NewReader(`{"User":"x","ClientAddress":"dynamic","CustomRoutes":[]}`))
	rec := httptest.NewRecorder()
	app.userApplyCcdHandler(rec, req)

	if rec.Code != http.StatusLocked {
		t.Errorf("expected 423 on slave, got %d", rec.Code)
	}
}

func TestUserApplyCcdHandler_MixedIPAndDomain(t *testing.T) {
	dir, cleanup := withTempCcdEnv(t)
	defer cleanup()

	app := newTestAdminCcd(t)
	app.role = "master"

	resolverCleanup := withMockResolver(t, map[string][]string{"d.com": {"1.1.1.1"}})
	defer resolverCleanup()

	payload := `{
		"User": "dave",
		"ClientAddress": "dynamic",
		"CustomRoutes": [
			{"Kind": "ip", "Address": "10.0.0.0", "Mask": "255.0.0.0", "Description": "corp"},
			{"Kind": "domain", "Domain": "d.com", "Description": "ext"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/user/ccd/apply", bytes.NewBufferString(payload))
	rec := httptest.NewRecorder()
	app.userApplyCcdHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	data, _ := os.ReadFile(dir + "/dave")
	content := string(data)
	if !strings.Contains(content, `push "route 10.0.0.0 255.0.0.0" # corp`) {
		t.Errorf("ip route missing:\n%s", content)
	}
	if !strings.Contains(content, `push "route 1.1.1.1 255.255.255.255" # __user_domain__:d.com ext`) {
		t.Errorf("domain route missing:\n%s", content)
	}
}

// --- refreshAllUserDomains scheduler ---

func TestRefreshAllUserDomains_RewritesCcdOnIPChange(t *testing.T) {
	dir, cleanup := withTempCcdEnv(t)
	defer cleanup()

	app := newTestAdminCcd(t)
	app.clients = []OpenvpnClient{
		{Identity: "alice", AccountStatus: "Active"},
	}

	// Pre-seed CCD with old IPs.
	existing := `push "route 1.1.1.1 255.255.255.255" # __user_domain__:dynamic.example test
`
	if err := os.WriteFile(dir+"/alice", []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	// Mock returns NEW IPs.
	resolverCleanup := withMockResolver(t, map[string][]string{
		"dynamic.example": {"9.9.9.9", "10.10.10.10"},
	})
	defer resolverCleanup()

	app.refreshAllUserDomains(context.Background())

	data, _ := os.ReadFile(dir + "/alice")
	content := string(data)
	if strings.Contains(content, "1.1.1.1") {
		t.Errorf("old IP still present after refresh:\n%s", content)
	}
	if !strings.Contains(content, "9.9.9.9") || !strings.Contains(content, "10.10.10.10") {
		t.Errorf("new IPs missing after refresh:\n%s", content)
	}
}

func TestRefreshAllUserDomains_SkipsRevokedUsers(t *testing.T) {
	dir, cleanup := withTempCcdEnv(t)
	defer cleanup()

	app := newTestAdminCcd(t)
	app.clients = []OpenvpnClient{
		{Identity: "alice", AccountStatus: "Active"},
		{Identity: "revoked-user", AccountStatus: "Revoked"},
	}

	existing := `push "route 1.1.1.1 255.255.255.255" # __user_domain__:x.com test
`
	if err := os.WriteFile(dir+"/alice", []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/revoked-user", []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	resolveCount := 0
	orig := domainResolver
	domainResolver = func(ctx context.Context, d string) ([]string, error) {
		resolveCount++
		return []string{"2.2.2.2"}, nil
	}
	defer func() { domainResolver = orig }()

	app.refreshAllUserDomains(context.Background())

	// Should resolve exactly once — only alice. Revoked-user is skipped.
	if resolveCount != 1 {
		t.Errorf("expected 1 resolve call for active user only, got %d", resolveCount)
	}

	revokedContent, _ := os.ReadFile(dir + "/revoked-user")
	if !strings.Contains(string(revokedContent), "1.1.1.1") {
		t.Errorf("revoked user CCD should be unchanged:\n%s", revokedContent)
	}
}

func TestRefreshAllUserDomains_NoOpWhenIPsUnchanged(t *testing.T) {
	dir, cleanup := withTempCcdEnv(t)
	defer cleanup()

	app := newTestAdminCcd(t)
	app.clients = []OpenvpnClient{{Identity: "alice", AccountStatus: "Active"}}

	existing := `push "route 1.1.1.1 255.255.255.255" # __user_domain__:same.com test
push "route 2.2.2.2 255.255.255.255" # __user_domain__:same.com test
`
	if err := os.WriteFile(dir+"/alice", []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	statBefore, _ := os.Stat(dir + "/alice")

	resolverCleanup := withMockResolver(t, map[string][]string{
		"same.com": {"1.1.1.1", "2.2.2.2"}, // same as existing
	})
	defer resolverCleanup()

	app.refreshAllUserDomains(context.Background())

	statAfter, _ := os.Stat(dir + "/alice")
	if !statBefore.ModTime().Equal(statAfter.ModTime()) {
		t.Errorf("CCD file should not be rewritten when IPs are unchanged (before=%v after=%v)",
			statBefore.ModTime(), statAfter.ModTime())
	}
}

// --- helpers/imports usage anchors (silence unused-import warnings if any) ---

var _ = url.Parse
var _ = io.Discard
var _ = time.Second

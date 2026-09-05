package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ovpn-admin/internal/storage"
)

// ---------------------------------------------------------------------------
// FINDING #11.1 — parseCcd: malformed ifconfig-push line must not panic
// ---------------------------------------------------------------------------

func TestParseCcd_MalformedIfconfigPushNoPanic(t *testing.T) {
	dir := t.TempDir()
	app := newTestAdminCcd(t, dir)

	cases := []struct {
		name    string
		content string
		wantCA  string // expected ClientAddress
	}{
		{"bare directive no address", "ifconfig-push\n", "dynamic"},
		{"trailing space only", "ifconfig-push \n", "dynamic"},
		{"well-formed still parses", "ifconfig-push 10.0.0.5 255.255.255.0\n", "10.0.0.5"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := app.store.SaveCcd("alice", []byte(tc.content)); err != nil {
				t.Fatalf("SaveCcd: %v", err)
			}
			// Must not panic.
			ccd := app.getCcd("alice")
			if ccd.ClientAddress != tc.wantCA {
				t.Errorf("ClientAddress = %q; want %q", ccd.ClientAddress, tc.wantCA)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FINDING #11.2 — validateCcd: bad OVPN_NETWORK must error, not panic
// ---------------------------------------------------------------------------

func TestValidateCcd_BadOpenvpnNetworkNoPanic(t *testing.T) {
	orig := *openvpnNetwork
	t.Cleanup(func() { *openvpnNetwork = orig })

	dir := t.TempDir()
	app := newTestAdminCcd(t, dir)

	for _, bad := range []string{"", "not-a-cidr", "999.999.999.999/24", "172.16.100.0"} {
		t.Run(bad, func(t *testing.T) {
			*openvpnNetwork = bad
			ccd := Ccd{User: "alice", ClientAddress: "172.16.100.10"}
			ok, msg := app.validateCcd(ccd) // must not panic
			if ok {
				t.Errorf("validateCcd() ok=true; want false for OVPN_NETWORK=%q", bad)
			}
			if msg == "" {
				t.Errorf("validateCcd() returned empty error message for OVPN_NETWORK=%q", bad)
			}
		})
	}
}

func TestValidateOpenvpnNetwork(t *testing.T) {
	orig := *openvpnNetwork
	t.Cleanup(func() { *openvpnNetwork = orig })

	*openvpnNetwork = "172.16.100.0/24"
	if err := validateOpenvpnNetwork(); err != nil {
		t.Errorf("validateOpenvpnNetwork(valid) = %v; want nil", err)
	}
	for _, bad := range []string{"", "garbage", "10.0.0.0"} {
		*openvpnNetwork = bad
		if err := validateOpenvpnNetwork(); err == nil {
			t.Errorf("validateOpenvpnNetwork(%q) = nil; want error", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// FINDING #11.3 — parseOpenvpnServers: OVPN_SERVER without 3 parts must skip
// ---------------------------------------------------------------------------

func TestParseOpenvpnServers_MalformedNoPanic(t *testing.T) {
	t.Parallel()
	in := []string{
		"1.2.3.4:1194:udp", // valid
		"only-host",        // no port/proto
		"host:1194",        // no proto
		"",                 // empty
		"5.6.7.8:443:tcp",  // valid
		":::",              // degenerate but has >=3 parts -> kept as empty fields
	}
	got := parseOpenvpnServers(in) // must not panic
	// Valid entries: the two real ones, plus ":::" which SplitN yields
	// ["", "", ":"] (3 parts) — it is intentionally kept (only <3 parts skip).
	want := []OpenvpnServer{
		{Host: "1.2.3.4", Port: "1194", Protocol: "udp"},
		{Host: "5.6.7.8", Port: "443", Protocol: "tcp"},
		{Host: "", Port: "", Protocol: ":"},
	}
	if len(got) != len(want) {
		t.Fatalf("parseOpenvpnServers len = %d (%v); want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("host[%d] = %+v; want %+v", i, got[i], want[i])
		}
	}
}

// ---------------------------------------------------------------------------
// FINDING #11.4 — getOvpnServerHostsFromKubeApi: no cluster must error, not panic
// ---------------------------------------------------------------------------

func TestGetOvpnServerHostsFromKubeApi_NoClusterNoPanic(t *testing.T) {
	// Outside a cluster rest.InClusterConfig fails; the function must return an
	// error rather than dereferencing a nil clientset/service.
	_, err := getOvpnServerHostsFromKubeApi() // must not panic
	if err == nil {
		t.Skip("running inside a kubernetes cluster; nil-guard path not exercised")
	}
}

// ---------------------------------------------------------------------------
// FINDING #11.5 — decodePrivKey: non-RSA PKCS#8 / no-PEM must error, not nil key
// ---------------------------------------------------------------------------

func TestDecodePrivKey_NonRSAPKCS8ReturnsError(t *testing.T) {
	t.Parallel()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	key, err := decodePrivKey(pemBytes)
	if err == nil {
		t.Fatal("decodePrivKey(EC PKCS8) = nil error; want error")
	}
	if key != nil {
		t.Errorf("decodePrivKey(EC PKCS8) key = %v; want nil", key)
	}
}

func TestDecodePrivKey_NoPEMBlockReturnsError(t *testing.T) {
	t.Parallel()
	if _, err := decodePrivKey([]byte("not a pem block")); err == nil {
		t.Fatal("decodePrivKey(non-PEM) = nil error; want error")
	}
}

func TestDecodePrivKey_ValidRSAPKCS8(t *testing.T) {
	t.Parallel()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	key, err := decodePrivKey(pemBytes)
	if err != nil {
		t.Fatalf("decodePrivKey(RSA PKCS8) = %v; want nil", err)
	}
	if key == nil {
		t.Fatal("decodePrivKey(RSA PKCS8) returned nil key")
	}
}

// ---------------------------------------------------------------------------
// FINDING #11.6 — templates: bad template surfaces as error/startup, not panic
// ---------------------------------------------------------------------------

func TestGetCcdTemplate_MalformedCustomReturnsError(t *testing.T) {
	orig := *ccdTemplatePath
	t.Cleanup(func() { *ccdTemplatePath = orig })

	bad := filepath.Join(t.TempDir(), "ccd.tpl")
	if err := os.WriteFile(bad, []byte("{{ .Unclosed "), 0600); err != nil {
		t.Fatalf("write bad template: %v", err)
	}
	*ccdTemplatePath = bad

	app := &OvpnAdmin{}
	_, err := app.getCcdTemplate() // must not panic
	if err == nil {
		t.Fatal("getCcdTemplate(malformed) = nil error; want error")
	}
}

func TestGetClientConfigTemplate_MalformedCustomReturnsError(t *testing.T) {
	orig := *clientConfigTemplatePath
	t.Cleanup(func() { *clientConfigTemplatePath = orig })

	bad := filepath.Join(t.TempDir(), "client.conf.tpl")
	if err := os.WriteFile(bad, []byte("{{ if .X }}no-end"), 0600); err != nil {
		t.Fatalf("write bad template: %v", err)
	}
	*clientConfigTemplatePath = bad

	app := &OvpnAdmin{}
	_, err := app.getClientConfigTemplate() // must not panic
	if err == nil {
		t.Fatal("getClientConfigTemplate(malformed) = nil error; want error")
	}
}

// validateTemplates is the startup-validation entry point: it must FAIL at
// startup on a broken template rather than deferring a panic to a request.
func TestValidateTemplates_BadTemplateFailsAtStartup(t *testing.T) {
	origCcd := *ccdTemplatePath
	origCC := *clientConfigTemplatePath
	t.Cleanup(func() {
		*ccdTemplatePath = origCcd
		*clientConfigTemplatePath = origCC
	})

	bad := filepath.Join(t.TempDir(), "client.conf.tpl")
	if err := os.WriteFile(bad, []byte("{{ range }}"), 0600); err != nil {
		t.Fatalf("write bad template: %v", err)
	}
	*clientConfigTemplatePath = bad
	*ccdTemplatePath = ""

	app := &OvpnAdmin{}
	if err := app.validateTemplates(); err == nil {
		t.Fatal("validateTemplates(bad client template) = nil; want error at startup")
	}
}

func TestValidateTemplates_EmbeddedTemplatesOK(t *testing.T) {
	origCcd := *ccdTemplatePath
	origCC := *clientConfigTemplatePath
	t.Cleanup(func() {
		*ccdTemplatePath = origCcd
		*clientConfigTemplatePath = origCC
	})
	*ccdTemplatePath = ""
	*clientConfigTemplatePath = ""

	app := newTestAdminCcd(t, t.TempDir())
	if err := app.validateTemplates(); err != nil {
		t.Fatalf("validateTemplates(embedded) = %v; want nil", err)
	}
}

// ---------------------------------------------------------------------------
// FINDING #11.7 — mgmt version line parse must not panic on a short line
// ---------------------------------------------------------------------------

func TestParseMgmtVersionLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		wantVer string
		wantOK  bool
	}{
		{"OpenVPN Version: OpenVPN 2.5.1 x86_64", "2.5.1", true},
		{"OpenVPN Version: OpenVPN 2.4.7", "2.4.7", true},
		{"OpenVPN Version:", "", false},         // too short -> skip, no panic
		{"OpenVPN Version: OpenVPN", "", false}, // only 3 fields
		{"", "", false},
	}
	for _, tc := range cases {
		ver, ok := parseMgmtVersionLine(tc.in) // must not panic
		if ok != tc.wantOK || ver != tc.wantVer {
			t.Errorf("parseMgmtVersionLine(%q) = (%q,%v); want (%q,%v)", tc.in, ver, ok, tc.wantVer, tc.wantOK)
		}
	}
}

// ---------------------------------------------------------------------------
// FINDING #12 — DNS scheduler: 0 disables; persist before publish
// ---------------------------------------------------------------------------

func TestSchedulerRunState(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		store        *serverConfigStore
		wantInterval time.Duration
		wantEnabled  bool
	}{
		{"nil store defaults enabled 24h", nil, 24 * time.Hour, true},
		{"positive interval enabled", &serverConfigStore{cfg: ServerConfig{DomainRefreshIntervalHours: 6}}, 6 * time.Hour, true},
		{"zero disables (contract)", &serverConfigStore{cfg: ServerConfig{DomainRefreshIntervalHours: 0}}, time.Hour, false},
		{"negative disables", &serverConfigStore{cfg: ServerConfig{DomainRefreshIntervalHours: -3}}, time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := &OvpnAdmin{serverConfigStore: tc.store}
			interval, enabled := app.schedulerRunState()
			if interval != tc.wantInterval || enabled != tc.wantEnabled {
				t.Errorf("schedulerRunState() = (%v,%v); want (%v,%v)", interval, enabled, tc.wantInterval, tc.wantEnabled)
			}
		})
	}
}

// failingCommonRoutesStore is a storage.Store whose SaveCommonRoutes always
// fails; every other method is unused (embedded nil interface). Used to prove
// a persist failure leaves the in-memory routes untouched.
type failingCommonRoutesStore struct {
	storage.Store
}

func (failingCommonRoutesStore) SaveCommonRoutes(_ []byte) error {
	return errors.New("simulated disk failure")
}

func TestRefreshCommonRoutesOnce_PersistFailureLeavesMemoryUnchanged(t *testing.T) {
	// Not parallel: mutates package-level domainResolver.
	restore := withMockResolver(t, map[string][]string{"example.com": {"1.2.3.4"}})
	defer restore()

	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{
			{ID: "r1", Kind: "domain", Domain: "example.com"}, // no ResolvedIPs yet
		}}},
		store: failingCommonRoutesStore{},
	}

	app.refreshCommonRoutesOnce(context.Background())

	got := app.commonRoutes.snapshot()
	if len(got.Routes) != 1 {
		t.Fatalf("routes len = %d; want 1", len(got.Routes))
	}
	if len(got.Routes[0].ResolvedIPs) != 0 {
		t.Errorf("persist failed but in-memory ResolvedIPs = %v; want unchanged (empty)", got.Routes[0].ResolvedIPs)
	}
}

func TestRefreshCommonRoutesOnce_PersistSuccessPublishes(t *testing.T) {
	// Not parallel: mutates package-level domainResolver.
	restore := withMockResolver(t, map[string][]string{"example.com": {"1.2.3.4"}})
	defer restore()

	dir := t.TempDir()
	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{
			{ID: "r1", Kind: "domain", Domain: "example.com"},
		}}},
		store: testFilesystemStore(dir),
	}

	app.refreshCommonRoutesOnce(context.Background())

	got := app.commonRoutes.snapshot()
	if len(got.Routes) != 1 || len(got.Routes[0].ResolvedIPs) != 1 || got.Routes[0].ResolvedIPs[0] != "1.2.3.4" {
		t.Errorf("after successful persist, ResolvedIPs = %v; want [1.2.3.4]", got.Routes[0].ResolvedIPs)
	}
}

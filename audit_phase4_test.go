package main

import (
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// --- F38: expired (E) index entries survive a parse→render round-trip ---
func TestAuditExpiredIndexEntriesPreserved(t *testing.T) {
	idx := "E\t990101000000Z\t\t0A\tunknown\t/CN=expired\n" +
		"V\t990101000000Z\t\t0B\tunknown\t/CN=valid\n"
	parsed := indexTxtParser(idx)
	if len(parsed) != 2 {
		t.Fatalf("F38: expected 2 entries (E+V), got %d", len(parsed))
	}
	out := renderIndexTxt(parsed)
	if !strings.Contains(out, "/CN=expired") || !strings.HasPrefix(out, "E\t") {
		t.Fatalf("F38: expired entry lost on render:\n%s", out)
	}
	// Re-parse must still find both (idempotent round-trip).
	if len(indexTxtParser(out)) != 2 {
		t.Fatalf("F38: round-trip dropped an entry:\n%s", out)
	}
}

// --- F25: strict IPv4 + contiguous-mask validation ---
func TestAuditIPv4NetworkMaskValidation(t *testing.T) {
	// non-contiguous mask, IPv6, host bits set → rejected
	for _, c := range []struct{ addr, mask string }{
		{"172.16.0.0", "255.0.255.0"}, // non-contiguous
		{"2001:db8::", "ffff::"},      // IPv6
		{"10.0.0.5", "255.255.255.0"}, // host bits set (canonical 10.0.0.0)
	} {
		if err := validateIPv4NetworkMask(c.addr, c.mask); err == nil {
			t.Errorf("F25: %s/%s must be rejected", c.addr, c.mask)
		}
	}
	// valid /16, /24, /30
	for _, c := range []struct{ addr, mask string }{
		{"10.0.0.0", "255.255.0.0"},
		{"172.16.100.0", "255.255.255.0"},
		{"192.168.1.0", "255.255.255.252"},
	} {
		if err := validateIPv4NetworkMask(c.addr, c.mask); err != nil {
			t.Errorf("F25: %s/%s must be valid, got %v", c.addr, c.mask, err)
		}
	}
	// server config uses it
	cfg := defaultServerConfig()
	cfg.NetworkMask = "255.0.255.0"
	if err := validateServerConfig(cfg); err == nil {
		t.Fatal("F25: validateServerConfig must reject a non-contiguous network_mask")
	}
}

// --- F27: a scheduler-interval-only change needs no reload ---
func TestAuditSchedulerIntervalIsNoReload(t *testing.T) {
	old := defaultServerConfig()
	next := old
	next.DomainRefreshIntervalHours = old.DomainRefreshIntervalHours + 1
	if kind := categorizeChanges(old, next); kind != "none" {
		t.Fatalf("F27: changing only the refresh interval must be 'none' (no SIGHUP), got %q", kind)
	}
}

// --- F34: getCcdTemplate must not panic on a nil embedded FS ---
func TestAuditGetCcdTemplateNilFS(t *testing.T) {
	prev := *ccdTemplatePath
	*ccdTemplatePath = ""
	t.Cleanup(func() { *ccdTemplatePath = prev })
	app := &OvpnAdmin{} // templates == nil
	if _, err := app.getCcdTemplate(); err == nil {
		t.Fatal("F34: getCcdTemplate with a nil template FS must return an error, not panic")
	}
}

// --- F24: an endpoint-only change (kind none) is still persisted ---
func TestAuditPublicEndpointIsPersisted(t *testing.T) {
	dir := t.TempDir()
	backend := testFilesystemStore(dir)
	store := newServerConfigStore()
	store.replace(defaultServerConfig())
	mgr := &serverManager{
		store:          store,
		persistBackend: backend,
		mgmtAddr:       "127.0.0.1:0",
		confPath:       filepath.Join(dir, "server.conf"),
		ccdEnabled:     true,
	}
	cfg := store.snapshot()
	cfg.PublicHostname = "vpn.example.com"
	cfg.PublicPort = 443
	cfg.PublicProto = "tcp"

	kind, err := mgr.apply(context.Background(), cfg, "admin")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if kind != "none" {
		t.Fatalf("endpoint-only change should be 'none', got %q", kind)
	}
	if got := store.snapshot(); got.PublicHostname != "vpn.example.com" || got.PublicPort != 443 {
		t.Fatalf("F24: endpoint not persisted in memory: %+v", got)
	}
	// And durably: reload from the backend.
	raw, _ := backend.LoadServerConfig()
	reloaded, _ := deserializeServerConfig(raw)
	if reloaded.PublicHostname != "vpn.example.com" || reloaded.PublicPort != 443 {
		t.Fatalf("F24: endpoint not persisted to disk: %+v", reloaded)
	}
}

// --- F26: a failed server.conf write rolls the durable JSON back ---
func TestAuditFailedApplyRollsBackJSON(t *testing.T) {
	dir := t.TempDir()
	backend := testFilesystemStore(dir)
	store := newServerConfigStore()
	store.replace(defaultServerConfig())
	origPort := store.snapshot().Port

	// confPath's parent is a regular file → the atomic write fails (ENOTDIR),
	// but the JSON persist (to the backend) succeeds first.
	notDir := filepath.Join(dir, "afile")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mgr := &serverManager{
		store:          store,
		persistBackend: backend,
		mgmtAddr:       "127.0.0.1:0",
		confPath:       filepath.Join(notDir, "server.conf"),
		ccdEnabled:     true,
	}
	cfg := store.snapshot()
	cfg.Port = origPort + 1 // hard change → reaches the write path

	if _, err := mgr.apply(context.Background(), cfg, "admin"); err == nil {
		t.Fatal("apply must fail when server.conf cannot be written")
	}
	// Durable JSON must have been rolled back to the OLD port (audit F26).
	raw, _ := backend.LoadServerConfig()
	reloaded, _ := deserializeServerConfig(raw)
	if reloaded.Port != origPort {
		t.Fatalf("F26: rejected config leaked to disk: persisted port=%d want %d", reloaded.Port, origPort)
	}
}

// --- F30: turning the GLOBAL full-tunnel off returns a user to their own choice ---
func TestAuditGlobalRedirectCanBeDisabled(t *testing.T) {
	dir := t.TempDir()
	app := newTestAdminCcd(t, dir)
	app.serverConfigStore = newServerConfigStore()

	cfg := app.serverConfigStore.snapshot()
	cfg.RedirectGateway = true // GLOBAL full-tunnel ON
	app.serverConfigStore.replace(cfg)

	// User's OWN intent is OFF, while global forces it on.
	if ok, msg := app.modifyCcd(Ccd{User: "alice", ClientAddress: "dynamic", RedirectGateway: false}, nil); !ok {
		t.Fatalf("modifyCcd: %s", msg)
	}
	if app.parseCcd("alice").RedirectGateway {
		t.Fatal("F30: the user's own intent must read OFF even while global forces full-tunnel")
	}

	// Global OFF; rerender from the parsed (intent-off) CCD.
	cfg.RedirectGateway = false
	app.serverConfigStore.replace(cfg)
	if ok, msg := app.modifyCcd(app.parseCcd("alice"), nil); !ok {
		t.Fatalf("rerender: %s", msg)
	}
	content, _ := os.ReadFile(dir + "/alice")
	if strings.Contains(string(content), "redirect-gateway def1") {
		t.Fatalf("F30: after global off the inheriting user must not stay full-tunnel:\n%s", content)
	}
}

// --- F31: a domain route with no resolved IPs survives a save→parse round trip ---
func TestAuditUnresolvedDomainSurvives(t *testing.T) {
	dir := t.TempDir()
	app := newTestAdminCcd(t, dir)
	in := Ccd{User: "bob", ClientAddress: "dynamic", CustomRoutes: []ccdRoute{
		{Kind: "domain", Domain: "example.com", Description: "corp"},
	}}
	if ok, msg := app.modifyCcd(in, nil); !ok {
		t.Fatalf("modifyCcd: %s", msg)
	}
	found := false
	for _, r := range app.parseCcd("bob").CustomRoutes {
		if r.Kind == "domain" && r.Domain == "example.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("F31: an unresolved domain route was lost on round-trip")
	}
}

// --- F32: a personal route that coincides with a common route keeps a clean
// description (no reserved marker) and re-validates on save ---
func TestAuditMergedCommonRouteStaysPersonal(t *testing.T) {
	dir := t.TempDir()
	app := newTestAdminCcd(t, dir)
	in := Ccd{User: "carol", ClientAddress: "dynamic", CustomRoutes: []ccdRoute{
		{Kind: "ip", Address: "10.5.0.0", Mask: "255.255.0.0", Description: "lab"},
	}}
	common := []ccdCommonRoute{{Address: "10.5.0.0", Mask: "255.255.0.0", Tag: "static"}}
	if ok, msg := app.modifyCcd(in, common); !ok {
		t.Fatalf("modifyCcd: %s", msg)
	}
	parsed := app.parseCcd("carol")
	var pr *ccdRoute
	for i := range parsed.CustomRoutes {
		if parsed.CustomRoutes[i].Address == "10.5.0.0" {
			pr = &parsed.CustomRoutes[i]
		}
	}
	if pr == nil {
		t.Fatal("F32: personal route was lost")
	}
	if descriptionHasReservedMarker(pr.Description) {
		t.Fatalf("F32: reserved marker leaked into personal description: %q", pr.Description)
	}
	if ok, msg := app.validateCcd(parsed); !ok {
		t.Fatalf("F32: re-save must validate, got %q", msg)
	}
}

// --- F36: filesystem unrevoke reports failure when the restore can't complete ---
func TestAuditFilesystemUnrevokeReturnsError(t *testing.T) {
	// index has an R entry but the revoked cert/key files don't exist.
	s := fsTestEnv(t, 0, rLine("0A0B0C", "erin"), nil)
	if err := s.UnrevokeClient("erin"); err == nil {
		t.Fatal("F36: unrevoke must error when the revoked cert/key files are missing")
	}
	if got := fRead(s.indexTxtPath); !strings.Contains(got, "R\t") {
		t.Fatalf("F36: entry must stay R after a failed unrevoke:\n%s", got)
	}
}

// --- F39: duplicate-cn sessions are not re-counted on an identical repeat ---
func TestAuditTrafficDuplicateCNNoDoubleCount(t *testing.T) {
	ta := newTrafficAccountant(filepath.Join(t.TempDir(), "traffic.db"))
	month := currentMonth()
	snap := []clientStatus{
		{CommonName: "alice", ConnectedSince: "s1", RealAddress: "10.0.0.1:1", BytesReceived: "100", BytesSent: "0"},
		{CommonName: "alice", ConnectedSince: "s2", RealAddress: "10.0.0.2:2", BytesReceived: "200", BytesSent: "0"},
	}
	ta.update(snap)
	rx1, _ := monthTotal(t, ta, "alice", month)
	ta.update(snap) // identical repeat — must add nothing
	rx2, _ := monthTotal(t, ta, "alice", month)
	if rx1 != 300 {
		t.Fatalf("first accounting: want 300, got %d", rx1)
	}
	if rx2 != 300 {
		t.Fatalf("F39: identical duplicate-cn snapshot double-counted: %d -> %d", rx1, rx2)
	}
}

// --- F48: archived (revoked) CCD secrets are excluded from the live list ---
func TestAuditArchivedCCDNotListed(t *testing.T) {
	active := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "c1", Namespace: namespace,
			Labels: map[string]string{"name": "alice", "index.txt": "", "type": "clientAuth"}},
		Data: map[string][]byte{"ccd": []byte("ifconfig-push 172.16.100.42 255.255.255.0\n")},
	}
	archived := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "c2", Namespace: namespace,
			Labels:      map[string]string{"name": "REVOKED-x", "index.txt": "", "type": "clientAuth", "revokedForever": "true"},
			Annotations: map[string]string{"revokedAt": "260101000000Z"}},
		Data: map[string][]byte{"ccd": []byte("ifconfig-push 172.16.100.42 255.255.255.0\n")},
	}
	s := &kubernetesStore{pki: &OpenVPNPKI{KubeClient: fake.NewSimpleClientset(active, archived)}}
	out, err := s.ListCcdSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].CommonName != "alice" {
		t.Fatalf("F48: archived CCD must be excluded, got %+v", out)
	}
}

// --- F37: a valid long CN stays deletable (archival label within the 63-char limit) ---
func TestAuditK8sDeleteLabelFits(t *testing.T) {
	longCN := strings.Repeat("a", 40) // valid username, but old label overflowed 63
	caCert, caKey := testCA(t)
	cert := testClientCert(t, caCert, caKey, longCN)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pki"), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := easyrsaDirPath
	easyrsaDirPath = &dir
	t.Cleanup(func() { easyrsaDirPath = prev })

	sec := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "c1", Namespace: namespace,
			Labels:      map[string]string{"name": longCN, "index.txt": "", "type": "clientAuth"},
			Annotations: map[string]string{}},
		Data: map[string][]byte{certFileName: certPEM},
	}
	pki := &OpenVPNPKI{CACert: caCert, CAPrivKeyRSA: caKey, KubeClient: fake.NewSimpleClientset(sec)}
	if err := pki.easyrsaDelete(longCN); err != nil {
		t.Fatalf("easyrsaDelete(long CN): %v", err)
	}
	list, _ := pki.KubeClient.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{})
	for _, s := range list.Items {
		if nl := s.Labels["name"]; nl != "" {
			if err := validateK8sLabelValue(nl); err != nil {
				t.Fatalf("F37: archival name label is not a valid k8s label value: %q: %v", nl, err)
			}
		}
	}
}

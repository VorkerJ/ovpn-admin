package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// ─────────────────────────────────────────────────────────────────────────────
// Re-audit (2026-09-14) residual findings N01–N20. Each test maps to one card's
// "Критерий закрытия" / "Воспроизводящие тесты".
// ─────────────────────────────────────────────────────────────────────────────

// N01 (P1, F03): userDelete revokes the CERT before dropping the password, so a
// PKI success + password-DB failure still surfaces as a non-200 (and never a
// silent cert-only downgrade). Covered end-to-end by
// TestUserDelete_PropagatesOpenvpnUserError (robustness_test.go), reordered for
// N01. Here we assert the ordering invariant on userRotate: a RotateClient
// failure aborts WITHOUT having touched the password DB first.
func TestReauditRotateFailureDoesNotDropPasswordFirst(t *testing.T) {
	origRun := runOpenvpnUser
	origAuth := *authByPassword
	origIdx := *indexTxtPath
	origDb := *authDatabase
	t.Cleanup(func() {
		runOpenvpnUser = origRun
		*authByPassword = origAuth
		*indexTxtPath = origIdx
		*authDatabase = origDb
	})

	// index has the user so checkUserExist passes.
	*indexTxtPath = writeIndexTxtWithUser(t, "alice")
	*authByPassword = true
	*authDatabase = filepath.Join(t.TempDir(), "users.db")

	var passwordTouched bool
	runOpenvpnUser = func(args ...string) (string, error) {
		for _, a := range args {
			if a == "delete" || a == "create" {
				passwordTouched = true
			}
		}
		return "", nil
	}

	// A store whose RotateClient always fails (PKI mutation failure). userRotate
	// returns immediately on that error, so no other store method is invoked.
	app := &OvpnAdmin{store: &rotateFailStore{}}
	err, _ := app.userRotate("alice", "newpass123")
	if err == nil {
		t.Fatal("expected rotate to fail when RotateClient errors")
	}
	if passwordTouched {
		t.Fatal("N01: the password DB must NOT be mutated before the cert is rotated (no cert-only downgrade window)")
	}
}

type rotateFailStore struct{ *filesystemStore }

func (*rotateFailStore) RotateClient(cn, pw string) error {
	return fmt.Errorf("simulated PKI failure")
}

// N02 (P1, F05): a common route with kind=domain whose DNS resolution FAILS must
// not keep client-supplied ResolvedIPs — they must never be rendered.
func TestReauditCommonRouteDNSFailureInjection(t *testing.T) {
	dir := t.TempDir()
	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}},
		store:        testFilesystemStore(dir),
	}
	prev := domainResolver
	domainResolver = func(ctx context.Context, d string) ([]string, error) {
		return nil, fmt.Errorf("simulated NXDOMAIN")
	}
	t.Cleanup(func() { domainResolver = prev })

	// Attacker supplies resolved_ips for a domain that won't resolve server-side.
	body := `{"kind":"domain","domain":"evil.example.com","resolved_ips":["6.6.6.6","7.7.7.7"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/common-routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	app.handleCreateCommonRoute(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	routes := app.commonRoutes.snapshot().Routes
	if len(routes) != 1 {
		t.Fatalf("expected 1 stored route, got %d", len(routes))
	}
	if len(routes[0].ResolvedIPs) != 0 {
		t.Fatalf("N02: client-supplied ResolvedIPs must be discarded on DNS failure, got %v", routes[0].ResolvedIPs)
	}
	// And they must not survive into the expanded render either.
	for _, e := range expandCommonRoutes(app.commonRoutes.snapshot()) {
		if e.Address == "6.6.6.6" || e.Address == "7.7.7.7" {
			t.Fatalf("N02: injected IP %s reached the rendered routes", e.Address)
		}
	}
}

// N02 sibling: the PER-USER CCD apply endpoint must also ignore client-supplied
// ResolvedIPs for a domain route and resolve server-side — otherwise a caller
// can point a domain route at arbitrary IPs the firewall then ACCEPTs.
func TestReauditPerUserDomainRouteIgnoresClientIPs(t *testing.T) {
	dir := t.TempDir()
	app := newTestAdminCcd(t, dir)
	cleanup := withMockResolver(t, map[string][]string{"evil.example.com": {"9.9.9.9"}})
	t.Cleanup(cleanup)

	body := `{"User":"alice","ClientAddress":"dynamic","CustomRoutes":[{"Kind":"domain","Domain":"evil.example.com","ResolvedIPs":["6.6.6.6"]}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/user/ccd/apply", strings.NewReader(body))
	rec := httptest.NewRecorder()
	app.userApplyCcdHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	got := app.parseCcd("alice")
	var domainRoute *ccdRoute
	for i := range got.CustomRoutes {
		if got.CustomRoutes[i].Domain == "evil.example.com" {
			domainRoute = &got.CustomRoutes[i]
		}
	}
	if domainRoute == nil {
		t.Fatalf("domain route missing after apply: %+v", got.CustomRoutes)
	}
	for _, ip := range domainRoute.ResolvedIPs {
		if ip == "6.6.6.6" {
			t.Fatal("N02 sibling: client-supplied ResolvedIP 6.6.6.6 must not be stored")
		}
	}
	if len(domainRoute.ResolvedIPs) != 1 || domainRoute.ResolvedIPs[0] != "9.9.9.9" {
		t.Fatalf("N02 sibling: expected server-resolved [9.9.9.9], got %v", domainRoute.ResolvedIPs)
	}
}

// N03 (P1, F08/F18): the validator the API uses (and now the startup path) must
// reject a saved config that bypasses client isolation or references a missing
// auth script.
func TestReauditInitialFirewallConfigIsValidated(t *testing.T) {
	origFw := firewallEnabled
	origSb := storageBackend
	t.Cleanup(func() { firewallEnabled = origFw; storageBackend = origSb })

	on := true
	firewallEnabled = &on
	cfg := defaultServerConfig()
	cfg.ClientToClient = true // incompatible with the firewall
	if err := validateServerConfig(cfg); err == nil {
		t.Fatal("N03: client_to_client together with the firewall must be rejected at startup")
	}

	off := false
	firewallEnabled = &off
	k8s := "kubernetes.secrets"
	storageBackend = &k8s
	cfg2 := defaultServerConfig()
	cfg2.ClientToClient = false
	cfg2.PasswordAuth = true
	if err := validateServerConfig(cfg2); err == nil {
		t.Fatal("N03: password_auth on the kubernetes.secrets backend must be rejected at startup")
	}
}

// N04 (P1, F09): initChain must DETACH the FORWARD jump before flushing (no
// fail-open window) and install the catch-all DROP before re-attaching the jump.
func TestReauditInitChainDetachesJumpBeforeFlush(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		// -C FORWARD (existence check) fails so -I re-adds the jump.
		if len(args) >= 2 && args[0] == "-C" && args[1] == "FORWARD" {
			return fmt.Errorf("no such rule")
		}
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	if err := fc.initChain(); err != nil {
		t.Fatalf("initChain: %v", err)
	}

	idxDetach, idxFlush, idxDrop, idxJumpAdd := -1, -1, -1, -1
	for i, c := range cmds {
		j := strings.Join(c, " ")
		switch {
		case idxDetach == -1 && strings.HasPrefix(j, "-D FORWARD -j OVPN_FW"):
			idxDetach = i
		case idxFlush == -1 && strings.HasPrefix(j, "-F OVPN_FW"):
			idxFlush = i
		case idxDrop == -1 && strings.Contains(j, "-j DROP"):
			idxDrop = i
		case strings.HasPrefix(j, "-I FORWARD 1 -j OVPN_FW"):
			idxJumpAdd = i
		}
	}
	if idxDetach == -1 || idxFlush == -1 || idxDrop == -1 || idxJumpAdd == -1 {
		t.Fatalf("N04: missing expected commands: detach=%d flush=%d drop=%d jumpAdd=%d\n%v", idxDetach, idxFlush, idxDrop, idxJumpAdd, cmds)
	}
	if idxDetach >= idxFlush {
		t.Fatal("N04: FORWARD jump must be detached BEFORE the chain is flushed")
	}
	if idxDrop >= idxJumpAdd {
		t.Fatal("N04: catch-all DROP must be installed BEFORE the FORWARD jump is re-attached")
	}
}

// N04: a mid-install iptables failure on connect must not leave an orphan/dup
// ACCEPT — the session is recorded with only the CIDRs actually installed, and a
// reconnect (retry) then disconnect leaves the chain clean.
func TestReauditConnectRetryLeavesNoOrphanAccept(t *testing.T) {
	dir := t.TempDir()
	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{
			{ID: "a", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"},
			{ID: "b", Kind: "ip", Address: "8.8.8.8", Mask: "255.255.255.255"},
		}}},
		store: testFilesystemStore(dir),
	}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")

	// Track live ACCEPT rules by "src->dst". Fail the FIRST insert of 8.8.8.8/32.
	live := map[string]int{}
	failOnce := true
	iptMock := func(args ...string) error {
		j := strings.Join(args, " ")
		if args[0] == "-I" && strings.Contains(j, "ACCEPT") && strings.Contains(j, "-d ") {
			if strings.Contains(j, "-d 8.8.8.8/32") && failOnce {
				failOnce = false
				return fmt.Errorf("simulated failure")
			}
			key := ruleKey(args)
			live[key]++
		}
		if args[0] == "-D" && strings.Contains(j, "ACCEPT") {
			key := ruleKey(args)
			live[key]--
			if live[key] <= 0 {
				delete(live, key)
			}
		}
		return nil
	}
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, iptMock)

	// Connect: 8.8.8.8/32 insert fails once -> partial install (fail-closed).
	fc.handleEvent(fwEvent{Kind: EvConnect, CN: "alice", VpnIP: "172.16.100.5"})
	// Reconnect (same session key) -> installer diffs and inserts only the missing rule.
	fc.handleEvent(fwEvent{Kind: EvUserChanged, CN: "alice"})
	// Disconnect -> all ACCEPTs removed.
	fc.handleEvent(fwEvent{Kind: EvDisconnect, CN: "alice", VpnIP: "172.16.100.5"})

	for k, n := range live {
		if n != 0 {
			t.Fatalf("N04: orphan ACCEPT rule left after retry+disconnect: %s x%d", k, n)
		}
	}
}

func ruleKey(args []string) string {
	var src, dst string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-s" {
			src = args[i+1]
		}
		if args[i] == "-d" {
			dst = args[i+1]
		}
	}
	return src + "->" + dst
}

// N05 (P1, F13): killUserSessions must consult the LIVE mgmt console; when it is
// unreachable it must return an error (not falsely confirm termination off a
// stale-empty cache).
func TestReauditKillUsesLiveSnapshot(t *testing.T) {
	// Reserve a port, then close it, so the address is guaranteed refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	app := &OvpnAdmin{mgmtInterfaces: map[string]string{"main": addr}}
	// Seed a stale-EMPTY cache: the old code would have returned nil here.
	app.setActiveClients(nil)

	if err := app.killUserSessions("bob"); err == nil {
		t.Fatal("N05: killUserSessions must return an error when the live mgmt poll cannot be completed")
	}
}

// N05 sibling: userDisconnectHandler ("disconnect now") must also decide off the
// LIVE mgmt console — when it's unreachable it must NOT report "disconnected: 0 /
// ok" off a stale-empty cache, but surface that it couldn't confirm.
func TestReauditDisconnectUsesLiveSnapshot(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	origIdx := *indexTxtPath
	t.Cleanup(func() { *indexTxtPath = origIdx })
	*indexTxtPath = writeIndexTxtWithUser(t, "bob")

	app := &OvpnAdmin{mgmtInterfaces: map[string]string{"main": addr}}
	app.setActiveClients(nil) // stale-empty cache: the old path returned ok/0 here

	req := httptest.NewRequest(http.MethodPost, "/api/user/disconnect", bytes.NewReader([]byte(`{"username":"bob"}`)))
	rec := httptest.NewRecorder()
	app.userDisconnectHandler(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("N05 sibling: disconnect must not report success off a stale cache when mgmt is unreachable, got 200: %s", rec.Body.String())
	}
}

// N09 sibling: concurrent MFA store writes (distinct users) must all reach disk —
// mfaStore.save marshalled outside the lock before the fix, losing enrollments.
func TestReauditConcurrentMFAWritesAreDurable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mfa.json")
	s := newMfaStore(path)

	const n = 48
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := s.set(fmt.Sprintf("user%02d", i), mfaRecord{Enabled: true}); err != nil {
				t.Errorf("set: %v", err)
			}
		}(i)
	}
	wg.Wait()

	// Reload from disk and assert none were lost.
	reloaded := newMfaStore(path)
	if reloaded.loadErr != nil {
		t.Fatalf("reload: %v", reloaded.loadErr)
	}
	for i := 0; i < n; i++ {
		if !reloaded.isEnabled(fmt.Sprintf("user%02d", i)) {
			t.Fatalf("N09 sibling: user%02d enrollment lost on disk under concurrent writes", i)
		}
	}
}

// N07 (P1, F16): crlFix must actually set the setgid bit on pki/.
func TestReauditCrlFixSetsSetgid(t *testing.T) {
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pki, "crl.pem"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := easyrsaDirPath
	easyrsaDirPath = &dir
	t.Cleanup(func() { easyrsaDirPath = prev })

	crlFix()

	fi, err := os.Stat(pki)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("N07: crlFix must set setgid on pki/, got mode %v", fi.Mode())
	}
}

// N08 (P1, F19): a MISSING MFA store when the durable enrollment marker still
// lists users must fail closed (loadErr set) instead of first-run.
func TestReauditMFAMissingStoreRetainsEnrollment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mfa.json")

	s := newMfaStore(path)
	if err := s.set("alice", mfaRecord{Enabled: true}); err != nil {
		t.Fatalf("set: %v", err)
	}
	// The marker must now exist.
	if _, err := os.Stat(path + ".enrolled"); err != nil {
		t.Fatalf("N08: enrollment marker not written: %v", err)
	}
	// Simulate the store being lost/deleted while the marker survives.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	s2 := newMfaStore(path)
	if s2.loadErr == nil {
		t.Fatal("N08: a missing MFA store with a non-empty enrollment marker must fail closed (loadErr)")
	}

	// A genuine first run (no marker, no store) must NOT fail closed.
	fresh := newMfaStore(filepath.Join(t.TempDir(), "mfa.json"))
	if fresh.loadErr != nil {
		t.Fatalf("N08: genuine first run must not set loadErr, got %v", fresh.loadErr)
	}
}

// N09 (P1, F21): concurrent epoch bumps must all reach disk (no lost update from
// the marshal/write race).
func TestReauditConcurrentEpochWritesAreDurable(t *testing.T) {
	prevFile := sessionEpochsFile
	t.Cleanup(func() {
		sessionEpochsFile = prevFile
		sessionEpochsMu.Lock()
		sessionEpochs = map[string]int64{}
		sessionEpochsMu.Unlock()
	})
	sessionEpochsFile = filepath.Join(t.TempDir(), "epochs.json")
	sessionEpochsMu.Lock()
	sessionEpochs = map[string]int64{}
	sessionEpochsMu.Unlock()

	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := bumpUserEpoch(fmt.Sprintf("user%02d", i)); err != nil {
				t.Errorf("bumpUserEpoch: %v", err)
			}
		}(i)
	}
	wg.Wait()

	raw, err := os.ReadFile(sessionEpochsFile)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk map[string]int64
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if len(onDisk) != n {
		t.Fatalf("N09: expected %d epochs persisted, got %d (lost updates)", n, len(onDisk))
	}
	for i := 0; i < n; i++ {
		if onDisk[fmt.Sprintf("user%02d", i)] != 1 {
			t.Fatalf("N09: user%02d epoch not durable: %v", i, onDisk)
		}
	}
}

// N10 (P2, F21/F23): if the epoch bump fails during mfaConfirm, MFA must be left
// DISABLED (bump happens before the enable is persisted).
func TestReauditMFAConfirmBumpFailureLeavesDisabled(t *testing.T) {
	app, _ := newTestAdminWithMFA(t)
	key, err := generateTOTPKey("testadmin")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.mfaStore.set("testadmin", mfaRecord{Secret: key.Secret(), Enabled: false}); err != nil {
		t.Fatal(err)
	}
	seedTestAdmin(t, "testadmin")

	// Make bumpUserEpoch fail: point the epochs file at a path whose parent is a
	// regular file (ENOTDIR on write).
	prevFile := sessionEpochsFile
	badParent := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(badParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sessionEpochsFile = filepath.Join(badParent, "epochs.json")
	t.Cleanup(func() { sessionEpochsFile = prevFile })

	code, _ := totp.GenerateCode(key.Secret(), time.Now())
	body := `{"code":"` + code + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/mfa/confirm", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signSession("testadmin", false)})
	rec := httptest.NewRecorder()
	app.mfaConfirmHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on epoch-bump failure, got %d: %s", rec.Code, rec.Body.String())
	}
	if app.mfaStore.isEnabled("testadmin") {
		t.Fatal("N10: MFA must be left DISABLED when the epoch bump fails (bump before enable)")
	}
}

// N11 (P2, F33): the scheduler must NOT bind a stale DNS answer to a route whose
// domain changed while resolution was in flight.
func TestReauditCommonRouteStaleDomainAnswerSkipped(t *testing.T) {
	dir := t.TempDir()
	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{
			{ID: "r1", Kind: "domain", Domain: "a.example.com"},
		}}},
		store: testFilesystemStore(dir),
	}

	prev := domainResolver
	domainResolver = func(ctx context.Context, d string) ([]string, error) {
		// While resolving the old domain, an operator edits the route's domain.
		_, _ = app.commonRoutes.update(func(cfg *CommonRoutesConfig) error {
			for i := range cfg.Routes {
				if cfg.Routes[i].ID == "r1" {
					cfg.Routes[i].Domain = "b.example.com"
				}
			}
			return nil
		}, app.persistCommonRoutes)
		return []string{"1.2.3.4"}, nil
	}
	t.Cleanup(func() { domainResolver = prev })

	app.refreshCommonRoutesOnce(context.Background())

	got := app.commonRoutes.snapshot().Routes[0]
	if len(got.ResolvedIPs) != 0 {
		t.Fatalf("N11: stale answer for the old domain must not be applied to the changed domain, got %v", got.ResolvedIPs)
	}
}

// N12 (P2, F28): CCD mask uses the RUNTIME network (server-config), not the
// startup flag.
func TestReauditRuntimeNetworkMaskForCcd(t *testing.T) {
	prev := openvpnNetwork
	flagVal := "172.16.100.0/24"
	openvpnNetwork = &flagVal
	t.Cleanup(func() { openvpnNetwork = prev })

	store := newServerConfigStore()
	cfg := defaultServerConfig()
	cfg.Initialized = true
	cfg.Network = "10.8.0.0"
	cfg.NetworkMask = "255.255.0.0"
	store.replace(cfg)
	app := &OvpnAdmin{serverConfigStore: store}

	if got := app.clientMaskDotted(); got != "255.255.0.0" {
		t.Fatalf("N12: clientMaskDotted must use the runtime network mask, got %q", got)
	}
}

// N13 (P2, F25): a personal CCD IP route with an IPv6 address or a non-contiguous
// mask must be rejected.
func TestReauditCcdPersonalRouteRejectsBadMask(t *testing.T) {
	app := &OvpnAdmin{}
	bad := Ccd{
		User:          "alice",
		ClientAddress: "dynamic",
		CustomRoutes: []ccdRoute{
			{Kind: "ip", Address: "10.0.0.0", Mask: "255.0.255.0"}, // non-contiguous
		},
	}
	if ok, _ := app.validateCcd(bad); ok {
		t.Fatal("N13: non-contiguous mask on a personal route must be rejected")
	}
	badV6 := Ccd{
		User:          "alice",
		ClientAddress: "dynamic",
		CustomRoutes: []ccdRoute{
			{Kind: "ip", Address: "2001:db8::1", Mask: "255.255.255.255"},
		},
	}
	if ok, _ := app.validateCcd(badV6); ok {
		t.Fatal("N13: IPv6 address on a personal route must be rejected")
	}
	good := Ccd{
		User:          "alice",
		ClientAddress: "dynamic",
		CustomRoutes: []ccdRoute{
			{Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"},
		},
	}
	if ok, msg := app.validateCcd(good); !ok {
		t.Fatalf("N13: a valid IPv4 route must pass, got %q", msg)
	}
}

// N14 (P2, F36): unrevoke reconciles the CRL — when index.txt says V but the
// serial is still listed in crl.pem, regenerate it.
func TestReauditUnrevokeReconcilesCRL(t *testing.T) {
	caCert, caKey := testCA(t)
	cert := testClientCert(t, caCert, caKey, "alice")
	serial := fmt.Sprintf("%X", cert.SerialNumber)

	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0o755); err != nil {
		t.Fatal(err)
	}
	// index.txt: cert is VALID (V), but the CRL still lists its serial (stale).
	idxPath := filepath.Join(pki, "index.txt")
	if err := os.WriteFile(idxPath, []byte(vLine(serial, "alice")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pki, "crl.pem"), crlWithSerial(t, serial), 0o644); err != nil {
		t.Fatal(err)
	}
	// Stage a CLEAN CRL (no revoked entries) that the fake gen-crl will install.
	clean := crlWith(t) // empty revocation list
	cleanPath := filepath.Join(dir, "clean-crl.pem")
	if err := os.WriteFile(cleanPath, clean, 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "easyrsa-fake.sh")
	script := fmt.Sprintf(`#!/bin/sh
case "$*" in
  *gen-crl*) cp %q %q; exit 0 ;;
esac
exit 0
`, cleanPath, filepath.Join(pki, "crl.pem"))
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &filesystemStore{easyrsaDirPath: dir, easyrsaBinPath: bin, ccdDir: dir, indexTxtPath: idxPath}

	if err := s.UnrevokeClient("alice"); err != nil {
		t.Fatalf("N14: unrevoke must reconcile a stale CRL, got %v", err)
	}
	present, err := crlContainsSerialHex(filepath.Join(pki, "crl.pem"), serial)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("N14: serial must be gone from the CRL after reconcile")
	}
}

// N15 (P2, F48): a TEMPORARILY revoked (revokedAt only) k8s CCD keeps its static
// IP reservation; only revokedForever is dropped.
func TestReauditTempRevokeKeepsStaticIP(t *testing.T) {
	tempRevoked := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "c1", Namespace: namespace,
			Labels:      map[string]string{"name": "alice", "index.txt": "", "type": "clientAuth"},
			Annotations: map[string]string{"revokedAt": "260101000000Z"}},
		Data: map[string][]byte{"ccd": []byte("ifconfig-push 172.16.100.42 255.255.255.0\n")},
	}
	permaRevoked := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "c2", Namespace: namespace,
			Labels:      map[string]string{"name": "REVOKED-bob", "index.txt": "", "type": "clientAuth", "revokedForever": "true"},
			Annotations: map[string]string{"revokedAt": "260101000000Z"}},
		Data: map[string][]byte{"ccd": []byte("ifconfig-push 172.16.100.43 255.255.255.0\n")},
	}
	s := &kubernetesStore{pki: &OpenVPNPKI{KubeClient: fake.NewSimpleClientset(tempRevoked, permaRevoked)}}
	out, err := s.ListCcdSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].CommonName != "alice" {
		t.Fatalf("N15: temp-revoked CCD must be kept (reservation), perma-revoked dropped; got %+v", out)
	}
}

// N16 (P2, F26/F27): a soft change whose live reload cannot be confirmed must NOT
// be reported as applied — apply returns "soft-pending".
func TestReauditFailedReloadIsNotReportedApplied(t *testing.T) {
	dir := t.TempDir()
	backend := testFilesystemStore(dir)
	store := newServerConfigStore()
	store.replace(defaultServerConfig())
	mgr := &serverManager{
		store:          store,
		persistBackend: backend,
		mgmtAddr:       "127.0.0.1:0", // unreachable -> SIGHUP cannot be delivered
		confPath:       filepath.Join(dir, "server.conf"),
		ccdEnabled:     true,
	}
	cfg := store.snapshot()
	cfg.Verb = cfg.Verb + 1 // soft-only change

	kind, err := mgr.apply(context.Background(), cfg, "admin")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if kind != "soft-pending" {
		t.Fatalf("N16: a failed soft reload must report %q, got %q", "soft-pending", kind)
	}
}

// N17 (P2, F40): readiness must reject a non-empty but unparseable CRL.
func TestReauditReadinessRejectsMalformedCRL(t *testing.T) {
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pki, "crl.pem"), []byte("not a valid CRL"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := easyrsaDirPath
	easyrsaDirPath = &dir
	t.Cleanup(func() { easyrsaDirPath = prev })

	rc := buildReadinessChecker(testFilesystemStore(dir), &OvpnAdmin{})
	if err := rc.crlReady(); err == nil {
		t.Fatal("N17: a non-empty unparseable crl.pem must make readiness fail")
	}
}

// N18 (P2, F30): a legacy CCD (redirect push, no state line) must not cement the
// GLOBAL full-tunnel force as a personal choice.
func TestReauditLegacyGlobalRedirectMigration(t *testing.T) {
	dir := t.TempDir()
	app := newTestAdminCcd(t, dir)
	// Legacy CCD: only the rendered redirect push, no __user_redirect__ state line.
	if err := app.store.SaveCcd("alice", []byte(`push "redirect-gateway def1" # __redirect_gateway__`+"\n")); err != nil {
		t.Fatal(err)
	}

	scStore := newServerConfigStore()

	// Global force ON -> the ambiguous legacy push must NOT be read as personal.
	scStore.replace(ServerConfig{RedirectGateway: true})
	app.serverConfigStore = scStore
	if app.parseCcd("alice").RedirectGateway {
		t.Fatal("N18: legacy redirect push must not be treated as personal while global force is on")
	}

	// Global force OFF -> the push could only have been personal; preserve it.
	scStore.replace(ServerConfig{RedirectGateway: false})
	if !app.parseCcd("alice").RedirectGateway {
		t.Fatal("N18: with global force off, a legacy redirect push must be preserved as personal")
	}
}

// N19 (P2, F06/F07): a legacy client whose CN starts with "_" stays manageable;
// the exact internal blob names remain reserved.
func TestReauditExistingUnderscoreClientRemainsManageable(t *testing.T) {
	if err := validateExistingUsername("_alice"); err != nil {
		t.Fatalf("N19: an existing _alice must be manageable, got %v", err)
	}
	if err := validateExistingUsername("_server_config.json"); err == nil {
		t.Fatal("N19: the internal server-config blob name must stay reserved")
	}
	if err := validateExistingUsername("_common_routes.json"); err == nil {
		t.Fatal("N19: the internal common-routes blob name must stay reserved")
	}
	// Creating a NEW client with a leading underscore is still forbidden.
	if err := validateUsername("_alice"); err == nil {
		t.Fatal("N19: creating a new _-prefixed CN must still be rejected")
	}

	// Handler-level: revoking an existing _alice must not 400 on validation.
	caCert, caKey := testCA(t)
	cert := testClientCert(t, caCert, caKey, "_alice")
	serial := fmt.Sprintf("%X", cert.SerialNumber)
	crl := crlWithSerial(t, serial)
	store := fsTestEnv(t, 0, vLine(serial, "_alice"), crl)

	origIdx := *indexTxtPath
	t.Cleanup(func() { *indexTxtPath = origIdx })
	*indexTxtPath = store.indexTxtPath

	app := &OvpnAdmin{store: store}
	req := httptest.NewRequest(http.MethodPost, "/api/user/revoke", bytes.NewReader([]byte(`{"username":"_alice"}`)))
	rec := httptest.NewRecorder()
	app.userRevokeHandler(rec, req)
	if rec.Code == http.StatusBadRequest && strings.Contains(rec.Body.String(), "имя") {
		t.Fatalf("N19: revoking _alice must not be blocked by username validation, got %d: %s", rec.Code, rec.Body.String())
	}
}

// N20 (P2, F29): a static IP already held by a LIVE dynamic client must be
// rejected.
func TestReauditStaticIPCannotCollideWithLiveDynamicClient(t *testing.T) {
	dir := t.TempDir()
	app := &OvpnAdmin{store: testFilesystemStore(dir)}
	app.setActiveClients([]clientStatus{
		{CommonName: "bob", VirtualAddress: "172.16.100.42"},
	})

	if app.checkStaticAddressIsFree("172.16.100.42", "alice") {
		t.Fatal("N20: an address in use by a live dynamic client must not be free for a static assignment")
	}
	if !app.checkStaticAddressIsFree("172.16.100.43", "alice") {
		t.Fatal("N20: an unused address must be assignable")
	}
}

package main

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// writeRotateFakeEasyrsa drops a stub easyrsa that, on build-client-full,
// appends a fresh V line for the CN to pki/index.txt (so RotateClient's
// post-build swap finds the new entry), and treats revoke/gen-crl as no-ops.
func writeRotateFakeEasyrsa(t *testing.T, dir, newSerial string) string {
	t.Helper()
	bin := filepath.Join(dir, "easyrsa-rotate-fake.sh")
	script := fmt.Sprintf(`#!/bin/sh
case "$1$2$3" in
  *build-client-full*)
    printf 'V\t990101000000Z\t\t%s\tunknown\t/CN=%%s\n' "$3" >> pki/index.txt
    exit 0 ;;
esac
case "$*" in
  *gen-crl*) exit 0 ;;
  *revoke*) exit 0 ;;
esac
exit 0
`, newSerial)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake easyrsa: %v", err)
	}
	return bin
}

// TestAuditFilesystemRotationRevokesOldSerial locks audit F01: after a
// successful rotation the OLD serial must be marked revoked (R) in index.txt so
// gen-crl lists it, and rotate must fail if that serial is absent from the CRL.
func TestAuditFilesystemRotationRevokesOldSerial(t *testing.T) {
	oldSerial := "0A0B0C"
	crl := crlWithSerial(t, oldSerial) // CRL that DOES contain the old serial
	idx := vLine(oldSerial, "alice")

	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0o755); err != nil {
		t.Fatal(err)
	}
	ccd := filepath.Join(dir, "ccd")
	if err := os.MkdirAll(ccd, 0o755); err != nil {
		t.Fatal(err)
	}
	idxPath := filepath.Join(pki, "index.txt")
	if err := os.WriteFile(idxPath, []byte(idx), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pki, "crl.pem"), crl, 0o644); err != nil {
		t.Fatal(err)
	}
	s := &filesystemStore{
		easyrsaDirPath: dir,
		easyrsaBinPath: writeRotateFakeEasyrsa(t, dir, "0BEEF0"),
		ccdDir:         ccd,
		indexTxtPath:   idxPath,
	}

	if err := s.RotateClient("alice", ""); err != nil {
		t.Fatalf("RotateClient: unexpected error: %v", err)
	}

	// The old serial must now be flagged R (revoked), not V.
	var oldFlag string
	for _, u := range indexTxtParser(fRead(idxPath)) {
		if u.SerialNumber == oldSerial {
			oldFlag = u.Flag
		}
	}
	if oldFlag != "R" {
		t.Fatalf("F01: old serial %s must be R (revoked) after rotate, got %q", oldSerial, oldFlag)
	}
}

// TestAuditFilesystemRotationFailsWhenOldSerialNotInCRL is the defense-in-depth
// half of F01: if gen-crl did not land the old serial in the CRL, rotate must
// report failure rather than a false success.
func TestAuditFilesystemRotationFailsWhenOldSerialNotInCRL(t *testing.T) {
	oldSerial := "0A0B0C"
	emptyCRL := crlWith(t) // no serials
	idx := vLine(oldSerial, "alice")

	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0o755); err != nil {
		t.Fatal(err)
	}
	ccd := filepath.Join(dir, "ccd")
	if err := os.MkdirAll(ccd, 0o755); err != nil {
		t.Fatal(err)
	}
	idxPath := filepath.Join(pki, "index.txt")
	if err := os.WriteFile(idxPath, []byte(idx), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pki, "crl.pem"), emptyCRL, 0o644); err != nil {
		t.Fatal(err)
	}
	s := &filesystemStore{
		easyrsaDirPath: dir,
		easyrsaBinPath: writeRotateFakeEasyrsa(t, dir, "0BEEF0"),
		ccdDir:         ccd,
		indexTxtPath:   idxPath,
	}

	if err := s.RotateClient("alice", ""); err == nil {
		t.Fatal("F01: rotate must fail when the old serial is absent from the CRL")
	}
}

// TestAuditKubernetesRevokeRetryRepairsCRL locks audit F35: a retry of revoke
// after a partial failure (revokedAt already stamped, but the CRL was never
// regenerated/published) must NOT no-op — it must reconcile the CRL to
// completion so the serial actually lands in it.
func TestAuditKubernetesRevokeRetryRepairsCRL(t *testing.T) {
	caCert, caKey := testCA(t)
	cert := testClientCert(t, caCert, caKey, "revuser")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	// easyrsaRevoke and its downstream write to ${easyrsaDirPath}/pki/*.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pki"), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := easyrsaDirPath
	easyrsaDirPath = &dir
	t.Cleanup(func() { easyrsaDirPath = prev })

	// Client secret already carries revokedAt (the partial-failure state) but the
	// CRL was never built. Pre-fix easyrsaRevoke would early-return nil here.
	clientSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "revuser",
			Namespace: namespace,
			Labels:    map[string]string{"name": "revuser", "index.txt": "", "type": "clientAuth"},
			Annotations: map[string]string{
				"revokedAt": time.Now().Format(indexTxtDateFormat),
			},
		},
		Data: map[string][]byte{certFileName: certPEM},
	}

	pki := &OpenVPNPKI{
		CACert:       caCert,
		CAPrivKeyRSA: caKey,
		KubeClient:   fake.NewSimpleClientset(clientSecret),
	}

	if err := pki.easyrsaRevoke("revuser"); err != nil {
		t.Fatalf("easyrsaRevoke retry: unexpected error: %v", err)
	}

	// The reconciliation must have rebuilt the CRL and included the serial.
	if !pki.crlContainsSerial(cert.SerialNumber) {
		t.Fatalf("F35: retry did not rebuild the CRL — serial %s absent (revoke no-oped)", cert.SerialNumber)
	}
}

// TestAuditReservedIdentityRejected locks audit F07 at the single choke point:
// the server/CA identities and the REVOKED archival marker are not valid client
// usernames, so every endpoint and store method that validates a username
// refuses them.
func TestAuditReservedIdentityRejected(t *testing.T) {
	for _, bad := range []string{"server", "SERVER", "Server", "ca", "CA", "REVOKED-alice-abc"} {
		if err := validateUsername(bad); err == nil {
			t.Errorf("F07: validateUsername(%q) must be rejected as a reserved identity", bad)
		}
	}
	// A normal client name still validates.
	if err := validateUsername("alice"); err != nil {
		t.Fatalf("F07: legitimate username rejected: %v", err)
	}
}

// TestAuditUserEndpointsRejectServerIdentity is the handler-level guard for F07:
// delete and config-export refuse username=server before touching the store, so
// a service token cannot delete the server cert or export the server key.
func TestAuditUserEndpointsRejectServerIdentity(t *testing.T) {
	app := &OvpnAdmin{}

	del := httptest.NewRequest(http.MethodPost, "/api/user/delete", strings.NewReader(`{"username":"server"}`))
	delRec := httptest.NewRecorder()
	app.userDeleteHandler(delRec, del)
	if delRec.Code != http.StatusBadRequest {
		t.Fatalf("F07: delete(server) must be 400, got %d", delRec.Code)
	}

	show := httptest.NewRequest(http.MethodPost, "/api/user/config/show", strings.NewReader(`{"username":"server"}`))
	showRec := httptest.NewRecorder()
	app.userShowConfigHandler(showRec, show)
	if showRec.Code != http.StatusBadRequest {
		t.Fatalf("F07: config/show(server) must be 400, got %d", showRec.Code)
	}
}

// TestAuditReservedCCDNamesRejected locks audit F06: the internal config blobs
// and DEFAULT cannot be used as a CCD username, so ccd/apply -> SaveCcd can't
// overwrite _server_config.json / _common_routes.json.
func TestAuditReservedCCDNamesRejected(t *testing.T) {
	for _, bad := range []string{"_server_config.json", "_common_routes.json", "_anything", "DEFAULT", "default"} {
		if err := validateUsername(bad); err == nil {
			t.Errorf("F06: validateUsername(%q) must be rejected", bad)
		}
	}
	// Handler edge: ccd/apply with a reserved name is a 400 before any store write.
	app := &OvpnAdmin{}
	req := httptest.NewRequest(http.MethodPost, "/api/user/ccd/apply", strings.NewReader(`{"User":"_server_config.json","ClientAddress":"dynamic"}`))
	rec := httptest.NewRecorder()
	app.userApplyCcdHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F06: ccd/apply(_server_config.json) must be 400, got %d", rec.Code)
	}
}

// TestAuditResolvedIPValidation locks audit F05: client-supplied resolved IPs
// carrying newlines/extra directives or non-IPv4 values are rejected, and
// server results are filtered to clean IPv4.
func TestAuditResolvedIPValidation(t *testing.T) {
	// Strict validation (client input path).
	if err := validateResolvedIPv4s([]string{"203.0.113.1"}); err != nil {
		t.Fatalf("F05: valid IPv4 rejected: %v", err)
	}
	inject := "203.0.113.1\npush \"dhcp-option DNS 203.0.113.53\""
	if err := validateResolvedIPv4s([]string{inject}); err == nil {
		t.Fatal("F05: injected directive in resolved IP must be rejected")
	}
	if err := validateResolvedIPv4s([]string{"2001:db8::1"}); err == nil {
		t.Fatal("F05: IPv6 in an IPv4 resolved-IP field must be rejected")
	}
	// Filtering (server-resolved path) drops non-IPv4 but keeps clean IPv4.
	got := filterIPv4([]string{"203.0.113.1", "2001:db8::1", "bad value", "198.51.100.7"})
	if len(got) != 2 || got[0] != "203.0.113.1" || got[1] != "198.51.100.7" {
		t.Fatalf("F05: filterIPv4 = %v, want [203.0.113.1 198.51.100.7]", got)
	}
}

// TestAuditMFACorruptStoreFailsClosed locks audit F19: a corrupt/unreadable
// existing MFA store surfaces loadErr (which startup turns into a fatal), instead
// of silently becoming an empty "no MFA configured" store.
func TestAuditMFACorruptStoreFailsClosed(t *testing.T) {
	dir := t.TempDir()

	// Corrupt JSON.
	corrupt := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if s := newMfaStore(corrupt); s.loadErr == nil {
		t.Fatal("F19: corrupt MFA store must set loadErr (fail closed), got nil")
	}

	// Missing file is fine (first run).
	if s := newMfaStore(filepath.Join(dir, "missing.json")); s.loadErr != nil {
		t.Fatalf("F19: missing MFA store must NOT be an error, got %v", s.loadErr)
	}

	// Valid store loads cleanly.
	valid := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(valid, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s := newMfaStore(valid); s.loadErr != nil {
		t.Fatalf("F19: valid MFA store must load, got %v", s.loadErr)
	}
}

// seedTestAdmin registers user in the in-memory htpasswd table so verifySession's
// audit-F22 existence check accepts sessions minted for it in tests.
func seedTestAdmin(t *testing.T, user string) {
	t.Helper()
	adminAuthMu.Lock()
	if htpasswdUsers == nil {
		htpasswdUsers = map[string]string{}
	}
	htpasswdUsers[user] = "x"
	adminAuthMu.Unlock()
	t.Cleanup(func() {
		adminAuthMu.Lock()
		delete(htpasswdUsers, user)
		adminAuthMu.Unlock()
	})
}

// TestAuditEpochPersistenceFailureDoesNotReviveSession locks audit F21: when the
// session-epoch bump cannot be persisted, bumpUserEpoch returns an error (so the
// handler reports 5xx) and rolls back the in-memory increment, keeping memory and
// disk consistent instead of silently claiming a revocation that a restart undoes.
func TestAuditEpochPersistenceFailureDoesNotReviveSession(t *testing.T) {
	ensureSigningKey()
	user := "epoch_persist_user"
	seedTestAdmin(t, user)

	// Point the epochs file at a path whose parent is a regular file (ENOTDIR).
	f := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := sessionEpochsFile
	sessionEpochsFile = filepath.Join(f, "epochs.json")
	t.Cleanup(func() { sessionEpochsFile = prev })

	epochBefore := getUserEpoch(user)
	if err := bumpUserEpoch(user); err == nil {
		t.Fatal("F21: bumpUserEpoch must return an error when the epoch can't be persisted")
	}
	if got := getUserEpoch(user); got != epochBefore {
		t.Fatalf("F21: failed bump must roll back in-memory epoch (was %d, got %d)", epochBefore, got)
	}
}

// TestAuditSessionOfDeletedAdminRejected locks audit F22: a session for an admin
// removed from htpasswd must stop verifying immediately, not linger until TTL.
func TestAuditSessionOfDeletedAdminRejected(t *testing.T) {
	ensureSigningKey()
	user := "deleted_admin_user"
	seedTestAdmin(t, user)

	token := signSession(user, true)
	if _, ok := verifySession(token); !ok {
		t.Fatal("session must verify while the admin exists")
	}
	adminAuthMu.Lock()
	delete(htpasswdUsers, user)
	adminAuthMu.Unlock()
	if _, ok := verifySession(token); ok {
		t.Fatal("F22: session of a deleted admin must be rejected")
	}
}

// TestAuditIntermediateMFATokenRevokedOnPasswordChange locks audit F22: a
// first-factor MFA token minted before an epoch bump (password change / MFA
// enable) must no longer verify.
func TestAuditIntermediateMFATokenRevokedOnPasswordChange(t *testing.T) {
	ensureSigningKey()
	user := "mfa_epoch_user"

	prev := sessionEpochsFile
	sessionEpochsFile = "" // persist is a no-op so the bump succeeds
	t.Cleanup(func() { sessionEpochsFile = prev })

	tok := signMfaToken(user)
	if _, _, _, ok := verifyMfaToken(tok); !ok {
		t.Fatal("MFA token must verify before the epoch bump")
	}
	if err := bumpUserEpoch(user); err != nil {
		t.Fatalf("bumpUserEpoch: %v", err)
	}
	if _, _, _, ok := verifyMfaToken(tok); ok {
		t.Fatal("F22: an MFA token minted before the epoch bump must be rejected")
	}
}

// TestAuditBackupCodeConsumedAtomically locks audit F20: the same one-shot
// backup code offered by many concurrent requests is accepted exactly once.
func TestAuditBackupCodeConsumedAtomically(t *testing.T) {
	ensureSigningKey()
	s := newMfaStore(filepath.Join(t.TempDir(), "mfa.json"))

	const plain = "BACKUPCODE1"
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "t", AccountName: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.set("u", mfaRecord{Secret: key.Secret(), Enabled: true, BackupCodes: []string{string(hash)}}); err != nil {
		t.Fatal(err)
	}

	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	now := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, _ := s.verifyAndConsume("u", plain, now)
			if res == mfaOKBackup {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("F20: one-shot backup code accepted %d times (want exactly 1)", successes)
	}
}

// TestAuditTOTPReplayAfterAnotherValidCode locks audit F20: after accepting the
// current code, offering the previous window's code (also valid) and then the
// current code again must reject the replayed current code — replay protection
// tracks used time-steps, not just the single last code.
func TestAuditTOTPReplayAfterAnotherValidCode(t *testing.T) {
	ensureSigningKey()
	s := newMfaStore(filepath.Join(t.TempDir(), "mfa.json"))

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "t", AccountName: "u"})
	if err != nil {
		t.Fatal(err)
	}
	secret := key.Secret()
	if err := s.set("u", mfaRecord{Secret: secret, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	codeCur, _ := totp.GenerateCode(secret, now)
	codePrev, _ := totp.GenerateCode(secret, now.Add(-30*time.Second))
	if codeCur == codePrev {
		t.Skip("adjacent TOTP windows produced identical codes; rare, skip")
	}

	if res, _ := s.verifyAndConsume("u", codeCur, now); res != mfaOKTOTP {
		t.Fatalf("current code must be accepted first, got %v", res)
	}
	if res, _ := s.verifyAndConsume("u", codePrev, now); res != mfaOKTOTP {
		t.Fatalf("previous-window code must be accepted (distinct step), got %v", res)
	}
	if res, _ := s.verifyAndConsume("u", codeCur, now); res != mfaReject {
		t.Fatalf("F20: replay of the already-used current code must be rejected, got %v", res)
	}
}

// TestAuditPasswordAuthEnvSeedsServerConfig locks part of audit F03: the legacy
// OVPN_AUTH env seeds the persisted server-config PasswordAuth default, so the
// env flag and the runtime policy source no longer disagree.
func TestAuditPasswordAuthEnvSeedsServerConfig(t *testing.T) {
	t.Setenv("OVPN_AUTH", "true")
	if !defaultServerConfig().PasswordAuth {
		t.Fatal("F03: OVPN_AUTH=true must seed defaultServerConfig().PasswordAuth")
	}
	t.Setenv("OVPN_AUTH", "false")
	if defaultServerConfig().PasswordAuth {
		t.Fatal("F03: OVPN_AUTH=false must leave PasswordAuth off")
	}
}

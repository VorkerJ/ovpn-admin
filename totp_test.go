package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// mintMfaTokenForTest mints an MFA token with an arbitrary TTL — used only by
// tests that need to construct already-expired tokens. Production code calls
// signMfaToken which always uses mfaTokenTTL.
func mintMfaTokenForTest(user string, ttl time.Duration) string {
	secret := sessionSecret()
	jtiBytes := make([]byte, 16)
	_, _ = rand.Read(jtiBytes)
	p := mfaTokenPayload{
		User:    user,
		Purpose: "mfa",
		Exp:     time.Now().Add(ttl).Unix(),
		Jti:     base64.RawURLEncoding.EncodeToString(jtiBytes),
	}
	data, _ := json.Marshal(p)
	enc := base64.RawURLEncoding.EncodeToString(data)
	mac := computeHMAC(enc, secret)
	return enc + "." + mac
}

func init() {
	// Tests need htpasswdUsers initialized for validateCredentials() to work,
	// and a sessionSigningKey for sessionSecret() / signSession() to work.
	if htpasswdUsers == nil {
		htpasswdUsers = map[string]string{"testuser": "$2a$10$dummy"}
	}
	if sessionSigningKey == nil {
		sessionSigningKey = make([]byte, 64)
		// Deterministic for tests — content doesn't matter, only that it's set.
		for i := range sessionSigningKey {
			sessionSigningKey[i] = byte(i)
		}
	}
}

func TestMfaStore_RoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "mfa.json")

	s := newMfaStore(path)
	rec := mfaRecord{
		Secret:      "JBSWY3DPEHPK3PXP",
		Enabled:     true,
		BackupCodes: []string{"hash1", "hash2"},
		CreatedAt:   "2025-01-01T00:00:00Z",
	}
	s.set("alice", rec)

	// Verify in-memory
	got, ok := s.get("alice")
	if !ok {
		t.Fatal("expected to find alice in store")
	}
	if got.Secret != rec.Secret || got.Enabled != rec.Enabled || len(got.BackupCodes) != 2 {
		t.Fatalf("record mismatch: got %+v", got)
	}

	// Reload from disk
	s2 := newMfaStore(path)
	got2, ok := s2.get("alice")
	if !ok {
		t.Fatal("expected to find alice after reload")
	}
	if got2.Secret != rec.Secret || got2.Enabled != rec.Enabled {
		t.Fatalf("record mismatch after reload: got %+v", got2)
	}

	// Verify file permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected file permission 0600, got %04o", perm)
	}
}

func TestMfaStore_Delete(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "mfa.json")

	s := newMfaStore(path)
	s.set("bob", mfaRecord{Secret: "SECRET", Enabled: true})

	if !s.isEnabled("bob") {
		t.Fatal("bob should be enabled")
	}

	s.delete("bob")

	if _, ok := s.get("bob"); ok {
		t.Fatal("bob should be deleted")
	}
	if s.isEnabled("bob") {
		t.Fatal("bob should not be enabled after delete")
	}
}

func TestVerifyTOTP_ValidCode(t *testing.T) {
	t.Parallel()

	key, err := generateTOTPKey("testuser")
	if err != nil {
		t.Fatalf("generateTOTPKey: %v", err)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if !verifyTOTPCode(key.Secret(), code) {
		t.Error("expected valid code to pass verification")
	}
}

func TestVerifyTOTP_InvalidCode(t *testing.T) {
	t.Parallel()

	key, err := generateTOTPKey("testuser")
	if err != nil {
		t.Fatalf("generateTOTPKey: %v", err)
	}

	if verifyTOTPCode(key.Secret(), "000000") {
		t.Error("expected invalid code to be rejected")
	}
}

func TestBackupCodes_GenerateAndVerify(t *testing.T) {
	t.Parallel()

	plain, hashed := generateBackupCodes(8)

	if len(plain) != 8 || len(hashed) != 8 {
		t.Fatalf("expected 8 codes, got %d plain / %d hashed", len(plain), len(hashed))
	}

	// Verify format: XXXX-XXXX
	for _, code := range plain {
		if len(code) != 9 || code[4] != '-' {
			t.Errorf("unexpected backup code format: %q", code)
		}
	}

	// First code should verify
	if !verifyBackupCode(plain[0], hashed) {
		t.Error("first backup code should verify")
	}

	// Wrong code should be rejected
	if verifyBackupCode("ZZZZ-ZZZZ", hashed) {
		t.Error("wrong backup code should be rejected")
	}
}

func TestBackupCodes_OneTimeUse(t *testing.T) {
	t.Parallel()

	plain, hashed := generateBackupCodes(3)

	// Consume first code
	remaining := consumeBackupCode(plain[0], hashed)
	if len(remaining) != 2 {
		t.Fatalf("expected 2 remaining codes, got %d", len(remaining))
	}

	// First code should no longer verify against remaining
	if verifyBackupCode(plain[0], remaining) {
		t.Error("consumed backup code should no longer verify")
	}

	// Second code should still work
	if !verifyBackupCode(plain[1], remaining) {
		t.Error("unconsumed backup code should still verify")
	}
}

func TestMfaToken_SignAndVerify(t *testing.T) {
	t.Parallel()

	token := signMfaToken("alice")
	user, _, _, ok := verifyMfaToken(token)
	if !ok {
		t.Fatal("expected token to be valid")
	}
	if user != "alice" {
		t.Errorf("expected user 'alice', got %q", user)
	}
}

func TestMfaToken_Expired(t *testing.T) {
	t.Parallel()

	// Sign with a negative TTL so the token is already expired
	token := mintMfaTokenForTest("alice", -1*time.Minute)
	_, _, _, ok := verifyMfaToken(token)
	if ok {
		t.Error("expected expired token to be rejected")
	}
}

// ── Integration test helpers ────────────────────────────────────────────────

// newTestAdminWithMFA creates a minimal OvpnAdmin with MFA store and
// configures htpasswdUsers with a test user. NOT safe for t.Parallel()
// because it mutates the package-level htpasswdUsers.
func newTestAdminWithMFA(t *testing.T) (*OvpnAdmin, string) {
	t.Helper()
	dir := t.TempDir()
	mfaPath := filepath.Join(dir, "mfa.json")

	pass := "testpass123"
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	htpasswdUsers = map[string]string{"testadmin": string(hash)}

	oAdmin := &OvpnAdmin{
		mfaStore: newMfaStore(mfaPath),
	}
	return oAdmin, pass
}

// sessionCookie creates an authenticated session cookie for the given user.
func sessionCookie(user string) *http.Cookie {
	return &http.Cookie{
		Name:  sessionCookieName,
		Value: signSession(user),
	}
}

// ── Integration tests ───────────────────────────────────────────────────────

func TestMfaLogin_WithoutMFA(t *testing.T) {
	oAdmin, pass := newTestAdminWithMFA(t)

	body := `{"username":"testadmin","password":"` + pass + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	oAdmin.loginHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp["ok"] != true {
		t.Errorf("expected ok:true, got %v", resp["ok"])
	}
	if _, hasMfa := resp["mfa_required"]; hasMfa {
		t.Errorf("expected no mfa_required field, got %v", resp["mfa_required"])
	}

	// Session cookie must be set
	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected session cookie to be set")
	}
}

func TestMfaLogin_WithMFA(t *testing.T) {
	oAdmin, pass := newTestAdminWithMFA(t)

	// Generate a TOTP key and enable MFA for testadmin
	key, err := generateTOTPKey("testadmin")
	if err != nil {
		t.Fatalf("generateTOTPKey: %v", err)
	}
	_, hashedBackup := generateBackupCodes(2)
	oAdmin.mfaStore.set("testadmin", mfaRecord{
		Secret:      key.Secret(),
		Enabled:     true,
		BackupCodes: hashedBackup,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	})

	// Step 1: login with password → should get mfa_required + mfa_token
	body := `{"username":"testadmin","password":"` + pass + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	oAdmin.loginHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("step1: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var step1 map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &step1); err != nil {
		t.Fatalf("step1 unmarshal: %v", err)
	}
	if step1["mfa_required"] != true {
		t.Fatalf("expected mfa_required:true, got %v", step1["mfa_required"])
	}
	mfaToken, ok := step1["mfa_token"].(string)
	if !ok || mfaToken == "" {
		t.Fatal("expected mfa_token string in response")
	}

	// Step 2: submit TOTP code with mfa_token
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	mfaBody := `{"mfa_token":"` + mfaToken + `","code":"` + code + `"}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/login/mfa", strings.NewReader(mfaBody))
	req2.RemoteAddr = "127.0.0.1:12345"
	rec2 := httptest.NewRecorder()

	oAdmin.mfaLoginHandler(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("step2: expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}

	// Session cookie must be set after MFA
	cookies := rec2.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected session cookie after MFA login")
	}
}

func TestMfaSetup_Confirm_Cycle(t *testing.T) {
	oAdmin, _ := newTestAdminWithMFA(t)
	cookie := sessionCookie("testadmin")

	// Step 1: POST /api/mfa/setup
	req := httptest.NewRequest(http.MethodPost, "/api/mfa/setup", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	oAdmin.mfaSetupHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("setup: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var setupResp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &setupResp); err != nil {
		t.Fatalf("setup unmarshal: %v", err)
	}
	secret, ok := setupResp["secret"].(string)
	if !ok || secret == "" {
		t.Fatal("expected secret in setup response")
	}
	if _, ok := setupResp["qr_url"].(string); !ok {
		t.Fatal("expected qr_url in setup response")
	}

	// Step 2: Generate valid TOTP code and POST /api/mfa/confirm
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	confirmBody := `{"code":"` + code + `"}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/mfa/confirm", strings.NewReader(confirmBody))
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()

	oAdmin.mfaConfirmHandler(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("confirm: expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}

	var confirmResp map[string]interface{}
	if err := json.Unmarshal(rec2.Body.Bytes(), &confirmResp); err != nil {
		t.Fatalf("confirm unmarshal: %v", err)
	}
	backupCodes, ok := confirmResp["backup_codes"].([]interface{})
	if !ok {
		t.Fatal("expected backup_codes array in confirm response")
	}
	if len(backupCodes) != 8 {
		t.Fatalf("expected 8 backup codes, got %d", len(backupCodes))
	}

	// Step 3: GET /api/mfa/status → enabled: true
	req3 := httptest.NewRequest(http.MethodGet, "/api/mfa/status", nil)
	req3.AddCookie(cookie)
	rec3 := httptest.NewRecorder()

	oAdmin.mfaStatusHandler(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d: %s", rec3.Code, rec3.Body.String())
	}

	var statusResp map[string]interface{}
	if err := json.Unmarshal(rec3.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("status unmarshal: %v", err)
	}
	if statusResp["enabled"] != true {
		t.Errorf("expected enabled:true, got %v", statusResp["enabled"])
	}
}

func TestMfaLogin_BackupCode(t *testing.T) {
	oAdmin, pass := newTestAdminWithMFA(t)

	// Generate TOTP key and known backup codes
	key, err := generateTOTPKey("testadmin")
	if err != nil {
		t.Fatalf("generateTOTPKey: %v", err)
	}
	plainCodes, hashedCodes := generateBackupCodes(3)
	oAdmin.mfaStore.set("testadmin", mfaRecord{
		Secret:      key.Secret(),
		Enabled:     true,
		BackupCodes: hashedCodes,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	})

	// Step 1: login with password to get mfa_token
	body := `{"username":"testadmin","password":"` + pass + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	oAdmin.loginHandler(rec, req)

	var step1 map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &step1); err != nil {
		t.Fatalf("step1 unmarshal: %v", err)
	}
	mfaToken := step1["mfa_token"].(string)

	// Step 2: use backup code
	mfaBody := `{"mfa_token":"` + mfaToken + `","code":"` + plainCodes[0] + `"}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/login/mfa", strings.NewReader(mfaBody))
	req2.RemoteAddr = "127.0.0.1:12345"
	rec2 := httptest.NewRecorder()

	oAdmin.mfaLoginHandler(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("backup login: expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}

	// Verify backup code was consumed (only 2 remaining)
	updatedRec, ok := oAdmin.mfaStore.get("testadmin")
	if !ok {
		t.Fatal("expected testadmin still in mfaStore")
	}
	if len(updatedRec.BackupCodes) != 2 {
		t.Fatalf("expected 2 remaining backup codes, got %d", len(updatedRec.BackupCodes))
	}

	// Step 3: same backup code should fail now — need a fresh mfa_token
	req3 := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	req3.RemoteAddr = "127.0.0.1:12345"
	rec3 := httptest.NewRecorder()
	oAdmin.loginHandler(rec3, req3)

	var step3 map[string]interface{}
	if err := json.Unmarshal(rec3.Body.Bytes(), &step3); err != nil {
		t.Fatalf("step3 unmarshal: %v", err)
	}
	mfaToken2 := step3["mfa_token"].(string)

	mfaBody2 := `{"mfa_token":"` + mfaToken2 + `","code":"` + plainCodes[0] + `"}`
	req4 := httptest.NewRequest(http.MethodPost, "/api/login/mfa", strings.NewReader(mfaBody2))
	req4.RemoteAddr = "127.0.0.1:12345"
	rec4 := httptest.NewRecorder()

	oAdmin.mfaLoginHandler(rec4, req4)

	if rec4.Code != http.StatusUnauthorized {
		t.Fatalf("consumed backup code: expected 401, got %d: %s", rec4.Code, rec4.Body.String())
	}
}

func TestMfaDisable(t *testing.T) {
	oAdmin, pass := newTestAdminWithMFA(t)
	cookie := sessionCookie("testadmin")

	// Enable MFA for testadmin
	key, err := generateTOTPKey("testadmin")
	if err != nil {
		t.Fatalf("generateTOTPKey: %v", err)
	}
	_, hashedBackup := generateBackupCodes(2)
	oAdmin.mfaStore.set("testadmin", mfaRecord{
		Secret:      key.Secret(),
		Enabled:     true,
		BackupCodes: hashedBackup,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	})

	// Step 1: DELETE /api/mfa with valid TOTP code + password re-auth
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	disableBody := `{"password":"` + pass + `","code":"` + code + `"}`
	req := httptest.NewRequest(http.MethodDelete, "/api/mfa", strings.NewReader(disableBody))
	req.AddCookie(cookie)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	oAdmin.mfaDisableHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("disable: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var disableResp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &disableResp); err != nil {
		t.Fatalf("disable unmarshal: %v", err)
	}
	if disableResp["ok"] != true {
		t.Errorf("expected ok:true, got %v", disableResp["ok"])
	}

	// Step 2: GET /api/mfa/status → enabled: false
	req2 := httptest.NewRequest(http.MethodGet, "/api/mfa/status", nil)
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()

	oAdmin.mfaStatusHandler(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}

	var statusResp map[string]interface{}
	if err := json.Unmarshal(rec2.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("status unmarshal: %v", err)
	}
	if statusResp["enabled"] != false {
		t.Errorf("expected enabled:false, got %v", statusResp["enabled"])
	}
}

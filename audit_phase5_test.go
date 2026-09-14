package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// --- F44: server-config endpoint returns 503 (not a panic) when disabled ---
func TestAuditServerConfigDisabledNoPanic(t *testing.T) {
	app := &OvpnAdmin{} // serverConfigStore / serverManager are nil (module off)
	req := httptest.NewRequest(http.MethodGet, "/api/server-config", nil)
	rec := httptest.NewRecorder()
	app.serverConfigHandler(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("F44: disabled server-config must return 503, got %d", rec.Code)
	}
}

// --- F45: a malformed CCD apply body is rejected with 400, changes nothing ---
func TestAuditMalformedCCDRejected(t *testing.T) {
	app := &OvpnAdmin{}
	// CustomRoutes is the wrong JSON type → decode error.
	body := `{"User":"alice","ClientAddress":"dynamic","CustomRoutes":"not-an-array"}`
	req := httptest.NewRequest(http.MethodPost, "/api/user/ccd/apply", strings.NewReader(body))
	rec := httptest.NewRecorder()
	app.userApplyCcdHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F45: malformed CCD body must return 400, got %d", rec.Code)
	}
}

// --- F46: mfa/status reports can_manage_tokens per the server policy ---
func TestAuditMfaStatusReportsTokenCapability(t *testing.T) {
	app, _ := newTestAdminWithMFA(t)

	prev := mfaRequired
	no := false
	mfaRequired = &no // MFA optional → token management allowed even without enrollment
	t.Cleanup(func() { mfaRequired = prev })

	req := httptest.NewRequest(http.MethodGet, "/api/mfa/status", nil)
	rec := httptest.NewRecorder()
	app.mfaStatusHandler(rec, req)
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["can_manage_tokens"] != true {
		t.Fatalf("F46: can_manage_tokens must be true when MFA is optional, got %v", resp)
	}
	if resp["required"] != false {
		t.Fatalf("F46: required must be false, got %v", resp)
	}
}

// --- F47: a wrong MFA code must not burn the challenge; a correct retry works ---
func TestAuditMfaTypoDoesNotBurnChallenge(t *testing.T) {
	app, _ := newTestAdminWithMFA(t)
	key, err := generateTOTPKey("testadmin")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.mfaStore.set("testadmin", mfaRecord{Secret: key.Secret(), Enabled: true}); err != nil {
		t.Fatal(err)
	}

	token := signMfaToken("testadmin")

	// Wrong code first — must be 401 but MUST NOT consume the token.
	wrong := `{"mfa_token":"` + token + `","code":"000000"}`
	rw := httptest.NewRequest(http.MethodPost, "/api/login/mfa", strings.NewReader(wrong))
	rw.RemoteAddr = "127.0.0.1:5555"
	recW := httptest.NewRecorder()
	app.mfaLoginHandler(recW, rw)
	if recW.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code should be 401, got %d", recW.Code)
	}

	// Correct code with the SAME token — must now succeed (F47).
	code, _ := totp.GenerateCode(key.Secret(), time.Now())
	good := `{"mfa_token":"` + token + `","code":"` + code + `"}`
	rg := httptest.NewRequest(http.MethodPost, "/api/login/mfa", strings.NewReader(good))
	rg.RemoteAddr = "127.0.0.1:5555"
	recG := httptest.NewRecorder()
	app.mfaLoginHandler(recG, rg)
	if recG.Code != http.StatusOK {
		t.Fatalf("F47: correct retry with the same challenge must succeed, got %d: %s", recG.Code, recG.Body.String())
	}
}

// --- F23: confirming MFA issues a fresh session cookie (backup codes survive) ---
func TestAuditMfaConfirmIssuesFreshSession(t *testing.T) {
	app, _ := newTestAdminWithMFA(t)
	key, err := generateTOTPKey("testadmin")
	if err != nil {
		t.Fatal(err)
	}
	// Setup started (secret present, not yet enabled).
	if err := app.mfaStore.set("testadmin", mfaRecord{Secret: key.Secret(), Enabled: false}); err != nil {
		t.Fatal(err)
	}
	seedTestAdmin(t, "testadmin")

	code, _ := totp.GenerateCode(key.Secret(), time.Now())
	body := `{"code":"` + code + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/mfa/confirm", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signSession("testadmin", false)})
	rec := httptest.NewRecorder()
	app.mfaConfirmHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("confirm: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	// Response must carry the one-time backup codes...
	var resp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if _, ok := resp["backup_codes"]; !ok {
		t.Fatal("confirm response must include backup_codes")
	}
	// ...and a FRESH, valid session cookie (audit F23) so the UI stays logged in.
	var fresh string
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			fresh = c.Value
		}
	}
	if fresh == "" {
		t.Fatal("F23: confirm must set a fresh session cookie")
	}
	if _, ok := verifySession(fresh); !ok {
		t.Fatal("F23: the fresh session cookie must verify after the epoch bump")
	}
}

package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// ensureSigningKey is defined in force_password_change_test.go and seeds a
// deterministic sessionSigningKey so the HMAC helpers work in isolation.

// TestMfaTokenIsNotASession locks the fix for the MFA-bypass: an intermediate
// MFA token (minted after only the first factor) must NEVER validate as a
// session cookie. Before the fix, the purpose discriminator was serialized
// under a different JSON key for each token type, so an MFA token parsed as
// Purpose=="" in verifySession and the empty-allowed clause let it through —
// defeating MFA for anyone who knew the password.
func TestMfaTokenIsNotASession(t *testing.T) {
	ensureSigningKey()

	mfa := signMfaToken("admin")
	if _, ok := verifySession(mfa); ok {
		t.Fatal("SECURITY: an MFA token must not be accepted as a session cookie")
	}

	// A real session must still work, and must NOT be usable as an MFA token.
	sess := signSession("admin", true)
	if u, ok := verifySession(sess); !ok || u != "admin" {
		t.Fatalf("a genuine session must verify: ok=%v user=%q", ok, u)
	}
	if _, _, _, ok := verifyMfaToken(sess); ok {
		t.Fatal("SECURITY: a session token must not be accepted as an MFA token")
	}

	// The MFA token must still verify through its own path (domain-separated key).
	if u, _, _, ok := verifyMfaToken(mfa); !ok || u != "admin" {
		t.Fatalf("MFA token must verify via verifyMfaToken: ok=%v user=%q", ok, u)
	}
}

// TestEmptyPurposeRejected guards the strict purpose check: a token whose
// payload carries no purpose at all must be rejected (closes the legacy
// empty-allowed loophole the MFA token slipped through).
func TestEmptyPurposeRejected(t *testing.T) {
	ensureSigningKey()
	secret := sessionSecret()
	// hand-craft an enc payload with no "p" field
	raw := []byte(`{"u":"admin","exp":9999999999}`)
	enc := base64.RawURLEncoding.EncodeToString(raw)
	token := enc + "." + computeHMAC(enc, secret)
	if _, ok := verifySession(token); ok {
		t.Fatal("a token with no purpose must not be accepted as a session")
	}
}

// TestRevokeToken_PersistFailure locks in that a logout whose blacklist write
// fails is reported as a 5xx, not a lying 200 — otherwise the revoked session
// would revalidate after a restart (the durable blacklist never got the entry).
func TestRevokeToken_PersistFailure(t *testing.T) {
	ensureSigningKey()

	// Point the blacklist file at a path whose parent is a regular file so the
	// atomic write fails deterministically (ENOTDIR).
	f := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := revokedTokensFile
	revokedTokensFile = filepath.Join(f, "blacklist.json")
	t.Cleanup(func() { revokedTokensFile = prev })

	token := signSession("admin", true)
	if err := revokeToken(token); err == nil {
		t.Fatal("revokeToken must return an error when the blacklist can't be persisted")
	}

	// The direct call above added the token to the in-memory blacklist (only the
	// disk persist failed). verifySessionPayload rejects an already-blacklisted
	// token, so re-revoking the same token via logout would be a no-op (nil).
	// Reset the blacklist so the logout path genuinely re-attempts persistence.
	revokedTokensMu.Lock()
	revokedTokens = map[string]int64{}
	revokedTokensMu.Unlock()

	// The logout handler must surface that as a 500 while still clearing the cookie.
	app := &OvpnAdmin{}
	req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	app.logoutHandler(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("logout with a failed revocation persist must return 500, got %d", rec.Code)
	}
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout must still clear the session cookie even on persist failure")
	}
}

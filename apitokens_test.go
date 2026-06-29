package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPITokenCreateVerifyRevoke(t *testing.T) {
	s := newAPITokenStore(filepath.Join(t.TempDir(), "tokens.json"))

	plaintext, tok, err := s.create("teleport", "admin")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.HasPrefix(plaintext, tokenScheme) {
		t.Fatalf("token must carry scheme prefix, got %q", plaintext)
	}

	// correct token verifies
	if got, ok := s.verify(plaintext); !ok || got.ID != tok.ID {
		t.Fatal("valid token must verify to the same id")
	}
	// wrong token rejected
	if _, ok := s.verify(tokenScheme + "nope"); ok {
		t.Fatal("bogus token must not verify")
	}
	// missing scheme rejected
	if _, ok := s.verify("randomstring"); ok {
		t.Fatal("token without scheme must not verify")
	}
	// list never leaks the hash
	for _, l := range s.list() {
		if l.Hash != "" {
			t.Fatal("list() must not expose the hash")
		}
	}
	// empty name rejected
	if _, _, err := s.create("  ", "admin"); err == nil {
		t.Fatal("empty token name must be rejected")
	}

	// revoke kills it
	if !s.revoke(tok.ID) {
		t.Fatal("revoke should report success")
	}
	if _, ok := s.verify(plaintext); ok {
		t.Fatal("revoked token must no longer verify")
	}
}

func TestAPITokenPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	s := newAPITokenStore(path)
	plaintext, _, _ := s.create("svc", "admin")

	// fresh store loaded from disk still verifies
	s2 := newAPITokenStore(path)
	if _, ok := s2.verify(plaintext); !ok {
		t.Fatal("token must survive a reload")
	}
}

func TestAPITokenScope(t *testing.T) {
	allowed := []string{
		"/api/users/list", "/api/user/create", "/api/user/ccd/apply",
		"/api/common-routes", "/api/common-routes/abc", "/api/traffic",
	}
	for _, p := range allowed {
		if !apiTokenPathAllowed(p) {
			t.Errorf("%q must be allowed for a token", p)
		}
	}
	denied := []string{
		"/api/server-config", "/api/mfa/setup", "/api/admin/change-password",
		"/api/api-tokens", "/api/server/settings", "/metrics",
	}
	for _, p := range denied {
		if apiTokenPathAllowed(p) {
			t.Errorf("%q must be denied for a token", p)
		}
	}
}

func TestBearerTokenExtraction(t *testing.T) {
	mk := func(set func(*http.Request)) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/users/list", nil)
		set(r)
		return r
	}
	if got := bearerToken(mk(func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc123") })); got != "abc123" {
		t.Errorf("Bearer header: got %q", got)
	}
	if got := bearerToken(mk(func(r *http.Request) { r.Header.Set("X-API-Token", "xyz") })); got != "xyz" {
		t.Errorf("X-API-Token header: got %q", got)
	}
	if got := bearerToken(mk(func(r *http.Request) {})); got != "" {
		t.Errorf("no header should yield empty, got %q", got)
	}
}

// TestServiceAccountBypassesMfa locks the contract that a token request is
// treated as MFA-satisfied (a service can't do TOTP).
func TestServiceAccountBypassesMfa(t *testing.T) {
	app := &OvpnAdmin{}
	app.mfaStore = newMfaStore(filepath.Join(t.TempDir(), "mfa.json"))
	prev := mfaRequired
	on := true
	mfaRequired = &on
	defer func() { mfaRequired = prev }()

	// plain request (no service account) without enrolled MFA → not satisfied
	plain := httptest.NewRequest(http.MethodPost, "/api/user/create", nil)
	if app.adminHasMfa(plain) {
		t.Fatal("non-service request without MFA must not pass")
	}
	// same, but marked as a service account → passes
	svc := withServiceAccount(plain, "teleport")
	if !app.adminHasMfa(svc) {
		t.Fatal("service-account request must bypass the MFA gate")
	}
}

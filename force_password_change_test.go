package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func ensureSigningKey() {
	if sessionSigningKey == nil {
		sessionSigningKey = make([]byte, 64)
	}
}

// withMustChange sets the forced-password-change flag for the duration of a
// test and restores it afterwards (it's package-global state).
func withMustChange(t *testing.T, v bool) {
	t.Helper()
	prev := adminPasswordMustChange
	adminPasswordMustChange = v
	t.Cleanup(func() { adminPasswordMustChange = prev })
}

func TestPasswordChangeAllowed(t *testing.T) {
	allowed := []string{
		"/api/admin/change-password",
		"/ovpn/api/auth/check",
		"/api/server/settings",
		"/api/logout",
	}
	for _, p := range allowed {
		if !passwordChangeAllowed(p) {
			t.Errorf("expected %q to be allowed during forced change", p)
		}
	}
	blocked := []string{"/api/users/list", "/api/user/create", "/metrics", "/api/server-config"}
	for _, p := range blocked {
		if passwordChangeAllowed(p) {
			t.Errorf("expected %q to be blocked during forced change", p)
		}
	}
}

func TestValidateAdminPassword(t *testing.T) {
	if err := validateAdminPassword("short"); err == nil {
		t.Error("expected error for too-short password")
	}
	if err := validateAdminPassword("exactlytwelve"); err != nil {
		t.Errorf("expected 13-char password to pass, got %v", err)
	}
}

// TestRequireAuth_ForcedChange_BlocksNonAllowlisted — with a valid session but
// must-change set, a normal endpoint is held with 412 and next is not called.
func TestRequireAuth_ForcedChange_BlocksNonAllowlisted(t *testing.T) {
	ensureSigningKey()
	withMustChange(t, true)
	app := &OvpnAdmin{}

	called := false
	handler := app.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users/list", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signSession("admin")})
	rec := httptest.NewRecorder()
	handler(rec, req)

	if called {
		t.Fatal("next must not be invoked while forced change is active")
	}
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "password change required") {
		t.Errorf("unexpected body: %s", rec.Body.String())
	}
}

// TestRequireAuth_ForcedChange_AllowsChangeEndpoint — the change-password
// endpoint itself stays reachable so the admin can escape the gate.
func TestRequireAuth_ForcedChange_AllowsChangeEndpoint(t *testing.T) {
	ensureSigningKey()
	withMustChange(t, true)
	app := &OvpnAdmin{}

	called := false
	handler := app.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/change-password", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signSession("admin")})
	rec := httptest.NewRecorder()
	handler(rec, req)

	if !called {
		t.Fatal("change-password endpoint must be reachable during forced change")
	}
}

// TestAdminChangePassword_RotatesAndClearsGate — valid change updates the
// stored hash, clears must-change, and rejects the old password afterwards.
func TestAdminChangePassword_RotatesAndClearsGate(t *testing.T) {
	ensureSigningKey()
	withMustChange(t, true)

	const oldPass = "temp-password-xyz"
	const newPass = "BrandNewStrongPass123"

	hash, _ := bcrypt.GenerateFromPassword([]byte(oldPass), bcrypt.MinCost)
	prevUsers := htpasswdUsers
	htpasswdUsers = map[string]string{"admin": string(hash)}
	t.Cleanup(func() { htpasswdUsers = prevUsers })

	prevPath := adminHtpasswdPersistPath
	adminHtpasswdPersistPath = filepath.Join(t.TempDir(), "admin.htpasswd")
	t.Cleanup(func() { adminHtpasswdPersistPath = prevPath })

	app := &OvpnAdmin{}

	// wrong current password → 401, gate stays.
	req := httptest.NewRequest(http.MethodPost, "/api/admin/change-password",
		strings.NewReader(`{"current_password":"nope","new_password":"`+newPass+`"}`))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signSession("admin")})
	rec := httptest.NewRecorder()
	app.adminChangePasswordHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current: expected 401, got %d", rec.Code)
	}
	if !adminPasswordChangeRequired() {
		t.Fatal("gate must remain after a failed change")
	}

	// valid change → 200, gate cleared, old password no longer valid.
	req = httptest.NewRequest(http.MethodPost, "/api/admin/change-password",
		strings.NewReader(`{"current_password":"`+oldPass+`","new_password":"`+newPass+`"}`))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signSession("admin")})
	rec = httptest.NewRecorder()
	app.adminChangePasswordHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid change: expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if adminPasswordChangeRequired() {
		t.Fatal("gate must be cleared after a successful change")
	}
	if validateCredentials("admin", oldPass) {
		t.Error("old password must be rejected after change")
	}
	if !validateCredentials("admin", newPass) {
		t.Error("new password must be accepted after change")
	}
}

package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestAdminHasMfa_NoMfaStore — когда MFA выключена сервером (--mfa=false),
// adminHasMfa должен вернуть true (= "allow"), иначе сломаем dev-окружения,
// где 2FA отключена целиком.
func TestAdminHasMfa_NoMfaStore(t *testing.T) {
	app := &OvpnAdmin{role: "master"} // mfaStore = nil
	req := httptest.NewRequest(http.MethodPost, "/api/user/create", nil)
	if !app.adminHasMfa(req) {
		t.Fatal("expected true when mfaStore is nil (dev / --mfa=false)")
	}
}

// TestAdminHasMfa_OptOutFlag — когда --mfa.required=false, гейт не действует
// даже если у admin'а MFA не включена.
func TestAdminHasMfa_OptOutFlag(t *testing.T) {
	app := &OvpnAdmin{role: "master"}
	app.mfaStore = newMfaStore(filepath.Join(t.TempDir(), "mfa.json"))

	prev := mfaRequired
	off := false
	mfaRequired = &off
	defer func() { mfaRequired = prev }()

	req := httptest.NewRequest(http.MethodPost, "/api/user/create", nil)
	if !app.adminHasMfa(req) {
		t.Fatal("expected true when --mfa.required=false")
	}
}

// TestAdminHasMfa_NoSession — без cookie возвращаем false (запрещено).
func TestAdminHasMfa_NoSession(t *testing.T) {
	app := &OvpnAdmin{role: "master"}
	app.mfaStore = newMfaStore(filepath.Join(t.TempDir(), "mfa.json"))

	prev := mfaRequired
	on := true
	mfaRequired = &on
	defer func() { mfaRequired = prev }()

	req := httptest.NewRequest(http.MethodPost, "/api/user/create", nil)
	if app.adminHasMfa(req) {
		t.Fatal("expected false when no session cookie present")
	}
}

// TestAdminHasMfa_SessionWithoutMfa — есть валидная сессия, но MFA для юзера
// не включена → false.
func TestAdminHasMfa_SessionWithoutMfa(t *testing.T) {
	app := &OvpnAdmin{role: "master"}
	app.mfaStore = newMfaStore(filepath.Join(t.TempDir(), "mfa.json"))

	prev := mfaRequired
	on := true
	mfaRequired = &on
	defer func() { mfaRequired = prev }()

	token := signSession("testuser")
	req := httptest.NewRequest(http.MethodPost, "/api/user/create", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})

	if app.adminHasMfa(req) {
		t.Fatal("expected false when user has no MFA enabled")
	}
}

// TestAdminHasMfa_SessionWithMfa — валидная сессия + MFA enabled = true.
func TestAdminHasMfa_SessionWithMfa(t *testing.T) {
	app := &OvpnAdmin{role: "master"}
	app.mfaStore = newMfaStore(filepath.Join(t.TempDir(), "mfa.json"))
	app.mfaStore.set("testuser", mfaRecord{
		Secret:  "JBSWY3DPEHPK3PXP",
		Enabled: true,
	})

	prev := mfaRequired
	on := true
	mfaRequired = &on
	defer func() { mfaRequired = prev }()

	token := signSession("testuser")
	req := httptest.NewRequest(http.MethodPost, "/api/user/create", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})

	if !app.adminHasMfa(req) {
		t.Fatal("expected true when user has MFA enabled")
	}
}

// TestRequireAdminMfa_Blocks412 — middleware возвращает 412, если у юзера
// нет MFA, и не вызывает next.
func TestRequireAdminMfa_Blocks412(t *testing.T) {
	app := &OvpnAdmin{role: "master"}
	app.mfaStore = newMfaStore(filepath.Join(t.TempDir(), "mfa.json"))

	prev := mfaRequired
	on := true
	mfaRequired = &on
	defer func() { mfaRequired = prev }()

	called := false
	handler := app.requireAdminMfa(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/user/create", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if called {
		t.Fatal("next handler must NOT be invoked when MFA gate fails")
	}
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "MFA") {
		t.Errorf("expected error message about MFA, got %s", rec.Body.String())
	}
}

// TestRequireAdminMfa_PassesThroughWhenEnabled — middleware вызывает next,
// если MFA включена.
func TestRequireAdminMfa_PassesThroughWhenEnabled(t *testing.T) {
	app := &OvpnAdmin{role: "master"}
	app.mfaStore = newMfaStore(filepath.Join(t.TempDir(), "mfa.json"))
	app.mfaStore.set("testuser", mfaRecord{
		Secret:  "JBSWY3DPEHPK3PXP",
		Enabled: true,
	})

	prev := mfaRequired
	on := true
	mfaRequired = &on
	defer func() { mfaRequired = prev }()

	token := signSession("testuser")
	called := false
	handler := app.requireAdminMfa(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/user/create", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	handler(rec, req)

	if !called {
		t.Fatal("next handler must be invoked when MFA is enabled")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// TestRequireAdminMfa_PassesThroughWhenNoStore — middleware пропускает
// запрос, если mfaStore=nil (dev / --mfa=false).
func TestRequireAdminMfa_PassesThroughWhenNoStore(t *testing.T) {
	app := &OvpnAdmin{role: "master"} // mfaStore = nil

	called := false
	handler := app.requireAdminMfa(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/user/create", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if !called {
		t.Fatal("next handler must be invoked when mfaStore is nil")
	}
}

// TestServerSettings_ExposesMfaFields — endpoint должен возвращать
// adminMfaEnabled / adminMfaRequired для фронта.
func TestServerSettings_ExposesMfaFields(t *testing.T) {
	app := &OvpnAdmin{role: "master", modules: []string{}}
	app.mfaStore = newMfaStore(filepath.Join(t.TempDir(), "mfa.json"))

	prev := mfaRequired
	on := true
	mfaRequired = &on
	defer func() { mfaRequired = prev }()

	req := httptest.NewRequest(http.MethodGet, "/api/server/settings", nil)
	rec := httptest.NewRecorder()
	app.serverSettingsHandler(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `"adminMfaRequired":true`) {
		t.Errorf("expected adminMfaRequired=true, got %s", body)
	}
	if !strings.Contains(body, `"adminMfaEnabled":false`) {
		t.Errorf("expected adminMfaEnabled=false (no session, no MFA), got %s", body)
	}
}

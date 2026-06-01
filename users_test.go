package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUserCreate_BlockedWhenServerNotInitialized — гейт "сервер не настроен":
// если serverConfigStore присутствует и Initialized=false, /api/user/create
// должен вернуть 412 без попытки вызвать easyrsa.
func TestUserCreate_BlockedWhenServerNotInitialized(t *testing.T) {
	t.Parallel()
	app := &OvpnAdmin{role: "master"}
	app.serverConfigStore = newServerConfigStore()
	// store по умолчанию Initialized=false

	body := []byte(`{"username":"alice","password":"hunter22"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/user/create", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.userCreateHandler(rec, req)

	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not initialized") {
		t.Errorf("expected message about not initialized, got %s", rec.Body.String())
	}
}

// TestUserRotate_BlockedWhenServerNotInitialized — тот же гейт на ротации.
func TestUserRotate_BlockedWhenServerNotInitialized(t *testing.T) {
	t.Parallel()
	app := &OvpnAdmin{role: "master"}
	app.serverConfigStore = newServerConfigStore()

	body := []byte(`{"username":"alice","password":"hunter22"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/user/rotate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.userRotateHandler(rec, req)

	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestUserCreate_GateSkippedWhenServerConfigStoreNil — если модуль server-config
// выключен (store == nil), гейт не применяется — обработчик идёт дальше и доходит
// до парсинга body / userCreate(). Мы прерываем на этапе валидации тела —
// главное, что не получили 412.
func TestUserCreate_GateSkippedWhenServerConfigStoreNil(t *testing.T) {
	t.Parallel()
	app := &OvpnAdmin{role: "master"}
	// serverConfigStore намеренно nil

	req := httptest.NewRequest(http.MethodPost, "/api/user/create", bytes.NewReader([]byte(`not json`)))
	rec := httptest.NewRecorder()
	app.userCreateHandler(rec, req)

	if rec.Code == http.StatusPreconditionFailed {
		t.Errorf("must NOT return 412 when serverConfigStore is nil, got body=%s", rec.Body.String())
	}
}

// TestUserCreate_SlaveCheckBeforeGate — порядок проверок: slave-роль должна
// проверяться раньше гейта, чтобы slave-нода не сбивала пользователя
// сообщением про "не настроено" вместо "read-only".
//
// After the middleware extraction the slave check lives in requireMaster,
// not the handler. We exercise the exact route stack (requireMaster wrapping
// the handler) so the test still pins the contract end-to-end.
func TestUserCreate_SlaveCheckBeforeGate(t *testing.T) {
	t.Parallel()
	app := &OvpnAdmin{role: "slave"}
	app.serverConfigStore = newServerConfigStore() // Initialized=false

	body := []byte(`{"username":"alice","password":"hunter22"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/user/create", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.requireMaster(app.userCreateHandler)(rec, req)

	if rec.Code != http.StatusLocked {
		t.Errorf("expected 423 (slave locked) before gate, got %d", rec.Code)
	}
}

// TestServerSettingsHandler_ExposesServerInitialized — endpoint /api/server/settings
// должен возвращать поле serverInitialized для фронта.
func TestServerSettingsHandler_ExposesServerInitialized(t *testing.T) {
	t.Parallel()
	app := &OvpnAdmin{role: "master", modules: []string{"server-config"}}
	app.serverConfigStore = newServerConfigStore()

	req := httptest.NewRequest(http.MethodGet, "/api/server/settings", nil)
	rec := httptest.NewRecorder()
	app.serverSettingsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"serverInitialized":false`) {
		t.Errorf("expected serverInitialized=false in response, got %s", body)
	}

	// После пометки Initialized=true — должно быть true.
	cfg := app.serverConfigStore.snapshot()
	cfg.Initialized = true
	app.serverConfigStore.replace(cfg)

	rec2 := httptest.NewRecorder()
	app.serverSettingsHandler(rec2, req)
	if !strings.Contains(rec2.Body.String(), `"serverInitialized":true`) {
		t.Errorf("expected serverInitialized=true after replace, got %s", rec2.Body.String())
	}
}

// TestServerSettingsHandler_NilStoreMeansInitialized — если модуль server-config
// не подключен (store==nil), гейт не действует и serverInitialized=true.
func TestServerSettingsHandler_NilStoreMeansInitialized(t *testing.T) {
	t.Parallel()
	app := &OvpnAdmin{role: "master", modules: []string{}}
	// serverConfigStore намеренно nil

	req := httptest.NewRequest(http.MethodGet, "/api/server/settings", nil)
	rec := httptest.NewRecorder()
	app.serverSettingsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"serverInitialized":true`) {
		t.Errorf("expected serverInitialized=true when store is nil, got %s", rec.Body.String())
	}
}

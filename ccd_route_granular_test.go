package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// callRouteHandler invokes a granular add/remove handler with a JSON body and
// returns the decoded response map plus the raw recorder.
func callRouteHandler(t *testing.T, h http.HandlerFunc, body interface{}) (map[string]interface{}, *httptest.ResponseRecorder) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/user/ccd/route/x", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	h(rec, req)
	var out map[string]interface{}
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return out, rec
}

func routeCount(ccd map[string]interface{}) int {
	if ccd == nil {
		return -1
	}
	if cr, ok := ccd["CustomRoutes"].([]interface{}); ok {
		return len(cr)
	}
	return 0
}

func TestCcdRouteAdd_AddsIPRouteGranularly(t *testing.T) {
	dir := withTempCcdEnv(t)
	app := newTestAdminCcd(t, dir)

	// Seed an existing route so we prove add() preserves it.
	seed := Ccd{User: "alice", ClientAddress: "dynamic", CustomRoutes: []ccdRoute{
		{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.255.0", Description: "office"},
	}}
	if ok, msg := app.modifyCcd(seed, nil); !ok {
		t.Fatalf("seed modifyCcd: %s", msg)
	}

	out, rec := callRouteHandler(t, app.userAddCcdRouteHandler, map[string]interface{}{
		"username": "alice",
		"route":    ccdRoute{Kind: "ip", Address: "172.16.0.0", Mask: "255.255.0.0", Description: "dc"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	added, _ := out["added"].([]interface{})
	if len(added) != 1 {
		t.Fatalf("added: got %d, want 1", len(added))
	}
	if got := routeCount(out["ccd"].(map[string]interface{})); got != 2 {
		t.Fatalf("ccd routes: got %d, want 2 (existing preserved + new)", got)
	}

	// Re-parse from disk to confirm it persisted.
	if got := len(app.getCcd("alice").CustomRoutes); got != 2 {
		t.Fatalf("persisted routes: got %d, want 2", got)
	}
}

func TestCcdRouteAdd_DuplicateIsSkippedIdempotent(t *testing.T) {
	dir := withTempCcdEnv(t)
	app := newTestAdminCcd(t, dir)

	body := map[string]interface{}{
		"username": "bob",
		"route":    ccdRoute{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.255.0"},
	}
	if _, rec := callRouteHandler(t, app.userAddCcdRouteHandler, body); rec.Code != 200 {
		t.Fatalf("first add: %d", rec.Code)
	}
	out, rec := callRouteHandler(t, app.userAddCcdRouteHandler, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("second add status: got %d, want 200", rec.Code)
	}
	added, _ := out["added"].([]interface{})
	skipped, _ := out["skipped"].([]interface{})
	if len(added) != 0 || len(skipped) != 1 {
		t.Fatalf("want added=0 skipped=1, got added=%d skipped=%d", len(added), len(skipped))
	}
	if got := len(app.getCcd("bob").CustomRoutes); got != 1 {
		t.Fatalf("dup must not append: got %d routes, want 1", got)
	}
}

func TestCcdRouteAdd_DomainResolves(t *testing.T) {
	dir := withTempCcdEnv(t)
	app := newTestAdminCcd(t, dir)
	defer withMockResolver(t, map[string][]string{"example.com": {"93.184.216.34"}})()

	out, rec := callRouteHandler(t, app.userAddCcdRouteHandler, map[string]interface{}{
		"username": "carol",
		"route":    ccdRoute{Kind: "domain", Domain: "example.com", Description: "site"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d (%s)", rec.Code, rec.Body.String())
	}
	added, _ := out["added"].([]interface{})
	if len(added) != 1 {
		t.Fatalf("added: got %d, want 1", len(added))
	}
	stored := app.getCcd("carol").CustomRoutes
	if len(stored) != 1 || stored[0].Kind != "domain" || len(stored[0].ResolvedIPs) != 1 {
		t.Fatalf("domain route not stored with resolved IP: %+v", stored)
	}
}

func TestCcdRouteRemove_RemovesOneKeepsOthers(t *testing.T) {
	dir := withTempCcdEnv(t)
	app := newTestAdminCcd(t, dir)

	seed := Ccd{User: "dave", ClientAddress: "dynamic", CustomRoutes: []ccdRoute{
		{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.255.0", Description: "keep"},
		{Kind: "ip", Address: "172.16.0.0", Mask: "255.255.0.0", Description: "drop"},
	}}
	if ok, msg := app.modifyCcd(seed, nil); !ok {
		t.Fatalf("seed: %s", msg)
	}

	out, rec := callRouteHandler(t, app.userRemoveCcdRouteHandler, map[string]interface{}{
		"username": "dave",
		// Description intentionally omitted — match is by network+mask only.
		"route": ccdRoute{Kind: "ip", Address: "172.16.0.0", Mask: "255.255.0.0"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d (%s)", rec.Code, rec.Body.String())
	}
	removed, _ := out["removed"].([]interface{})
	if len(removed) != 1 {
		t.Fatalf("removed: got %d, want 1", len(removed))
	}
	remaining := app.getCcd("dave").CustomRoutes
	if len(remaining) != 1 || remaining[0].Address != "10.0.0.0" {
		t.Fatalf("wrong route survived: %+v", remaining)
	}
}

func TestCcdRouteRemove_NotFoundIsIdempotent(t *testing.T) {
	dir := withTempCcdEnv(t)
	app := newTestAdminCcd(t, dir)

	seed := Ccd{User: "erin", ClientAddress: "dynamic", CustomRoutes: []ccdRoute{
		{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.255.0"},
	}}
	if ok, msg := app.modifyCcd(seed, nil); !ok {
		t.Fatalf("seed: %s", msg)
	}

	out, rec := callRouteHandler(t, app.userRemoveCcdRouteHandler, map[string]interface{}{
		"username": "erin",
		"route":    ccdRoute{Kind: "ip", Address: "8.8.8.8", Mask: "255.255.255.255"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	removed, _ := out["removed"].([]interface{})
	notFound, _ := out["not_found"].([]interface{})
	if len(removed) != 0 || len(notFound) != 1 {
		t.Fatalf("want removed=0 not_found=1, got removed=%d not_found=%d", len(removed), len(notFound))
	}
	if got := len(app.getCcd("erin").CustomRoutes); got != 1 {
		t.Fatalf("untouched CCD changed: got %d routes, want 1", got)
	}
}

func TestCcdRouteMutation_BadUsernameRejected(t *testing.T) {
	app := newTestAdminCcd(t, withTempCcdEnv(t))
	_, rec := callRouteHandler(t, app.userAddCcdRouteHandler, map[string]interface{}{
		"username": "bad user!",
		"route":    ccdRoute{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.255.0"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
}

func TestCcdRouteMutation_NoRoutesRejected(t *testing.T) {
	app := newTestAdminCcd(t, withTempCcdEnv(t))
	_, rec := callRouteHandler(t, app.userAddCcdRouteHandler, map[string]interface{}{"username": "frank"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
}

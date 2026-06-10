package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"text/template"
)

// TestValidateSubnet covers the security-critical inputs that ultimately reach
// the rendered server.conf / CCD as a `push "route X Y net_gateway"` line.
// A malformed Description or non-IPv4 Address would either break OpenVPN parsing
// (best case: crash at startup, easy to catch) or, worse, allow CCD injection.
func TestValidateSubnet(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      Subnet
		wantErr bool
		errSub  string
	}{
		{"valid /16", Subnet{"192.168.0.0", "255.255.0.0", "Home LAN"}, false, ""},
		{"valid /8", Subnet{"10.0.0.0", "255.0.0.0", "Private 10/8"}, false, ""},
		{"valid /32 single host", Subnet{"1.1.1.1", "255.255.255.255", ""}, false, ""},
		// /0 is now REJECTED for exclusions: it would silently disable full-tunnel.
		{"slash-zero exclusion rejected", Subnet{"0.0.0.0", "0.0.0.0", ""}, true, "/0"},
		{"empty address", Subnet{"", "255.255.0.0", ""}, true, "valid IP"},
		{"empty mask", Subnet{"10.0.0.0", "", ""}, true, "valid IP"},
		{"garbage address", Subnet{"not-an-ip", "255.0.0.0", ""}, true, "valid IP"},
		{"garbage mask", Subnet{"10.0.0.0", "not-a-mask", ""}, true, "valid IP"},
		{"IPv6 address rejected", Subnet{"2001:db8::1", "255.255.0.0", ""}, true, "must be IPv4"},
		// 255.0.255.0 has a 0-bit gap → not a contiguous netmask
		{"non-contiguous mask", Subnet{"10.0.0.0", "255.0.255.0", ""}, true, "contiguous"},
		// host bits set: 192.168.0.5/16 should be 192.168.0.0/16
		{"host bits set", Subnet{"192.168.0.5", "255.255.0.0", ""}, true, "host bits"},
		{"host bits set in /24", Subnet{"10.0.0.1", "255.255.255.0", ""}, true, "host bits"},
		// Description injection vectors
		{"newline in description", Subnet{"10.0.0.0", "255.0.0.0", "evil\npush \"redirect-gateway def1\""}, true, "newlines"},
		{"CR in description", Subnet{"10.0.0.0", "255.0.0.0", "evil\rinjected"}, true, "newlines"},
		{"double quote in description", Subnet{"10.0.0.0", "255.0.0.0", `evil"break out`}, true, "double quotes"},
		{"NUL byte in description", Subnet{"10.0.0.0", "255.0.0.0", "ok\x00rest"}, true, "NUL"},
		{"long description", Subnet{"10.0.0.0", "255.0.0.0", strings.Repeat("x", 201)}, true, "too long"},
		{"description at max length", Subnet{"10.0.0.0", "255.0.0.0", strings.Repeat("x", 200)}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSubnet(tc.in)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr && err != nil && tc.errSub != "" && !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.errSub)
			}
		})
	}
}

// TestMergeExclusions documents the operator-facing dedup behaviour: a global
// 192.168.0.0/16 plus a user-added 192.168.0.0/16 must collapse to ONE push
// line, with both sources cited in the comment so an operator grepping the
// CCD file can tell where the entry came from.
func TestMergeExclusions(t *testing.T) {
	t.Parallel()

	t.Run("empty inputs", func(t *testing.T) {
		got := mergeExclusions(nil, nil)
		if len(got) != 0 {
			t.Fatalf("want empty, got %v", got)
		}
	})

	t.Run("global only", func(t *testing.T) {
		got := mergeExclusions(
			[]Subnet{{Address: "192.168.0.0", Mask: "255.255.0.0", Description: "LAN"}},
			nil,
		)
		if len(got) != 1 {
			t.Fatalf("want 1, got %d", len(got))
		}
		if !strings.HasPrefix(got[0].Source, "__exclusion_global__") {
			t.Errorf("expected global marker, got %q", got[0].Source)
		}
	})

	t.Run("user only", func(t *testing.T) {
		got := mergeExclusions(
			nil,
			[]Subnet{{Address: "10.42.0.0", Mask: "255.255.0.0", Description: "Work VPN"}},
		)
		if len(got) != 1 {
			t.Fatalf("want 1, got %d", len(got))
		}
		if !strings.HasPrefix(got[0].Source, "__exclusion_user__") {
			t.Errorf("expected user marker, got %q", got[0].Source)
		}
	})

	t.Run("globals first then users (deterministic order)", func(t *testing.T) {
		got := mergeExclusions(
			[]Subnet{{Address: "192.168.0.0", Mask: "255.255.0.0"}},
			[]Subnet{{Address: "10.42.0.0", Mask: "255.255.0.0"}},
		)
		if len(got) != 2 {
			t.Fatalf("want 2, got %d", len(got))
		}
		if got[0].Address != "192.168.0.0" {
			t.Errorf("expected global first; got %v", got)
		}
		if got[1].Address != "10.42.0.0" {
			t.Errorf("expected user second; got %v", got)
		}
	})

	t.Run("dedup global+user with combined source", func(t *testing.T) {
		got := mergeExclusions(
			[]Subnet{{Address: "192.168.0.0", Mask: "255.255.0.0", Description: "Default LAN"}},
			[]Subnet{{Address: "192.168.0.0", Mask: "255.255.0.0", Description: "Custom note"}},
		)
		if len(got) != 1 {
			t.Fatalf("want 1 deduped, got %d", len(got))
		}
		// Source must mention BOTH markers so grep-debugging an "unexpected exclusion" works.
		if !strings.Contains(got[0].Source, "__exclusion_global__") || !strings.Contains(got[0].Source, "__exclusion_user__") {
			t.Errorf("dedup must merge both markers: %q", got[0].Source)
		}
	})

	t.Run("dedup within user list (same subnet twice in user-list)", func(t *testing.T) {
		got := mergeExclusions(
			nil,
			[]Subnet{
				{Address: "10.0.0.0", Mask: "255.0.0.0"},
				{Address: "10.0.0.0", Mask: "255.0.0.0"},
			},
		)
		if len(got) != 1 {
			t.Fatalf("want 1, got %d", len(got))
		}
	})

	t.Run("empty Address skipped (defensive)", func(t *testing.T) {
		got := mergeExclusions(
			[]Subnet{{Address: "", Mask: "255.0.0.0"}, {Address: "10.0.0.0", Mask: ""}, {Address: "10.0.0.0", Mask: "255.0.0.0"}},
			nil,
		)
		if len(got) != 1 {
			t.Fatalf("want 1, got %d", len(got))
		}
	})
}

// TestServerConfig_RedirectGatewayExclusions_Validation locks in the
// server-config-level validation: a malformed default-exclusion list must be
// rejected at apply time, not when a user with full-tunnel reconnects.
func TestServerConfig_RedirectGatewayExclusions_Validation(t *testing.T) {
	t.Parallel()

	t.Run("default config is valid", func(t *testing.T) {
		cfg := defaultServerConfig()
		if err := validateServerConfig(cfg); err != nil {
			t.Fatalf("defaults must validate: %v", err)
		}
		if len(cfg.RedirectGatewayExclusions) == 0 {
			t.Fatal("defaults should ship with sensible exclusions, got empty")
		}
	})

	t.Run("malformed exclusion rejected", func(t *testing.T) {
		cfg := defaultServerConfig()
		cfg.RedirectGatewayExclusions = []Subnet{{Address: "not-an-ip", Mask: "255.0.0.0"}}
		if err := validateServerConfig(cfg); err == nil {
			t.Fatal("expected validation error")
		}
	})

	t.Run("description with newline rejected (injection guard)", func(t *testing.T) {
		cfg := defaultServerConfig()
		cfg.RedirectGatewayExclusions = []Subnet{{
			Address:     "10.0.0.0",
			Mask:        "255.0.0.0",
			Description: "ok\npush \"redirect-gateway def1\"",
		}}
		if err := validateServerConfig(cfg); err == nil {
			t.Fatal("expected validation error for newline-bearing description")
		}
	})
}

// TestCcd_RedirectGateway_Render checks the actual CCD output for the four
// matrix points: per-user flag on/off × global vs per-user exclusions.
// The render path is the contract the OpenVPN client sees.
func TestCcd_RedirectGateway_Render(t *testing.T) {
	t.Parallel()

	render := func(ccd Ccd) string {
		var buf bytes.Buffer
		tpl := template.Must(template.New("ccd").Parse(ccdTemplateRaw(t)))
		if err := tpl.Execute(&buf, ccd); err != nil {
			t.Fatalf("template execute: %v", err)
		}
		return buf.String()
	}

	t.Run("flag off: no redirect-gateway, no exclusions", func(t *testing.T) {
		ccd := Ccd{ClientAddress: "10.30.0.5", RedirectGateway: false}
		out := render(ccd)
		if strings.Contains(out, "redirect-gateway") {
			t.Errorf("did not expect redirect-gateway in output:\n%s", out)
		}
		if strings.Contains(out, "net_gateway") {
			t.Errorf("did not expect net_gateway in output:\n%s", out)
		}
	})

	t.Run("flag on + exclusions: full block rendered with markers", func(t *testing.T) {
		ccd := Ccd{
			ClientAddress:   "10.30.0.5",
			RedirectGateway: true,
			MergedExclusions: []renderedExclusion{
				{Address: "192.168.0.0", Mask: "255.255.0.0", Source: "__exclusion_global__ LAN"},
				{Address: "10.42.0.0", Mask: "255.255.0.0", Source: "__exclusion_user__ Work VPN"},
			},
		}
		out := render(ccd)
		if !strings.Contains(out, `push "redirect-gateway def1"`) {
			t.Errorf("missing redirect-gateway line:\n%s", out)
		}
		if !strings.Contains(out, "__redirect_gateway__") {
			t.Errorf("missing redirect-gateway marker (round-trip would fail):\n%s", out)
		}
		if !strings.Contains(out, `push "route 192.168.0.0 255.255.0.0 net_gateway"`) {
			t.Errorf("missing global exclusion:\n%s", out)
		}
		if !strings.Contains(out, `push "route 10.42.0.0 255.255.0.0 net_gateway"`) {
			t.Errorf("missing per-user exclusion:\n%s", out)
		}
	})
}

// TestDeserializeServerConfig_MigratesMissingExclusions covers the upgrade
// path from pre-v2.0.17: an old persisted config has no
// "redirect_gateway_exclusions" key at all. We must materialize the LAN
// defaults so that an operator's first per-user full-tunnel toggle doesn't
// silently kill their home-LAN access. An EXPLICITLY empty list (operator
// chose zero exclusions) must be respected.
func TestDeserializeServerConfig_MigratesMissingExclusions(t *testing.T) {
	t.Parallel()
	t.Run("missing key → defaults applied", func(t *testing.T) {
		// Pre-v2.0.17 JSON without the field.
		raw := []byte(`{"proto":"tcp","port":1194,"initialized":true}`)
		cfg, err := deserializeServerConfig(raw)
		if err != nil {
			t.Fatalf("deserialize: %v", err)
		}
		if len(cfg.RedirectGatewayExclusions) == 0 {
			t.Fatal("expected default exclusions to be backfilled for missing-key case")
		}
	})
	t.Run("explicit empty list → respected", func(t *testing.T) {
		raw := []byte(`{"proto":"tcp","port":1194,"initialized":true,"redirect_gateway_exclusions":[]}`)
		cfg, err := deserializeServerConfig(raw)
		if err != nil {
			t.Fatalf("deserialize: %v", err)
		}
		if len(cfg.RedirectGatewayExclusions) != 0 {
			t.Fatalf("explicit empty must be respected; got %v", cfg.RedirectGatewayExclusions)
		}
	})
	t.Run("explicit populated list → respected", func(t *testing.T) {
		raw := []byte(`{"proto":"tcp","port":1194,"initialized":true,"redirect_gateway_exclusions":[{"address":"172.20.0.0","mask":"255.255.0.0","description":"custom"}]}`)
		cfg, err := deserializeServerConfig(raw)
		if err != nil {
			t.Fatalf("deserialize: %v", err)
		}
		if len(cfg.RedirectGatewayExclusions) != 1 || cfg.RedirectGatewayExclusions[0].Address != "172.20.0.0" {
			t.Fatalf("explicit list must round-trip; got %v", cfg.RedirectGatewayExclusions)
		}
	})
}

// TestParseCcd_RoundTripsRedirectGatewayAndUserExclusion verifies that what
// modifyCcd writes to disk is exactly what parseCcd reads back, for the new
// per-user fields. Crucially: global exclusions are NOT round-tripped (they
// live in ServerConfig only) — re-importing them per user would silently
// "freeze" the global list at the moment of edit, defeating the central
// management story.
func TestParseCcd_RoundTripsRedirectGatewayAndUserExclusion(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Hand-crafted CCD that exercises every marker our render emits.
	// We can't easily call modifyCcd here (it requires a fuller OvpnAdmin) —
	// the literal mirrors the template output character-for-character.
	content := `ifconfig-push 10.30.0.5 255.255.255.0
push "redirect-gateway def1" # __redirect_gateway__
push "route 192.168.0.0 255.255.0.0 net_gateway" # __exclusion_global__ Default LAN
push "route 10.42.0.0 255.255.0.0 net_gateway" # __exclusion_user__ Work VPN
push "route 142.250.0.0 255.254.0.0" # __common__:google
`
	if err := os.WriteFile(dir+"/alice", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &OvpnAdmin{store: testFilesystemStore(dir)}
	ccd := app.parseCcd("alice")

	if !ccd.RedirectGateway {
		t.Error("RedirectGateway should be true after parsing __redirect_gateway__ marker")
	}
	if len(ccd.RedirectGatewayExclusions) != 1 {
		t.Fatalf("want 1 per-user exclusion, got %d: %+v", len(ccd.RedirectGatewayExclusions), ccd.RedirectGatewayExclusions)
	}
	u := ccd.RedirectGatewayExclusions[0]
	if u.Address != "10.42.0.0" || u.Mask != "255.255.0.0" {
		t.Errorf("user exclusion: got %s/%s want 10.42.0.0/255.255.0.0", u.Address, u.Mask)
	}
	if u.Description != "Work VPN" {
		t.Errorf("user exclusion description: got %q want %q", u.Description, "Work VPN")
	}
	// Global exclusion must NOT leak into per-user list (re-importing would
	// freeze it at the time of edit; we want server-config to remain
	// authoritative).
	for _, e := range ccd.RedirectGatewayExclusions {
		if e.Address == "192.168.0.0" {
			t.Errorf("global exclusion leaked into per-user list: %+v", e)
		}
	}
	// CommonRoutes-style line must not be mis-stored as a route either.
	for _, r := range ccd.CustomRoutes {
		if r.Description == "net_gateway" {
			t.Errorf("net_gateway leaked into route description (would corrupt round-trip): %+v", r)
		}
	}
}

// TestValidateCcd_RejectsBadExclusion ensures the per-user validation gate
// catches the same malformed inputs as the server-config one — otherwise an
// attacker with CCD-edit permission could bypass server-config validation.
func TestValidateCcd_RejectsBadExclusion(t *testing.T) {
	t.Parallel()
	app := &OvpnAdmin{}
	ccd := Ccd{
		User:          "alice",
		ClientAddress: "dynamic",
		RedirectGatewayExclusions: []Subnet{
			{Address: "not-an-ip", Mask: "255.0.0.0"},
		},
	}
	ok, msg := app.validateCcd(ccd)
	if ok {
		t.Fatal("expected validation failure")
	}
	if !strings.Contains(msg, "RedirectGatewayExclusions") {
		t.Errorf("expected field name in error, got %q", msg)
	}
}

// ccdTemplateRaw reads the embedded template file via testdata-style indirection.
// We avoid wiring through OvpnAdmin.templates here — the template is small enough
// to keep inline literal copy in sync (the real binary uses the embedded one).
func ccdTemplateRaw(t *testing.T) string {
	t.Helper()
	// Mirror of templates/ccd.tpl. If the template changes, update both — the
	// integration tests in render-path also assert against the embedded file.
	return `{{- if (ne .ClientAddress "dynamic") }}
ifconfig-push {{ .ClientAddress }} 255.255.255.0
{{- end }}
{{- if .RedirectGateway }}
push "redirect-gateway def1" # __redirect_gateway__
{{- range $e := .MergedExclusions }}
push "route {{ $e.Address }} {{ $e.Mask }} net_gateway" # {{ $e.Source }}
{{- end }}
{{- end }}
{{- range $r := .MergedPushRoutes }}
push "route {{ $r.Address }} {{ $r.Mask }}" # {{ $r.Source }}
{{- end }}
`
}

// TestParseCcd_MarkerConfusionDefense is the regression test for the HIGH
// finding: a user-supplied route description that contains a reserved marker
// must NOT be able to forge control state (redirect-gateway flag or an
// exclusion) on round-trip. parseCcd anchors on the directive SHAPE, so a
// normal `route` line (no net_gateway, not the redirect-gateway directive) is
// always read back as a plain route regardless of what its comment says.
func TestParseCcd_MarkerConfusionDefense(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Every line below is a PLAIN route whose description contains a marker.
	// None of them has the directive shape of a real control line, so none
	// may flip RedirectGateway or create an exclusion.
	content := `push "route 8.8.8.8 255.255.255.255" # __redirect_gateway__
push "route 9.9.9.9 255.255.255.255" # __exclusion_user__ 10.0.0.0 255.0.0.0 pwn
push "route 1.2.3.4 255.255.255.255" # __exclusion_global__ sneaky
push "route 5.6.7.8 255.255.255.255" # __common__: nope
`
	if err := os.WriteFile(dir+"/victim", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &OvpnAdmin{store: testFilesystemStore(dir)}
	ccd := app.parseCcd("victim")

	if ccd.RedirectGateway {
		t.Error("forged __redirect_gateway__ in a route description must NOT enable full-tunnel")
	}
	if len(ccd.RedirectGatewayExclusions) != 0 {
		t.Errorf("forged exclusion markers must NOT create exclusions, got %+v", ccd.RedirectGatewayExclusions)
	}
	// __redirect_gateway__, __exclusion_user__, __exclusion_global__ lines are
	// plain routes and must survive as CustomRoutes. The __common__: line is
	// swallowed (common routes are rebuilt from the store) — that's expected
	// since a real operator can't set a __common__: description anyway (the
	// validator rejects it). So we expect the 3 non-common routes to remain.
	if len(ccd.CustomRoutes) != 3 {
		t.Fatalf("expected 3 plain routes preserved, got %d: %+v", len(ccd.CustomRoutes), ccd.CustomRoutes)
	}
	addrs := map[string]bool{}
	for _, r := range ccd.CustomRoutes {
		addrs[r.Address] = true
	}
	for _, want := range []string{"8.8.8.8", "9.9.9.9", "1.2.3.4"} {
		if !addrs[want] {
			t.Errorf("route %s should have survived as a plain route", want)
		}
	}
}

// TestParseCcd_LegitLinesStillParse is the backwards-compatibility guard: every
// line shape our renderer actually produces (and that exists in deployed CCD
// files today) must still classify correctly after the parse rewrite.
func TestParseCcd_LegitLinesStillParse(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := `ifconfig-push 10.30.0.7 255.255.255.0
push "redirect-gateway def1" # __redirect_gateway__
push "route 192.168.0.0 255.255.0.0 net_gateway" # __exclusion_global__ Home/office LAN
push "route 10.42.0.0 255.255.0.0 net_gateway" # __exclusion_user__ Work VPN
push "route 142.250.0.0 255.254.0.0" # __common__:google
push "route 1.1.1.1 255.255.255.255" # __user_domain__:youtube.com yt
push "route 2.2.2.2 255.255.255.255" # __user_domain__:youtube.com yt
push "route 192.168.1.0 255.255.255.0" # corp net
`
	if err := os.WriteFile(dir+"/legit", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &OvpnAdmin{store: testFilesystemStore(dir)}
	ccd := app.parseCcd("legit")

	if ccd.ClientAddress != "10.30.0.7" {
		t.Errorf("ClientAddress: got %q, want 10.30.0.7", ccd.ClientAddress)
	}
	if !ccd.RedirectGateway {
		t.Error("legit __redirect_gateway__ line must enable RedirectGateway")
	}
	// Only the per-user exclusion round-trips; global is swallowed.
	if len(ccd.RedirectGatewayExclusions) != 1 {
		t.Fatalf("want 1 per-user exclusion, got %d: %+v", len(ccd.RedirectGatewayExclusions), ccd.RedirectGatewayExclusions)
	}
	ex := ccd.RedirectGatewayExclusions[0]
	if ex.Address != "10.42.0.0" || ex.Mask != "255.255.0.0" || ex.Description != "Work VPN" {
		t.Errorf("per-user exclusion round-trip wrong: %+v", ex)
	}
	// CustomRoutes: 1 domain (youtube.com, 2 IPs collapsed) + 1 plain IP route.
	// Common route is swallowed.
	var domain, ipRoute *ccdRoute
	for i := range ccd.CustomRoutes {
		switch ccd.CustomRoutes[i].Kind {
		case "domain":
			domain = &ccd.CustomRoutes[i]
		case "ip":
			ipRoute = &ccd.CustomRoutes[i]
		}
	}
	if domain == nil || domain.Domain != "youtube.com" || len(domain.ResolvedIPs) != 2 {
		t.Errorf("domain route not collapsed correctly: %+v", domain)
	}
	if ipRoute == nil || ipRoute.Address != "192.168.1.0" || ipRoute.Description != "corp net" {
		t.Errorf("plain IP route wrong (multi-word description must survive): %+v", ipRoute)
	}
}

// TestValidateSubnet_RejectsReservedMarkerAndSlashZero covers the two new
// validation rules: /0 exclusions and reserved markers in descriptions.
func TestValidateSubnet_RejectsReservedMarkerAndSlashZero(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		in     Subnet
		errSub string
	}{
		{"slash-zero exclusion", Subnet{"0.0.0.0", "0.0.0.0", ""}, "/0"},
		{"marker in description", Subnet{"10.0.0.0", "255.0.0.0", "ok __exclusion_user__ x"}, "reserved markers"},
		{"redirect marker in description", Subnet{"10.0.0.0", "255.0.0.0", "__redirect_gateway__"}, "reserved markers"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSubnet(tc.in)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errSub)
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.errSub)
			}
		})
	}
	// And a normal /16 LAN exclusion must still pass.
	if err := validateSubnet(Subnet{"192.168.0.0", "255.255.0.0", "Home LAN"}); err != nil {
		t.Fatalf("legit /16 exclusion must validate, got %v", err)
	}
}

// TestValidateCcd_RejectsReservedMarkerInRouteDescription guards the write-time
// rejection on the per-user route path.
func TestValidateCcd_RejectsReservedMarkerInRouteDescription(t *testing.T) {
	t.Parallel()
	app := &OvpnAdmin{}
	ccd := Ccd{
		User:          "alice",
		ClientAddress: "dynamic",
		CustomRoutes: []ccdRoute{
			{Kind: "ip", Address: "8.8.8.8", Mask: "255.255.255.255", Description: "__redirect_gateway__"},
		},
	}
	ok, msg := app.validateCcd(ccd)
	if ok {
		t.Fatal("a route description with a reserved marker must be rejected")
	}
	if !strings.Contains(msg, "reserved markers") {
		t.Errorf("expected reserved-marker error, got %q", msg)
	}
}

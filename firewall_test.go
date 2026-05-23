package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

func TestIpMaskToCIDR(t *testing.T) {
	cases := []struct {
		addr, mask, want string
	}{
		{"10.0.0.0", "255.255.255.0", "10.0.0.0/24"},
		{"10.0.0.0", "255.0.0.0", "10.0.0.0/8"},
		{"172.16.0.0", "255.240.0.0", "172.16.0.0/12"},
		{"192.168.1.1", "255.255.255.255", "192.168.1.1/32"},
		{"0.0.0.0", "0.0.0.0", "0.0.0.0/0"},
	}
	for _, c := range cases {
		got, err := ipMaskToCIDR(c.addr, c.mask)
		if err != nil {
			t.Errorf("ipMaskToCIDR(%q,%q) returned err: %v", c.addr, c.mask, err)
			continue
		}
		if got != c.want {
			t.Errorf("ipMaskToCIDR(%q,%q) = %q, want %q", c.addr, c.mask, got, c.want)
		}
	}
}

func TestIpMaskToCIDR_BadInput(t *testing.T) {
	cases := []struct{ addr, mask string }{
		{"not-an-ip", "255.255.255.0"},
		{"10.0.0.0", "not-a-mask"},
		{"10.0.0.0", "255.0.255.0"}, // non-contiguous mask
	}
	for _, c := range cases {
		if _, err := ipMaskToCIDR(c.addr, c.mask); err == nil {
			t.Errorf("ipMaskToCIDR(%q,%q) expected error, got nil", c.addr, c.mask)
		}
	}
}

func TestNewFirewallController_Defaults(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	called := 0
	iptMock := func(args ...string) error { called++; return nil }
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	if fc.chainName != "OVPN_FW" {
		t.Errorf("chainName: got %q", fc.chainName)
	}
	if fc.iptBin != "iptables" {
		t.Errorf("iptBin: got %q", fc.iptBin)
	}
	if !fc.enabled {
		t.Errorf("enabled must be true by default")
	}
	if fc.sessions == nil || fc.pending == nil || fc.kick == nil {
		t.Errorf("maps/channels not initialized")
	}
	if fc.iptCmd == nil {
		t.Errorf("iptCmd not set")
	}
	if called != 0 {
		t.Errorf("iptCmd should not be invoked by constructor")
	}
}

func TestInitChain_SequenceOfCommands(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var commands [][]string
	iptMock := func(args ...string) error {
		commands = append(commands, append([]string(nil), args...))
		// Имитируем отсутствие FORWARD-jump, чтобы initChain выполнил -I FORWARD.
		if len(args) > 0 && args[0] == "-C" {
			return fmt.Errorf("rule not found")
		}
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	if err := fc.initChain(); err != nil {
		t.Fatalf("initChain: %v", err)
	}

	wantPatterns := []string{
		"-N OVPN_FW",
		"-F OVPN_FW",
		"-I FORWARD",
		"-A OVPN_FW -m conntrack",
		"-A OVPN_FW -s 172.16.100.0/24 -j DROP",
	}
	if len(commands) < len(wantPatterns) {
		t.Fatalf("expected at least %d commands, got %d: %v", len(wantPatterns), len(commands), commands)
	}
	joined := []string{}
	for _, c := range commands {
		joined = append(joined, joinSpace(c))
	}
	for _, want := range wantPatterns {
		found := false
		for _, j := range joined {
			if containsAll(j, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected command pattern %q in:\n%v", want, joined)
		}
	}
	// catch-all DROP должен быть последним
	last := joined[len(joined)-1]
	if !containsAll(last, "-A OVPN_FW -s 172.16.100.0/24 -j DROP") {
		t.Errorf("expected catch-all DROP as last command, got %q", last)
	}
}

func TestInitChain_IdempotentOnExistingChain(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	calls := 0
	iptMock := func(args ...string) error {
		calls++
		if calls == 1 && len(args) > 0 && args[0] == "-N" {
			return fmt.Errorf("Chain already exists")
		}
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	if err := fc.initChain(); err != nil {
		t.Fatalf("initChain must tolerate existing chain, got: %v", err)
	}
}

func TestInstallRulesFor_PivotsCatchAllDrop(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)

	cidrs := []string{"10.0.0.0/8", "8.8.8.8/32"}
	if err := fc.installRulesFor("alice", "172.16.100.5", cidrs); err != nil {
		t.Fatalf("installRulesFor: %v", err)
	}

	// Expected sequence:
	// 1. -D catch-all (pivot)
	// 2. -A OVPN_FW -s 172.16.100.5 -d 10.0.0.0/8 -j ACCEPT ovpn-admin: alice
	// 3. -A OVPN_FW -s 172.16.100.5 -d 8.8.8.8/32 -j ACCEPT ovpn-admin: alice
	// 4. -A catch-all DROP back
	if len(cmds) != 4 {
		t.Fatalf("expected 4 commands, got %d: %v", len(cmds), cmds)
	}
	if !containsAll(joinSpace(cmds[0]), "-D OVPN_FW") || !containsAll(joinSpace(cmds[0]), "-j DROP") {
		t.Errorf("command[0] should remove catch-all DROP, got %v", cmds[0])
	}
	for i, cidr := range cidrs {
		c := joinSpace(cmds[i+1])
		if !containsAll(c, "-A OVPN_FW") || !containsAll(c, "-s 172.16.100.5") || !containsAll(c, "-d "+cidr) || !containsAll(c, "ovpn-admin: alice") {
			t.Errorf("command[%d] missing expected pattern: %v", i+1, cmds[i+1])
		}
	}
	if !containsAll(joinSpace(cmds[3]), "-A OVPN_FW") || !containsAll(joinSpace(cmds[3]), "-j DROP") {
		t.Errorf("command[3] should restore catch-all DROP, got %v", cmds[3])
	}
}

func TestUninstallRulesFor_RemovesAllEntries(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)

	cidrs := []string{"10.0.0.0/8", "8.8.8.8/32"}
	if err := fc.uninstallRulesFor("alice", "172.16.100.5", cidrs); err != nil {
		t.Fatalf("uninstallRulesFor: %v", err)
	}

	if len(cmds) != len(cidrs) {
		t.Fatalf("expected %d commands, got %d: %v", len(cidrs), len(cmds), cmds)
	}
	for i, cidr := range cidrs {
		c := joinSpace(cmds[i])
		if !containsAll(c, "-D OVPN_FW") || !containsAll(c, "-s 172.16.100.5") || !containsAll(c, "-d "+cidr) || !containsAll(c, "ovpn-admin: alice") {
			t.Errorf("command[%d] missing expected pattern: %v", i, cmds[i])
		}
	}
}

func TestApplyDiff_Add(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	s := &fwSession{CN: "alice", VpnIP: "172.16.100.5", AllowedCIDRs: []string{"10.0.0.0/8"}}

	if err := fc.applyDiff(s, []string{"10.0.0.0/8", "8.8.8.8/32"}); err != nil {
		t.Fatalf("applyDiff: %v", err)
	}

	// Expected: -D catch-all, -A для 8.8.8.8/32, -A catch-all
	// Удалений нет — 10.0.0.0/8 в обоих set'ах.
	if len(cmds) != 3 {
		t.Fatalf("expected 3 commands, got %d: %v", len(cmds), cmds)
	}
	added := joinSpace(cmds[1])
	if !containsAll(added, "-A OVPN_FW") || !containsAll(added, "-d 8.8.8.8/32") {
		t.Errorf("expected -A for 8.8.8.8/32, got %v", cmds[1])
	}
}

func TestApplyDiff_Remove(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	s := &fwSession{CN: "alice", VpnIP: "172.16.100.5", AllowedCIDRs: []string{"10.0.0.0/8", "8.8.8.8/32", "1.1.1.1/32"}}

	if err := fc.applyDiff(s, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("applyDiff: %v", err)
	}

	// Expected: -D catch-all, -D for 8.8.8.8/32, -D for 1.1.1.1/32, -A catch-all
	if len(cmds) != 4 {
		t.Fatalf("expected 4 commands, got %d: %v", len(cmds), cmds)
	}
	deletedAccepts := 0
	for _, c := range cmds {
		j := joinSpace(c)
		if containsAll(j, "-D OVPN_FW") && containsAll(j, "-j ACCEPT") {
			deletedAccepts++
		}
	}
	if deletedAccepts != 2 {
		t.Errorf("expected 2 ACCEPT -D commands, got %d", deletedAccepts)
	}
}

func TestApplyDiff_Mixed(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	s := &fwSession{CN: "alice", VpnIP: "172.16.100.5", AllowedCIDRs: []string{"10.0.0.0/8", "1.1.1.1/32"}}

	if err := fc.applyDiff(s, []string{"10.0.0.0/8", "8.8.8.8/32"}); err != nil {
		t.Fatalf("applyDiff: %v", err)
	}

	// -D catch-all, -D 1.1.1.1, -A 8.8.8.8, -A catch-all
	if len(cmds) != 4 {
		t.Fatalf("expected 4 commands, got %d: %v", len(cmds), cmds)
	}
	if len(s.AllowedCIDRs) != 2 {
		t.Errorf("expected 2 CIDRs after diff, got %d: %v", len(s.AllowedCIDRs), s.AllowedCIDRs)
	}
}

func TestApplyDiff_NoChange(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	s := &fwSession{CN: "alice", VpnIP: "172.16.100.5", AllowedCIDRs: []string{"10.0.0.0/8"}}

	if err := fc.applyDiff(s, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("applyDiff: %v", err)
	}
	if len(cmds) != 0 {
		t.Errorf("expected 0 commands for no-change diff, got %d: %v", len(cmds), cmds)
	}
}

func TestComputeAllowedCIDRs_PersonalAndCommon(t *testing.T) {
	dir := t.TempDir()
	originalCcdDir := *ccdDir
	tmp := dir
	ccdDir = &tmp
	defer func() { ccdDir = &originalCcdDir }()
	originalStorage := *storageBackend
	fs := "filesystem"
	storageBackend = &fs
	defer func() { storageBackend = &originalStorage }()

	// CCD юзера alice с двумя custom routes
	ccdContent := `ifconfig-push 172.16.100.5 255.255.255.0
push "route 10.0.0.0 255.0.0.0" # corp
push "route 192.168.1.0 255.255.255.0" # lan
`
	if err := os.WriteFile(dir+"/alice", []byte(ccdContent), 0o644); err != nil {
		t.Fatal(err)
	}

	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{
			{ID: "x", Kind: "ip", Address: "8.8.8.8", Mask: "255.255.255.255"},
			{ID: "y", Kind: "domain", Domain: "yt.com", ResolvedIPs: []string{"1.1.1.1", "2.2.2.2"}},
		}}},
	}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, func(args ...string) error { return nil })

	cidrs, err := fc.computeAllowedCIDRs("alice")
	if err != nil {
		t.Fatalf("computeAllowedCIDRs: %v", err)
	}

	want := map[string]bool{
		"10.0.0.0/8":     true,
		"192.168.1.0/24": true,
		"8.8.8.8/32":     true,
		"1.1.1.1/32":     true,
		"2.2.2.2/32":     true,
	}
	if len(cidrs) != len(want) {
		t.Errorf("expected %d CIDRs, got %d: %v", len(want), len(cidrs), cidrs)
	}
	for _, c := range cidrs {
		if !want[c] {
			t.Errorf("unexpected CIDR %q", c)
		}
		delete(want, c)
	}
	if len(want) > 0 {
		t.Errorf("missing CIDRs: %v", want)
	}
}

func TestComputeAllowedCIDRs_Dedup(t *testing.T) {
	dir := t.TempDir()
	originalCcdDir := *ccdDir
	tmp := dir
	ccdDir = &tmp
	defer func() { ccdDir = &originalCcdDir }()
	originalStorage := *storageBackend
	fs := "filesystem"
	storageBackend = &fs
	defer func() { storageBackend = &originalStorage }()

	ccdContent := `push "route 8.8.8.8 255.255.255.255" # personal-8.8.8.8
`
	if err := os.WriteFile(dir+"/bob", []byte(ccdContent), 0o644); err != nil {
		t.Fatal(err)
	}

	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{
			{ID: "x", Kind: "ip", Address: "8.8.8.8", Mask: "255.255.255.255"},
		}}},
	}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, func(args ...string) error { return nil })

	cidrs, err := fc.computeAllowedCIDRs("bob")
	if err != nil {
		t.Fatalf("computeAllowedCIDRs: %v", err)
	}
	if len(cidrs) != 1 || cidrs[0] != "8.8.8.8/32" {
		t.Errorf("expected dedup to 1 CIDR, got %v", cidrs)
	}
}

// helpers in test file
func joinSpace(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " "
		}
		out += p
	}
	return out
}

func containsAll(s, needle string) bool {
	return strings.Contains(s, needle)
}

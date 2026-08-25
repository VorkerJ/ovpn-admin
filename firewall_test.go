package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIpMaskToCIDR(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	dir := t.TempDir()

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
		store: testFilesystemStore(dir),
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
	t.Parallel()
	dir := t.TempDir()

	ccdContent := `push "route 8.8.8.8 255.255.255.255" # personal-8.8.8.8
`
	if err := os.WriteFile(dir+"/bob", []byte(ccdContent), 0o644); err != nil {
		t.Fatal(err)
	}

	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{
			{ID: "x", Kind: "ip", Address: "8.8.8.8", Mask: "255.255.255.255"},
		}}},
		store: testFilesystemStore(dir),
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

func TestParseMgmtClientEvent_Connect(t *testing.T) {
	t.Parallel()
	lines := []string{
		">CLIENT:CONNECT,2,123",
		">CLIENT:ENV,common_name=alice",
		">CLIENT:ENV,ifconfig_pool_remote_ip=172.16.100.5",
		">CLIENT:ENV,END",
	}
	p := newMgmtEventParser()
	var got *fwEvent
	for _, l := range lines {
		if ev := p.feed(l); ev != nil {
			got = ev
		}
	}
	if got == nil {
		t.Fatal("expected a fwEvent after END")
	}
	if got.Kind != EvConnect {
		t.Errorf("kind: got %v, want EvConnect", got.Kind)
	}
	if got.CN != "alice" {
		t.Errorf("CN: got %q, want alice", got.CN)
	}
	if got.VpnIP != "172.16.100.5" {
		t.Errorf("VpnIP: got %q, want 172.16.100.5", got.VpnIP)
	}
}

func TestParseMgmtClientEvent_Disconnect(t *testing.T) {
	t.Parallel()
	lines := []string{
		">CLIENT:DISCONNECT,2",
		">CLIENT:ENV,common_name=bob",
		">CLIENT:ENV,END",
	}
	p := newMgmtEventParser()
	var got *fwEvent
	for _, l := range lines {
		if ev := p.feed(l); ev != nil {
			got = ev
		}
	}
	if got == nil {
		t.Fatal("expected a fwEvent after END")
	}
	if got.Kind != EvDisconnect {
		t.Errorf("kind: got %v, want EvDisconnect", got.Kind)
	}
	if got.CN != "bob" {
		t.Errorf("CN: got %q, want bob", got.CN)
	}
}

func TestParseMgmtClientEvent_Garbage(t *testing.T) {
	t.Parallel()
	lines := []string{
		"SUCCESS: log enabled",
		">INFO:OpenVPN Management Interface Version 1",
		">BYTECOUNT:0,0",
		"random line",
	}
	p := newMgmtEventParser()
	for _, l := range lines {
		if ev := p.feed(l); ev != nil {
			t.Errorf("garbage line should not produce an event: %q → %+v", l, ev)
		}
	}
}

func TestParseMgmtClientEvent_InterleavedSessions(t *testing.T) {
	t.Parallel()
	lines := []string{
		">CLIENT:CONNECT,2,1",
		">CLIENT:ENV,common_name=alice",
		">CLIENT:ENV,ifconfig_pool_remote_ip=172.16.100.5",
		">CLIENT:ENV,END",
		">CLIENT:CONNECT,3,1",
		">CLIENT:ENV,common_name=bob",
		">CLIENT:ENV,ifconfig_pool_remote_ip=172.16.100.6",
		">CLIENT:ENV,END",
	}
	p := newMgmtEventParser()
	var events []*fwEvent
	for _, l := range lines {
		if ev := p.feed(l); ev != nil {
			events = append(events, ev)
		}
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].CN != "alice" || events[1].CN != "bob" {
		t.Errorf("event order: %+v, %+v", events[0], events[1])
	}
}

func TestEventHandlerLoop_ConnectThenDisconnect(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{
			{ID: "x", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"},
		}}},
		store: testFilesystemStore(dir),
	}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var calls int32
	iptMock := func(args ...string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, iptMock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fc.eventHandlerLoop(ctx)

	fc.push(fwEvent{Kind: EvConnect, CN: "alice", VpnIP: "172.16.100.5"})
	waitForCalls(t, &calls, 1, 2*time.Second)

	fc.mu.Lock()
	if _, ok := fc.sessions["alice"]; !ok {
		fc.mu.Unlock()
		t.Fatal("session for alice not registered after Connect")
	}
	fc.mu.Unlock()

	prev := atomic.LoadInt32(&calls)
	fc.push(fwEvent{Kind: EvDisconnect, CN: "alice"})
	waitForCalls(t, &calls, prev+1, 2*time.Second)

	fc.mu.Lock()
	if _, ok := fc.sessions["alice"]; ok {
		fc.mu.Unlock()
		t.Fatal("session for alice not removed after Disconnect")
	}
	fc.mu.Unlock()
}

func TestEventHandlerLoop_Coalescing(t *testing.T) {
	t.Parallel()
	app := &OvpnAdmin{commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}, store: testFilesystemStore(t.TempDir())}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	iptMock := func(args ...string) error { return nil }
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, iptMock)

	// Толкаем 10 EvConnect для alice ПЕРЕД запуском обработчика — должны коалесцироваться.
	for i := 0; i < 10; i++ {
		fc.push(fwEvent{Kind: EvConnect, CN: "alice", VpnIP: "172.16.100.5"})
	}

	fc.mu.Lock()
	if len(fc.pending) != 1 {
		fc.mu.Unlock()
		t.Fatalf("expected 1 pending event after coalescing, got %d", len(fc.pending))
	}
	fc.mu.Unlock()
}

func TestEventHandlerLoop_NoOpIfDisconnected(t *testing.T) {
	t.Parallel()
	app := &OvpnAdmin{commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}, store: testFilesystemStore(t.TempDir())}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var calls int32
	iptMock := func(args ...string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, iptMock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fc.eventHandlerLoop(ctx)

	// alice не в sessions; EvUserChanged для неё должен быть no-op
	fc.push(fwEvent{Kind: EvUserChanged, CN: "alice"})
	time.Sleep(200 * time.Millisecond)

	if atomic.LoadInt32(&calls) != 0 {
		t.Errorf("expected 0 iptables calls for UserChanged on disconnected CN, got %d", calls)
	}
}

func waitForCalls(t *testing.T, calls *int32, want int32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(calls) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %d iptables calls (got %d)", want, atomic.LoadInt32(calls))
}

func TestReconcile_FromMgmtSnapshot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{
			{ID: "x", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"},
		}}},
		store: testFilesystemStore(dir),
	}

	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, iptMock)
	fc.mgmtSnapshot = func() ([]clientStatus, bool) {
		return []clientStatus{
			{CommonName: "alice", VirtualAddress: "172.16.100.5"},
			{CommonName: "bob", VirtualAddress: "172.16.100.6"},
		}, true
	}

	fc.mu.Lock()
	fc.reconcileLocked()
	fc.mu.Unlock()

	if len(fc.sessions) != 2 {
		t.Errorf("expected 2 sessions after reconcile, got %d", len(fc.sessions))
	}
	if _, ok := fc.sessions["alice"]; !ok {
		t.Errorf("alice missing from sessions")
	}
	if _, ok := fc.sessions["bob"]; !ok {
		t.Errorf("bob missing from sessions")
	}
}

func TestReconcile_DriftCorrection(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	app := &OvpnAdmin{commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}, store: testFilesystemStore(dir)}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, func(args ...string) error { return nil })

	// pre-seed: ghost session не существующая в mgmt
	fc.sessions["ghost"] = &fwSession{CN: "ghost", VpnIP: "172.16.100.99", AllowedCIDRs: []string{"10.0.0.0/8"}}
	fc.mgmtSnapshot = func() ([]clientStatus, bool) { return nil, true } // mgmt видит 0 клиентов

	fc.mu.Lock()
	fc.reconcileLocked()
	fc.mu.Unlock()

	if _, ok := fc.sessions["ghost"]; ok {
		t.Errorf("ghost session should have been removed by reconcile")
	}
}

func TestSubscribeAndPump_ParsesMultipleEvents(t *testing.T) {
	t.Parallel()
	app := &OvpnAdmin{commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}, store: testFilesystemStore(t.TempDir())}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, func(args ...string) error { return nil })

	streamLines := []string{
		"SUCCESS: real-time notification of client events enabled",
		">CLIENT:CONNECT,2,1",
		">CLIENT:ENV,common_name=alice",
		">CLIENT:ENV,ifconfig_pool_remote_ip=172.16.100.5",
		">CLIENT:ENV,END",
		">CLIENT:DISCONNECT,2",
		">CLIENT:ENV,common_name=alice",
		">CLIENT:ENV,END",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go fc.eventHandlerLoop(ctx)

	// Drive the mgmt event parser directly (prod no longer holds a persistent
	// >CLIENT: stream — see firewallReconcilePoll — but the parser + event
	// handling for connect/disconnect must still work correctly).
	p := newMgmtEventParser()
	for _, line := range streamLines {
		if ev := p.feed(line); ev != nil {
			fc.push(*ev)
		}
	}

	// Дать обработчику время
	time.Sleep(200 * time.Millisecond)

	// После CONNECT+DISCONNECT alice должна отсутствовать
	fc.mu.Lock()
	_, exists := fc.sessions["alice"]
	fc.mu.Unlock()
	if exists {
		t.Errorf("alice should have been disconnected by end of stream")
	}
}

func TestStart_RunsInitAndReconcile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	app := &OvpnAdmin{commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}, store: testFilesystemStore(dir)}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, iptMock)
	fc.mgmtSnapshot = func() ([]clientStatus, bool) { return nil, true }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := fc.Start(ctx, "127.0.0.1:65000", 100*time.Millisecond); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Должны быть вызваны initChain команды
	if len(cmds) == 0 {
		t.Errorf("Start should have invoked initChain commands")
	}

	cancel()
	time.Sleep(150 * time.Millisecond) // дать горутинам выйти
}

func TestStop_RunsCleanup(t *testing.T) {
	t.Parallel()
	app := &OvpnAdmin{commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}, store: testFilesystemStore(t.TempDir())}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, iptMock)
	fc.mgmtSnapshot = func() ([]clientStatus, bool) { return nil, true }

	ctx, cancel := context.WithCancel(context.Background())
	if err := fc.Start(ctx, "127.0.0.1:65001", 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	cmds = nil // сбрасываем команды от Start

	cancel()
	fc.Stop()

	// Должны быть -D FORWARD -j OVPN_FW, -F OVPN_FW, -X OVPN_FW
	if len(cmds) < 3 {
		t.Errorf("Stop should have invoked at least 3 cleanup commands, got %d: %v", len(cmds), cmds)
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

package main

import (
	"fmt"
	"net"
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

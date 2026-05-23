package main

import (
	"net"
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

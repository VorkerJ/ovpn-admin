package main

import "testing"

// The chart seeds the first-boot listen proto/port/network from env so a
// GitOps deploy renders server.conf on the right port from the very first boot.
func TestDefaultServerConfig_EnvSeeding(t *testing.T) {
	t.Setenv("OVPN_SERVER_PROTO", "tcp")
	t.Setenv("OVPN_SERVER_PORT", "21994")
	t.Setenv("OVPN_SERVER_NETWORK", "10.20.30.0")
	t.Setenv("OVPN_SERVER_NETWORK_MASK", "255.255.255.0")

	cfg := defaultServerConfig()
	if cfg.Proto != "tcp" || cfg.Port != 21994 {
		t.Fatalf("proto/port: got %s/%d, want tcp/21994", cfg.Proto, cfg.Port)
	}
	if cfg.Network != "10.20.30.0" || cfg.NetworkMask != "255.255.255.0" {
		t.Fatalf("network: got %s/%s, want 10.20.30.0/255.255.255.0", cfg.Network, cfg.NetworkMask)
	}
}

func TestDefaultServerConfig_FallbacksWhenUnset(t *testing.T) {
	// No env set → built-in defaults preserved (upgrade-safe for existing installs).
	cfg := defaultServerConfig()
	if cfg.Proto != "tcp" || cfg.Port != 1194 {
		t.Fatalf("default proto/port: got %s/%d, want tcp/1194", cfg.Proto, cfg.Port)
	}
	if cfg.Network != "172.16.100.0" {
		t.Fatalf("default network: got %s, want 172.16.100.0", cfg.Network)
	}
}

func TestDefaultServerConfig_InvalidPortFallsBack(t *testing.T) {
	t.Setenv("OVPN_SERVER_PORT", "not-a-number")
	if got := defaultServerConfig().Port; got != 1194 {
		t.Fatalf("invalid port should fall back to 1194, got %d", got)
	}
}

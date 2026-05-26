package main

import "testing"

func TestDefaultServerConfig_PreservesBackwardCompat(t *testing.T) {
	cfg := defaultServerConfig()

	// proto/tls остаются текущими prod-значениями, чтобы upgrade не сломал клиентов
	if cfg.Proto != "tcp" {
		t.Errorf("Proto: got %q, want tcp", cfg.Proto)
	}
	if cfg.TLSAuthMode != "tls-auth" {
		t.Errorf("TLSAuthMode: got %q, want tls-auth", cfg.TLSAuthMode)
	}
	if cfg.Port != 1194 {
		t.Errorf("Port: got %d, want 1194", cfg.Port)
	}
	if cfg.Network != "172.16.100.0" || cfg.NetworkMask != "255.255.255.0" {
		t.Errorf("Network: got %s/%s", cfg.Network, cfg.NetworkMask)
	}
	if cfg.TunMTU != 1500 || cfg.MssFix != 1450 {
		t.Errorf("MTU/MssFix: got %d/%d", cfg.TunMTU, cfg.MssFix)
	}
	if cfg.TLSVersionMin != "1.2" {
		t.Errorf("TLSVersionMin: got %q", cfg.TLSVersionMin)
	}
	if cfg.Compression != "" {
		t.Errorf("Compression must be empty (VORACLE), got %q", cfg.Compression)
	}
	if !cfg.DCOEnabled {
		t.Error("DCOEnabled must default to true (gated by DCOAvailable at render time)")
	}
	if !cfg.ClientToClient || !cfg.DuplicateCN {
		t.Error("ClientToClient/DuplicateCN must default to true")
	}
	if len(cfg.DataCiphers) == 0 || cfg.DataCiphers[0] != "AES-256-GCM" {
		t.Errorf("DataCiphers first must be AES-256-GCM, got %v", cfg.DataCiphers)
	}
	if len(cfg.DNSServers) != 2 || cfg.DNSServers[0] != "1.1.1.1" {
		t.Errorf("DNSServers: got %v", cfg.DNSServers)
	}
}

package main

import (
	"sync"
	"testing"
)

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

func TestServerConfigStore_RoundTrip(t *testing.T) {
	store := newServerConfigStore()
	cfg := defaultServerConfig()
	cfg.Port = 8443
	cfg.DNSServers = []string{"77.88.8.8"}
	store.replace(cfg)

	got := store.snapshot()
	if got.Port != 8443 {
		t.Errorf("Port: got %d", got.Port)
	}
	if len(got.DNSServers) != 1 || got.DNSServers[0] != "77.88.8.8" {
		t.Errorf("DNSServers: got %v", got.DNSServers)
	}
}

func TestServerConfigStore_SnapshotIsDeepCopy(t *testing.T) {
	store := newServerConfigStore()
	cfg := defaultServerConfig()
	cfg.DNSServers = []string{"1.1.1.1"}
	store.replace(cfg)

	snap := store.snapshot()
	snap.DNSServers[0] = "9.9.9.9"
	snap.DataCiphers[0] = "TRASH"

	again := store.snapshot()
	if again.DNSServers[0] == "9.9.9.9" {
		t.Error("snapshot must not share DNSServers slice")
	}
	if again.DataCiphers[0] == "TRASH" {
		t.Error("snapshot must not share DataCiphers slice")
	}
}

func TestServerConfigStore_ConcurrentAccess(t *testing.T) {
	store := newServerConfigStore()
	store.replace(defaultServerConfig())

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = store.snapshot() }()
		go func() { defer wg.Done(); cfg := defaultServerConfig(); store.replace(cfg) }()
	}
	wg.Wait()
}

func TestServerConfigStore_NilSlicesNormalized(t *testing.T) {
	store := newServerConfigStore()
	cfg := defaultServerConfig()
	cfg.DataCiphers = nil
	cfg.DNSServers = nil
	cfg.PushExtra = nil
	cfg.CustomDirectives = nil
	store.replace(cfg)

	got := store.snapshot()
	if got.DataCiphers == nil || got.DNSServers == nil || got.PushExtra == nil || got.CustomDirectives == nil {
		t.Error("nil slices must be normalized to empty slices")
	}
}

func TestValidateServerConfig_OK(t *testing.T) {
	cfg := defaultServerConfig()
	if err := validateServerConfig(cfg); err != nil {
		t.Errorf("default config must validate, got: %v", err)
	}
}

func TestValidateServerConfig_BadProto(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.Proto = "sctp"
	if err := validateServerConfig(cfg); err == nil {
		t.Error("expected error for non-tcp/udp proto")
	}
}

func TestValidateServerConfig_PortRange(t *testing.T) {
	for _, p := range []int{0, -1, 65536, 100000} {
		cfg := defaultServerConfig()
		cfg.Port = p
		if err := validateServerConfig(cfg); err == nil {
			t.Errorf("expected error for port %d", p)
		}
	}
}

func TestValidateServerConfig_MTURange(t *testing.T) {
	for _, m := range []int{0, 100, 9001, 100000} {
		cfg := defaultServerConfig()
		cfg.TunMTU = m
		if err := validateServerConfig(cfg); err == nil {
			t.Errorf("expected error for MTU %d", m)
		}
	}
}

func TestValidateServerConfig_MssFix(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.MssFix = 0
	if err := validateServerConfig(cfg); err != nil {
		t.Errorf("MssFix=0 must be OK (disabled)")
	}
	cfg.MssFix = 50
	if err := validateServerConfig(cfg); err == nil {
		t.Error("MssFix < 100 must fail")
	}
}

func TestValidateServerConfig_DataCipherWhitelist(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.DataCiphers = []string{"BF-CBC"}
	if err := validateServerConfig(cfg); err == nil {
		t.Error("expected error for BF-CBC cipher")
	}
}

func TestValidateServerConfig_TLSVersion(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.TLSVersionMin = "1.0"
	if err := validateServerConfig(cfg); err == nil {
		t.Error("TLS 1.0 must be rejected")
	}
}

func TestValidateServerConfig_TLSAuthMode(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.TLSAuthMode = "tls-magic"
	if err := validateServerConfig(cfg); err == nil {
		t.Error("invalid tls_auth_mode must be rejected")
	}
}

func TestValidateServerConfig_Verb(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.Verb = -1
	if err := validateServerConfig(cfg); err == nil {
		t.Error("negative verb must fail")
	}
	cfg.Verb = 12
	if err := validateServerConfig(cfg); err == nil {
		t.Error("verb > 11 must fail")
	}
}

func TestValidateServerConfig_DNSServers(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.DNSServers = []string{"1.1.1.1", "not-an-ip"}
	if err := validateServerConfig(cfg); err == nil {
		t.Error("invalid DNS IP must be rejected")
	}
}

func TestValidateServerConfig_CustomDirective_Whitelist(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.CustomDirectives = []string{"route 10.0.0.0 255.0.0.0"}
	if err := validateServerConfig(cfg); err != nil {
		t.Errorf("whitelisted directive must pass: %v", err)
	}

	cfg.CustomDirectives = []string{"script-security 2"}
	if err := validateServerConfig(cfg); err == nil {
		t.Error("script-security must be rejected")
	}

	cfg.CustomDirectives = []string{"up /tmp/evil.sh"}
	if err := validateServerConfig(cfg); err == nil {
		t.Error("up /tmp/evil.sh must be rejected")
	}
}

func TestValidateServerConfig_KeepaliveRelation(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.KeepaliveInterval = 100
	cfg.KeepaliveTimeout = 50
	if err := validateServerConfig(cfg); err == nil {
		t.Error("KeepaliveTimeout must be > KeepaliveInterval")
	}
}

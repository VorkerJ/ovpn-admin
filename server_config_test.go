package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

func TestRenderServerConfig_Defaults(t *testing.T) {
	cfg := defaultServerConfig()
	out, err := renderServerConfig(cfg, false /* dco available */, true /* ccd enabled */)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	checks := []string{
		"proto tcp-server",
		"port 1194",
		"tun-mtu 1500",
		"mssfix 1450",
		"data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
		"data-ciphers-fallback AES-256-GCM",
		"tls-version-min 1.2",
		"tls-auth /etc/openvpn/pki/ta.key",
		"key-direction 0",
		"keepalive 10 60",
		"client-to-client",
		"duplicate-cn",
		"server 172.16.100.0 255.255.255.0",
		"topology subnet",
		`push "topology subnet"`,
		`push "dhcp-option DNS 1.1.1.1"`,
		`push "dhcp-option DNS 8.8.8.8"`,
		"verb 3",
		"management 127.0.0.1 8989",
		"management-client-auth",
		"client-config-dir /etc/openvpn/ccd",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("missing directive: %q\n---rendered---\n%s", want, out)
		}
	}
	if strings.Contains(out, "data-channel-offload") {
		t.Errorf("data-channel-offload must not appear when DCOAvailable=false")
	}
}

func TestRenderServerConfig_DCOEnabled(t *testing.T) {
	cfg := defaultServerConfig()
	out, _ := renderServerConfig(cfg, true, false)
	if !strings.Contains(out, "data-channel-offload") {
		t.Error("data-channel-offload must appear when DCOEnabled+Available both true")
	}
}

func TestRenderServerConfig_TLSCrypt(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.TLSAuthMode = "tls-crypt"
	out, _ := renderServerConfig(cfg, false, false)
	if !strings.Contains(out, "tls-crypt /etc/openvpn/pki/ta.key") {
		t.Errorf("tls-crypt missing:\n%s", out)
	}
	if strings.Contains(out, "tls-auth /etc/openvpn/pki/ta.key") {
		t.Errorf("tls-auth must NOT appear when mode=tls-crypt:\n%s", out)
	}
	if strings.Contains(out, "key-direction 0") {
		t.Errorf("key-direction 0 must NOT appear with tls-crypt:\n%s", out)
	}
}

func TestRenderServerConfig_RedirectGateway(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.RedirectGateway = true
	out, _ := renderServerConfig(cfg, false, false)
	if !strings.Contains(out, `push "redirect-gateway def1"`) {
		t.Errorf("redirect-gateway push missing:\n%s", out)
	}
}

func TestRenderServerConfig_Compression(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.Compression = "lz4-v2"
	out, _ := renderServerConfig(cfg, false, false)
	if !strings.Contains(out, "compress lz4-v2") {
		t.Errorf("compress lz4-v2 missing:\n%s", out)
	}
}

func TestRenderServerConfig_MaxClients(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.MaxClients = 100
	out, _ := renderServerConfig(cfg, false, false)
	if !strings.Contains(out, "max-clients 100") {
		t.Errorf("max-clients missing:\n%s", out)
	}
	cfg.MaxClients = 0
	out, _ = renderServerConfig(cfg, false, false)
	if strings.Contains(out, "max-clients") {
		t.Errorf("max-clients must not appear when 0:\n%s", out)
	}
}

func TestRenderServerConfig_CustomDirectivesAtEnd(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.CustomDirectives = []string{"route 10.0.0.0 255.0.0.0", "explicit-exit-notify"}
	out, _ := renderServerConfig(cfg, false, false)
	if !strings.Contains(out, "route 10.0.0.0 255.0.0.0") {
		t.Errorf("custom route missing:\n%s", out)
	}
	if !strings.Contains(out, "explicit-exit-notify") {
		t.Errorf("explicit-exit-notify missing:\n%s", out)
	}
}

func TestRenderServerConfig_PushExtra(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.PushExtra = []string{`route 10.0.0.0 255.0.0.0`}
	out, _ := renderServerConfig(cfg, false, false)
	if !strings.Contains(out, `push "route 10.0.0.0 255.0.0.0"`) {
		t.Errorf("push extra missing:\n%s", out)
	}
}

func TestRenderServerConfig_CcdEnabledFalse(t *testing.T) {
	cfg := defaultServerConfig()
	out, _ := renderServerConfig(cfg, false, false)
	if strings.Contains(out, "client-config-dir") {
		t.Errorf("client-config-dir must not appear when ccd disabled")
	}
}

func TestDetectDCOSupport_NoModule(t *testing.T) {
	available := detectDCOSupport()
	if runtimeIsLinux() && available {
		t.Logf("DCO available on this host (Linux kernel with ovpn module)")
	}
	if !runtimeIsLinux() && available {
		t.Errorf("DCO must be false on non-Linux, got true")
	}
}

func runtimeIsLinux() bool {
	_, err := os.Stat("/sys")
	return err == nil
}

func TestCategorizeChanges_NoChange(t *testing.T) {
	cfg := defaultServerConfig()
	kind := categorizeChanges(cfg, cfg)
	if kind != "none" {
		t.Errorf("identical configs must produce none, got %q", kind)
	}
}

func TestCategorizeChanges_SoftFields(t *testing.T) {
	for _, mod := range []func(*ServerConfig){
		func(c *ServerConfig) { c.Verb = 5 },
		func(c *ServerConfig) { c.DNSServers = append(c.DNSServers, "9.9.9.9") },
		func(c *ServerConfig) { c.RedirectGateway = true },
		func(c *ServerConfig) { c.KeepaliveInterval = 20 },
		func(c *ServerConfig) { c.KeepaliveTimeout = 120 },
		func(c *ServerConfig) { c.MaxClients = 50 },
		func(c *ServerConfig) { c.PushExtra = []string{"route 10.0.0.0 255.0.0.0"} },
		func(c *ServerConfig) { c.CustomDirectives = []string{"explicit-exit-notify"} },
	} {
		old := defaultServerConfig()
		new := defaultServerConfig()
		mod(&new)
		if got := categorizeChanges(old, new); got != "soft" {
			t.Errorf("expected soft, got %q for change", got)
		}
	}
}

func TestCategorizeChanges_HardFields(t *testing.T) {
	for _, mod := range []func(*ServerConfig){
		func(c *ServerConfig) { c.Proto = "udp" },
		func(c *ServerConfig) { c.Port = 8443 },
		func(c *ServerConfig) { c.TunMTU = 1400 },
		func(c *ServerConfig) { c.MssFix = 1300 },
		func(c *ServerConfig) { c.DataCiphers = []string{"AES-128-GCM"} },
		func(c *ServerConfig) { c.TLSVersionMin = "1.3" },
		func(c *ServerConfig) { c.TLSAuthMode = "tls-crypt" },
		func(c *ServerConfig) { c.DCOEnabled = false },
		func(c *ServerConfig) { c.Compression = "lz4-v2" },
		func(c *ServerConfig) { c.ClientToClient = false },
		func(c *ServerConfig) { c.DuplicateCN = false },
		func(c *ServerConfig) { c.Network = "10.8.0.0" },
		func(c *ServerConfig) { c.NetworkMask = "255.255.0.0" },
	} {
		old := defaultServerConfig()
		new := defaultServerConfig()
		mod(&new)
		if got := categorizeChanges(old, new); got != "hard" {
			t.Errorf("expected hard, got %q", got)
		}
	}
}

func TestCategorizeChanges_HardWinsOverSoft(t *testing.T) {
	old := defaultServerConfig()
	new := defaultServerConfig()
	new.Verb = 5
	new.Port = 8443
	if got := categorizeChanges(old, new); got != "hard" {
		t.Errorf("hard must win over soft, got %q", got)
	}
}

func TestServerConfig_FilePersist_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "_server_config.json")

	cfg := defaultServerConfig()
	cfg.Port = 8443
	cfg.UpdatedBy = "admin"

	if err := saveServerConfigToFile(path, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := loadServerConfigFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Port != 8443 || loaded.UpdatedBy != "admin" {
		t.Errorf("roundtrip mismatch: %+v", loaded)
	}
}

func TestServerConfig_FilePersist_LoadMissingReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "_missing.json")
	cfg, err := loadServerConfigFromFile(path)
	if err != nil {
		t.Errorf("missing file must not error, got %v", err)
	}
	if cfg.Proto != "tcp" {
		t.Errorf("missing file must return defaults, got Proto=%q", cfg.Proto)
	}
}

func TestServerConfig_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "_server_config.json")
	cfg := defaultServerConfig()

	if err := saveServerConfigToFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := saveServerConfigToFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file not cleaned: %v", err)
	}
}

func TestServerConfig_Serialize_Deserialize(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.Port = 8443
	data, err := serializeServerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := deserializeServerConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Port != 8443 {
		t.Errorf("roundtrip mismatch: %+v", parsed)
	}
}

func TestServerConfig_Deserialize_Empty(t *testing.T) {
	cfg, err := deserializeServerConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proto != "tcp" {
		t.Errorf("empty input must return defaults, got %q", cfg.Proto)
	}
}

// fakeMgmtServer — мок OpenVPN management-interface для тестов.
type fakeMgmtServer struct {
	listener     net.Listener
	gotSignals   []string
	respondError bool
	closed       chan struct{}
}

func startFakeMgmt(t *testing.T) *fakeMgmtServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeMgmtServer{listener: ln, closed: make(chan struct{})}
	go f.serve()
	t.Cleanup(func() {
		ln.Close()
		close(f.closed)
	})
	return f
}

func (f *fakeMgmtServer) addr() string {
	return f.listener.Addr().String()
}

func (f *fakeMgmtServer) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			c.Write([]byte(">INFO:OpenVPN Management Interface Version 5\r\n"))
			buf := make([]byte, 256)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				line := strings.TrimSpace(string(buf[:n]))
				if strings.HasPrefix(line, "signal ") {
					f.gotSignals = append(f.gotSignals, line)
					if f.respondError {
						c.Write([]byte("ERROR: signal not delivered\r\n"))
					} else {
						c.Write([]byte("SUCCESS: signal " + strings.TrimPrefix(line, "signal ") + " thrown\r\n"))
					}
				}
			}
		}(conn)
	}
}

func TestServerManager_SoftReload_SendsSIGHUP(t *testing.T) {
	mgmt := startFakeMgmt(t)
	mgr := &serverManager{mgmtAddr: mgmt.addr()}

	if err := mgr.softReload(); err != nil {
		t.Fatalf("softReload: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if len(mgmt.gotSignals) == 0 || !strings.Contains(mgmt.gotSignals[0], "SIGHUP") {
		t.Errorf("expected SIGHUP signal, got %v", mgmt.gotSignals)
	}
}

func TestServerManager_HardReload_SendsSIGTERM(t *testing.T) {
	mgmt := startFakeMgmt(t)
	mgr := &serverManager{mgmtAddr: mgmt.addr()}

	if err := mgr.sendSignal("SIGTERM"); err != nil {
		t.Fatalf("sendSignal: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if len(mgmt.gotSignals) == 0 || !strings.Contains(mgmt.gotSignals[0], "SIGTERM") {
		t.Errorf("expected SIGTERM, got %v", mgmt.gotSignals)
	}
}

func TestServerManager_WaitMgmtReady_Timeout(t *testing.T) {
	mgr := &serverManager{mgmtAddr: "127.0.0.1:0"}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := mgr.waitMgmtReady(ctx)
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestServerManager_WaitMgmtReady_Success(t *testing.T) {
	mgmt := startFakeMgmt(t)
	mgr := &serverManager{mgmtAddr: mgmt.addr()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := mgr.waitMgmtReady(ctx); err != nil {
		t.Errorf("waitMgmtReady: %v", err)
	}
}

func TestServerManager_Apply_NoChange(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "server.conf")
	store := newServerConfigStore()

	mgr := &serverManager{
		store:       store,
		storagePath: filepath.Join(dir, "store.json"),
		mgmtAddr:    "127.0.0.1:0",
		confPath:    confPath,
		ccdEnabled:  true,
	}

	cfg := store.snapshot()
	kind, err := mgr.apply(context.Background(), cfg, "admin")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if kind != "none" {
		t.Errorf("expected none for identical config, got %q", kind)
	}
}

func TestServerManager_Apply_Soft(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "server.conf")
	mgmt := startFakeMgmt(t)
	store := newServerConfigStore()

	originalStorage := *storageBackend
	fs := "filesystem"
	storageBackend = &fs
	defer func() { storageBackend = &originalStorage }()

	mgr := &serverManager{
		store:       store,
		storagePath: filepath.Join(dir, "store.json"),
		mgmtAddr:    mgmt.addr(),
		confPath:    confPath,
		ccdEnabled:  true,
	}

	cfg := store.snapshot()
	cfg.Verb = 5

	kind, err := mgr.apply(context.Background(), cfg, "admin")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if kind != "soft" {
		t.Errorf("expected soft, got %q", kind)
	}
	time.Sleep(100 * time.Millisecond)
	found := false
	for _, sig := range mgmt.gotSignals {
		if strings.Contains(sig, "SIGHUP") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SIGHUP in signals, got %v", mgmt.gotSignals)
	}
	if _, err := os.Stat(confPath); err != nil {
		t.Errorf("server.conf not written: %v", err)
	}
}

func TestServerManager_Apply_RejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	store := newServerConfigStore()

	originalStorage := *storageBackend
	fs := "filesystem"
	storageBackend = &fs
	defer func() { storageBackend = &originalStorage }()

	mgr := &serverManager{
		store:       store,
		storagePath: filepath.Join(dir, "store.json"),
		mgmtAddr:    "127.0.0.1:0",
		confPath:    filepath.Join(dir, "server.conf"),
		ccdEnabled:  true,
	}

	cfg := store.snapshot()
	cfg.Port = 99999

	_, err := mgr.apply(context.Background(), cfg, "admin")
	if err == nil {
		t.Error("expected validation error")
	}
}

func newServerConfigTestAdmin(t *testing.T) (*OvpnAdmin, *fakeMgmtServer, string) {
	t.Helper()
	dir := t.TempDir()
	mgmt := startFakeMgmt(t)
	app := &OvpnAdmin{role: "master"}
	app.serverConfigStore = newServerConfigStore()
	app.serverManager = &serverManager{
		store:       app.serverConfigStore,
		storagePath: filepath.Join(dir, "store.json"),
		mgmtAddr:    mgmt.addr(),
		confPath:    filepath.Join(dir, "server.conf"),
		ccdEnabled:  true,
	}
	fs := "filesystem"
	storageBackend = &fs
	return app, mgmt, dir
}

func TestServerConfigHandler_GET(t *testing.T) {
	app, _, _ := newServerConfigTestAdmin(t)
	req := httptest.NewRequest(http.MethodGet, "/api/server-config", nil)
	rec := httptest.NewRecorder()
	app.serverConfigHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	var resp ServerConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Config.Proto != "tcp" {
		t.Errorf("default proto wrong: %q", resp.Config.Proto)
	}
}

func TestServerConfigHandler_PUT_Soft(t *testing.T) {
	app, mgmt, _ := newServerConfigTestAdmin(t)

	cfg := app.serverConfigStore.snapshot()
	cfg.Verb = 5

	body, _ := json.Marshal(cfg)
	req := httptest.NewRequest(http.MethodPut, "/api/server-config", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.serverConfigHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Config     ServerConfig `json:"config"`
		ReloadKind string       `json:"reload_kind"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.ReloadKind != "soft" {
		t.Errorf("expected reload_kind=soft, got %q", resp.ReloadKind)
	}
	time.Sleep(100 * time.Millisecond)
	if len(mgmt.gotSignals) == 0 {
		t.Errorf("expected SIGHUP signal")
	}
}

func TestServerConfigHandler_PUT_RejectsInvalid(t *testing.T) {
	app, _, _ := newServerConfigTestAdmin(t)
	cfg := app.serverConfigStore.snapshot()
	cfg.Port = 99999

	body, _ := json.Marshal(cfg)
	req := httptest.NewRequest(http.MethodPut, "/api/server-config", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.serverConfigHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestServerConfigHandler_PUT_SlaveLocked(t *testing.T) {
	app, _, _ := newServerConfigTestAdmin(t)
	app.role = "slave"

	body, _ := json.Marshal(app.serverConfigStore.snapshot())
	req := httptest.NewRequest(http.MethodPut, "/api/server-config", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.serverConfigHandler(rec, req)

	if rec.Code != http.StatusLocked {
		t.Errorf("expected 423, got %d", rec.Code)
	}
}

func TestServerConfigHandler_Test_DryRun(t *testing.T) {
	app, _, _ := newServerConfigTestAdmin(t)
	cfg := app.serverConfigStore.snapshot()
	cfg.Port = 8443

	body, _ := json.Marshal(cfg)
	req := httptest.NewRequest(http.MethodPost, "/api/server-config/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.serverConfigTestHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: %d body=%s", rec.Code, rec.Body.String())
	}
	if app.serverConfigStore.snapshot().Port == 8443 {
		t.Error("dry-run must not modify store")
	}
}

func TestServerConfigHandler_Defaults(t *testing.T) {
	app, _, _ := newServerConfigTestAdmin(t)
	req := httptest.NewRequest(http.MethodGet, "/api/server-config/defaults", nil)
	rec := httptest.NewRecorder()
	app.serverConfigDefaultsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	var cfg ServerConfig
	json.Unmarshal(rec.Body.Bytes(), &cfg)
	if cfg.Proto != "tcp" {
		t.Errorf("defaults proto: %q", cfg.Proto)
	}
}

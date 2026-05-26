# Editable OpenVPN Server Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Через Admin UI редактируется ~15 параметров OpenVPN-сервера (proto, port, MTU, cipher, DCO, DNS push, custom directives). Hybrid reload: SIGHUP для soft-полей, SIGTERM-restart с rollback для hard-полей. DCO auto-detected при старте.

**Architecture:** Новый Go-модуль `server_config.go` владеет `ServerConfig` структурой и `serverConfigStore` (Secret или JSON, тот же паттерн что Common Routes). Рендерит `server.conf` через `text/template` в shared `emptyDir` volume. openvpn-container в init-loop ждёт файл, потом стартует. Reload-операции — через OpenVPN management-interface (127.0.0.1:8989).

**Tech Stack:** Go 1.25 stdlib (`text/template`, `os/exec`, `net`, `sync`), `github.com/google/uuid`, `github.com/prometheus/client_golang/prometheus`. Vue 3 + Tailwind + Lucide для UI. Helm chart + docker-compose deployment.

**Spec:** [`docs/superpowers/specs/2026-05-26-server-config-design.md`](../specs/2026-05-26-server-config-design.md)

---

## File Structure

**Новые файлы (Go):**
- `server_config.go` — типы (`ServerConfig`, `ServerConfigResponse`, `serverConfigStore`), валидация, render, DCO detection, manager (soft/hard reload + rollback), HTTP handlers. Один файл ~600-800 строк по аналогии с `common_routes.go`.
- `server_config_test.go` — все unit + httptest интеграционные тесты.

**Новые файлы (Frontend):**
- `frontend/src/components/ServerConfigView.vue` — главный view вкладки «Сервер».
- `frontend/src/components/server-config/SectionCard.vue` — переиспользуемая обёртка-секция (collapsible card с заголовком).
- `frontend/src/components/server-config/ChipInput.vue` — multi-value chip input для DNS, DataCiphers.

**Изменяемые файлы:**
- `main.go` — регистрация `--server-config` флага, инициализация store + manager, регистрация HTTP роутов, передача DCO-detect результата.
- `frontend/src/App.vue` — добавление вкладки «Сервер» в `visibleTabs`.
- `frontend/src/api.js` — функции `fetchServerConfig`, `updateServerConfig`, `testServerConfig`, `fetchServerConfigDefaults`.
- `Dockerfile.ovpn-admin` — добавить пакет `kmod` если нужен `lsmod`/`modprobe` для DCO-detect (опционально, нативные `os.Stat /sys/module/ovpn` работают без `kmod`).
- `Dockerfile.openvpn` — без изменений (openvpn 2.6.20 в Alpine 3.23 уже умеет DCO если ядро поддерживает).
- `setup/configure.sh` — упростить: больше не генерит `openvpn.conf`, только PKI init и iptables MASQUERADE. Команда openvpn заменяется на init-wait-loop.
- `setup/openvpn.conf` — удалить файл (больше не нужен).
- `docker-compose.yaml` — emptyDir-equivalent: shared `./ovpn-config:/etc/openvpn/config` или named volume; init-wait-loop в command openvpn-сервиса; добавить `restart: unless-stopped`.
- `charts/openvpn-admin/templates/configmap.yaml` — удалить блок `server.conf`. Если ConfigMap пустой — удалить файл полностью.
- `charts/openvpn-admin/templates/deployment.yaml` — `server-conf` volume `configMap` → `emptyDir`, mount в обоих контейнерах, init-loop в openvpn-container command, добавить mount `/lib/modules` для DCO detection.
- `charts/openvpn-admin/values.yaml` — пометить deprecated поля `openvpn.proto`, `openvpn.port`, `openvpn.network`, `openvpn.networkMask`, `openvpn.networkPrefix`, `openvpn.logLevel` (комментарий «теперь управляется через UI»), оставить только для initial defaults.
- `README.md` — секция «Server configuration via Admin UI».
- `CHANGELOG.md` — note: deprecation values.yaml openvpn config-полей.

---

## Important Project Rules

- **Docker builds: ВСЕГДА `--no-cache`** (CLAUDE.md). На M-Mac добавлять `DOCKER_DEFAULT_PLATFORM=linux/amd64`.
- **Frontend → packr2:** после правок `frontend/src/` — `npm run build` затем `packr2` (docker делает сам).
- **Никаких `--no-verify` для git hooks.**
- **Коммитим часто** — после каждой задачи отдельный коммит.
- **Unit-тесты не должны дёргать реальный openvpn/iptables** — мокаем mgmt-conn и DCO-detection.

---

## Task 1: Типы данных и дефолты

**Files:**
- Create: `/Users/alexp/GolandProjects/ovpn-admin/server_config.go`
- Create: `/Users/alexp/GolandProjects/ovpn-admin/server_config_test.go`

- [ ] **Step 1: Тест на defaultServerConfig (RED)**

Создать `/Users/alexp/GolandProjects/ovpn-admin/server_config_test.go`:

```go
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
```

- [ ] **Step 2: Прогнать — RED**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run TestDefaultServerConfig -v ./...`
Expected: `undefined: defaultServerConfig`.

- [ ] **Step 3: Реализация типов и дефолтов**

Создать `/Users/alexp/GolandProjects/ovpn-admin/server_config.go`:

```go
package main

import "sync"

// ServerConfig — единственный источник правды для openvpn-сервера.
// Сериализуется в Secret ovpn-admin-server-config или в JSON-файл.
type ServerConfig struct {
	// Network / transport
	Proto       string `json:"proto"`        // "udp" | "tcp"
	Port        int    `json:"port"`         // 1194
	Network     string `json:"network"`      // "172.16.100.0"
	NetworkMask string `json:"network_mask"` // "255.255.255.0"

	// MTU
	TunMTU int `json:"tun_mtu"` // 1500
	MssFix int `json:"mss_fix"` // 0 = disabled

	// Cryptography
	DataCiphers   []string `json:"data_ciphers"`
	TLSVersionMin string   `json:"tls_version_min"`
	TLSAuthMode   string   `json:"tls_auth_mode"`
	DCOEnabled    bool     `json:"dco_enabled"`

	// Behavior
	KeepaliveInterval int    `json:"keepalive_interval"`
	KeepaliveTimeout  int    `json:"keepalive_timeout"`
	MaxClients        int    `json:"max_clients"`
	ClientToClient    bool   `json:"client_to_client"`
	DuplicateCN       bool   `json:"duplicate_cn"`
	Compression       string `json:"compression"`
	Verb              int    `json:"verb"`

	// Pushed to clients
	RedirectGateway bool     `json:"redirect_gateway"`
	DNSServers      []string `json:"dns_servers"`
	PushExtra       []string `json:"push_extra"`

	// Advanced
	CustomDirectives []string `json:"custom_directives"`

	// Bookkeeping
	UpdatedAt string `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`
}

// ServerConfigResponse — обёртка для API-ответа, добавляет runtime DCO-detection
// которая НЕ сохраняется в store (свойство ноды, может меняться при rescheduling).
type ServerConfigResponse struct {
	Config       ServerConfig `json:"config"`
	DCOAvailable bool         `json:"dco_available"`
}

// defaultServerConfig — дефолты при первом запуске (store пустой).
// Подобраны под текущие production-значения чтобы upgrade не ломал клиентов.
func defaultServerConfig() ServerConfig {
	return ServerConfig{
		Proto:             "tcp",
		Port:              1194,
		Network:           "172.16.100.0",
		NetworkMask:       "255.255.255.0",
		TunMTU:            1500,
		MssFix:            1450,
		DataCiphers:       []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"},
		TLSVersionMin:     "1.2",
		TLSAuthMode:       "tls-auth",
		DCOEnabled:        true,
		KeepaliveInterval: 10,
		KeepaliveTimeout:  60,
		MaxClients:        0,
		ClientToClient:    true,
		DuplicateCN:       true,
		Compression:       "",
		Verb:              3,
		RedirectGateway:   false,
		DNSServers:        []string{"1.1.1.1", "8.8.8.8"},
		PushExtra:         []string{},
		CustomDirectives:  []string{},
	}
}

// serverConfigStore — потокобезопасный держатель ServerConfig.
type serverConfigStore struct {
	mu  sync.RWMutex
	cfg ServerConfig
}

func newServerConfigStore() *serverConfigStore {
	return &serverConfigStore{cfg: defaultServerConfig()}
}

func (s *serverConfigStore) snapshot() ServerConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.cfg
	out.DataCiphers = append([]string(nil), s.cfg.DataCiphers...)
	out.DNSServers = append([]string(nil), s.cfg.DNSServers...)
	out.PushExtra = append([]string(nil), s.cfg.PushExtra...)
	out.CustomDirectives = append([]string(nil), s.cfg.CustomDirectives...)
	return out
}

func (s *serverConfigStore) replace(cfg ServerConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.DataCiphers == nil {
		cfg.DataCiphers = []string{}
	}
	if cfg.DNSServers == nil {
		cfg.DNSServers = []string{}
	}
	if cfg.PushExtra == nil {
		cfg.PushExtra = []string{}
	}
	if cfg.CustomDirectives == nil {
		cfg.CustomDirectives = []string{}
	}
	s.cfg = cfg
}
```

- [ ] **Step 4: GREEN**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -race -run TestDefaultServerConfig -v ./...`
Expected: PASS.

- [ ] **Step 5: Build + полный suite**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && gofmt -d server_config.go server_config_test.go && go build ./... && go test -race ./...`
Expected: gofmt clean, build OK, all 71+ существующих тестов проходят + 1 новый.

- [ ] **Step 6: Commit**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin
git add server_config.go server_config_test.go
git commit -m "feat(server-config): add ServerConfig types and defaults"
```

---

## Task 2: Store с RWMutex + snapshot deep-copy

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config_test.go`

- [ ] **Step 1: Тесты на store (RED)**

Append to `/Users/alexp/GolandProjects/ovpn-admin/server_config_test.go`:

```go
import (
	"sync"
	"testing"
)

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
```

- [ ] **Step 2: Прогнать**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -race -run TestServerConfigStore -v ./...`
Expected: 4 PASS.

- [ ] **Step 3: Build full**

Run: `go build ./... && go test -race ./...`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add server_config_test.go
git commit -m "test(server-config): store concurrent access and snapshot isolation"
```

---

## Task 3: Validation

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config.go`
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config_test.go`

- [ ] **Step 1: Тесты validation (RED)**

Append to `server_config_test.go`:

```go
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
	cfg.MssFix = 0 // disabled — OK
	if err := validateServerConfig(cfg); err != nil {
		t.Errorf("MssFix=0 must be OK (disabled)")
	}
	cfg.MssFix = 50 // < 100 — error
	if err := validateServerConfig(cfg); err == nil {
		t.Error("MssFix < 100 must fail")
	}
}

func TestValidateServerConfig_DataCipherWhitelist(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.DataCiphers = []string{"BF-CBC"} // обсолетная
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
	cfg.KeepaliveTimeout = 50 // timeout < interval — invalid
	if err := validateServerConfig(cfg); err == nil {
		t.Error("KeepaliveTimeout must be > KeepaliveInterval")
	}
}
```

- [ ] **Step 2: RED**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run TestValidateServerConfig -v ./...`
Expected: `undefined: validateServerConfig`.

- [ ] **Step 3: Имплементация валидации в `server_config.go`**

Append to `server_config.go`:

```go
import (
	"fmt"
	"net"
	"strings"
)

var allowedDataCiphers = map[string]struct{}{
	"AES-256-GCM":         {},
	"AES-128-GCM":         {},
	"CHACHA20-POLY1305":   {},
	"AES-256-CBC":         {},
	"AES-128-CBC":         {},
}

var allowedTLSVersions = map[string]struct{}{
	"1.2": {}, "1.3": {},
}

var allowedTLSAuthModes = map[string]struct{}{
	"tls-auth": {}, "tls-crypt": {},
}

var allowedCompressionModes = map[string]struct{}{
	"": {}, "lz4-v2": {}, "lzo": {},
}

// Префиксы разрешённых директив для CustomDirectives и PushExtra.
// Whitelist по строгому prefix match — недостающие префиксы → reject.
// Phase 1: только безопасные сетевые директивы. ЗАПРЕЩЕНЫ: script-*, up, down,
// plugin, ipchange, setenv-safe, learn-address.
var allowedDirectivePrefixes = []string{
	"route ",
	"route-nopull",
	"topology ",
	"mtu-test",
	"fragment ",
	"tun-mtu-extra ",
	"tx-queue-len ",
	"fast-io",
	"explicit-exit-notify",
	"sndbuf ",
	"rcvbuf ",
}

func validateServerConfig(cfg ServerConfig) error {
	if cfg.Proto != "udp" && cfg.Proto != "tcp" {
		return fmt.Errorf("proto must be udp or tcp, got %q", cfg.Proto)
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port must be 1..65535, got %d", cfg.Port)
	}
	if net.ParseIP(cfg.Network) == nil {
		return fmt.Errorf("network %q is not a valid IP", cfg.Network)
	}
	if net.ParseIP(cfg.NetworkMask) == nil {
		return fmt.Errorf("network_mask %q is not a valid mask", cfg.NetworkMask)
	}
	if cfg.TunMTU < 576 || cfg.TunMTU > 9000 {
		return fmt.Errorf("tun_mtu must be 576..9000, got %d", cfg.TunMTU)
	}
	if cfg.MssFix != 0 && (cfg.MssFix < 100 || cfg.MssFix > 9000) {
		return fmt.Errorf("mss_fix must be 0 (off) or 100..9000, got %d", cfg.MssFix)
	}
	if len(cfg.DataCiphers) == 0 {
		return fmt.Errorf("data_ciphers must not be empty")
	}
	for _, c := range cfg.DataCiphers {
		if _, ok := allowedDataCiphers[c]; !ok {
			return fmt.Errorf("data_ciphers contains unsupported %q", c)
		}
	}
	if _, ok := allowedTLSVersions[cfg.TLSVersionMin]; !ok {
		return fmt.Errorf("tls_version_min must be 1.2 or 1.3, got %q", cfg.TLSVersionMin)
	}
	if _, ok := allowedTLSAuthModes[cfg.TLSAuthMode]; !ok {
		return fmt.Errorf("tls_auth_mode must be tls-auth or tls-crypt, got %q", cfg.TLSAuthMode)
	}
	if cfg.KeepaliveInterval < 1 || cfg.KeepaliveInterval > 3600 {
		return fmt.Errorf("keepalive_interval must be 1..3600, got %d", cfg.KeepaliveInterval)
	}
	if cfg.KeepaliveTimeout <= cfg.KeepaliveInterval || cfg.KeepaliveTimeout > 86400 {
		return fmt.Errorf("keepalive_timeout must be > interval and ≤ 86400, got %d", cfg.KeepaliveTimeout)
	}
	if cfg.MaxClients < 0 {
		return fmt.Errorf("max_clients must be ≥ 0")
	}
	if _, ok := allowedCompressionModes[cfg.Compression]; !ok {
		return fmt.Errorf("compression must be empty, lz4-v2, or lzo")
	}
	if cfg.Verb < 0 || cfg.Verb > 11 {
		return fmt.Errorf("verb must be 0..11, got %d", cfg.Verb)
	}
	for _, ip := range cfg.DNSServers {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("dns_servers contains invalid IP %q", ip)
		}
	}
	for _, line := range cfg.CustomDirectives {
		if err := validateDirectiveLine(line); err != nil {
			return fmt.Errorf("custom_directives: %w", err)
		}
	}
	for _, line := range cfg.PushExtra {
		if err := validateDirectiveLine(line); err != nil {
			return fmt.Errorf("push_extra: %w", err)
		}
	}
	return nil
}

func validateDirectiveLine(line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	for _, prefix := range allowedDirectivePrefixes {
		if line == strings.TrimSpace(prefix) || strings.HasPrefix(line, prefix) {
			return nil
		}
	}
	return fmt.Errorf("directive %q is not in whitelist", line)
}
```

- [ ] **Step 4: GREEN**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -race -run TestValidateServerConfig -v ./...`
Expected: 11 PASS.

- [ ] **Step 5: Full suite**

Run: `go build ./... && go test -race ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add server_config.go server_config_test.go
git commit -m "feat(server-config): field-level and directive-whitelist validation"
```

---

## Task 4: render server.conf через text/template

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config.go`
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config_test.go`

- [ ] **Step 1: Тесты render (RED)**

Append:

```go
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
	// DCO disabled when DCOAvailable=false
	if strings.Contains(out, "data-channel-offload") {
		t.Errorf("data-channel-offload must not appear when DCOAvailable=false")
	}
}

func TestRenderServerConfig_DCOEnabled(t *testing.T) {
	cfg := defaultServerConfig()
	out, _ := renderServerConfig(cfg, true /* dco available */, false)
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
	out, _ := renderServerConfig(cfg, false, false /* ccd disabled */)
	if strings.Contains(out, "client-config-dir") {
		t.Errorf("client-config-dir must not appear when ccd disabled")
	}
}
```

- [ ] **Step 2: RED**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run TestRenderServerConfig -v ./...`
Expected: `undefined: renderServerConfig`.

- [ ] **Step 3: Имплементация рендера**

Append to `server_config.go`:

```go
import "text/template"

const serverConfTemplate = `# Generated by ovpn-admin at {{ .Cfg.UpdatedAt }}
user nobody
group nogroup

mode server
tls-server
dev tun
proto {{ .Cfg.Proto }}-server
port {{ .Cfg.Port }}
management 127.0.0.1 8989
management-client-auth

tun-mtu {{ .Cfg.TunMTU }}
{{- if gt .Cfg.MssFix 0 }}
mssfix {{ .Cfg.MssFix }}
{{- end }}

keepalive {{ .Cfg.KeepaliveInterval }} {{ .Cfg.KeepaliveTimeout }}
{{- if .Cfg.ClientToClient }}
client-to-client
{{- end }}
{{- if .Cfg.DuplicateCN }}
duplicate-cn
{{- end }}
{{- if gt .Cfg.MaxClients 0 }}
max-clients {{ .Cfg.MaxClients }}
{{- end }}
persist-key
persist-tun

data-ciphers {{ joinCiphers .Cfg.DataCiphers }}
data-ciphers-fallback {{ index .Cfg.DataCiphers 0 }}
tls-version-min {{ .Cfg.TLSVersionMin }}

{{- if and .Cfg.DCOEnabled .DCOAvailable }}
data-channel-offload
{{- end }}

{{- if ne .Cfg.Compression "" }}
compress {{ .Cfg.Compression }}
{{- end }}

server {{ .Cfg.Network }} {{ .Cfg.NetworkMask }}
topology subnet
push "topology subnet"
push "route-metric 9999"

{{- if .Cfg.RedirectGateway }}
push "redirect-gateway def1"
{{- end }}
{{- range $dns := .Cfg.DNSServers }}
push "dhcp-option DNS {{ $dns }}"
{{- end }}
{{- range $line := .Cfg.PushExtra }}
push "{{ $line }}"
{{- end }}

verb {{ .Cfg.Verb }}
ifconfig-pool-persist /tmp/openvpn.ipp
status /tmp/openvpn.status

ca /etc/openvpn/pki/ca.crt
key /etc/openvpn/pki/private/server.key
cert /etc/openvpn/pki/issued/server.crt
dh /etc/openvpn/pki/dh.pem
crl-verify /etc/openvpn/pki/crl.pem
{{- if eq .Cfg.TLSAuthMode "tls-auth" }}
tls-auth /etc/openvpn/pki/ta.key
key-direction 0
{{- else }}
tls-crypt /etc/openvpn/pki/ta.key
{{- end }}

{{- if .CcdEnabled }}
client-config-dir /etc/openvpn/ccd
{{- end }}

{{- range $line := .Cfg.CustomDirectives }}
{{ $line }}
{{- end }}
`

type serverConfTemplateData struct {
	Cfg          ServerConfig
	DCOAvailable bool
	CcdEnabled   bool
}

var renderTmpl = template.Must(
	template.New("server.conf").
		Funcs(template.FuncMap{
			"joinCiphers": func(s []string) string { return strings.Join(s, ":") },
		}).
		Parse(serverConfTemplate),
)

func renderServerConfig(cfg ServerConfig, dcoAvailable, ccdEnabled bool) (string, error) {
	var buf strings.Builder
	data := serverConfTemplateData{
		Cfg:          cfg,
		DCOAvailable: dcoAvailable,
		CcdEnabled:   ccdEnabled,
	}
	if err := renderTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render server.conf: %w", err)
	}
	return buf.String(), nil
}
```

- [ ] **Step 4: GREEN**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -race -run TestRenderServerConfig -v ./...`
Expected: 9 PASS.

- [ ] **Step 5: Полный suite**

Run: `go build ./... && go test -race ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add server_config.go server_config_test.go
git commit -m "feat(server-config): render server.conf via text/template"
```

---

## Task 5: DCO auto-detect

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config.go`
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config_test.go`

- [ ] **Step 1: Тесты с моком файлсистемы и exec (RED)**

Append:

```go
import "os"

func TestDetectDCOSupport_NoModule(t *testing.T) {
	// detectDCOSupport() reads /sys/module/ovpn — на dev-машине его нет (macOS).
	// Эта проверка просто гарантирует что функция не паникует и возвращает false.
	available := detectDCOSupport()
	// На macOS гарантированно false.
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
```

- [ ] **Step 2: RED**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run TestDetectDCOSupport -v ./...`
Expected: `undefined: detectDCOSupport`.

- [ ] **Step 3: Имплементация**

Append to `server_config.go`:

```go
import (
	"os/exec"
)

// detectDCOSupport проверяет загружен ли в ядре модуль `ovpn` (mainline 6.16+)
// или out-of-tree `ovpn_dco`. Вызывается один раз при старте ovpn-admin.
//
// Шаги:
//   1. /sys/module/ovpn существует → true
//   2. /sys/module/ovpn_dco существует → true
//   3. modprobe ovpn — лучшеподходит если у нас есть NET_ADMIN; затем (1)
//   4. openvpn --version содержит "[DCO]" → значит userspace fallback тоже OK, но это не kernel DCO
func detectDCOSupport() bool {
	if _, err := os.Stat("/sys/module/ovpn"); err == nil {
		return true
	}
	if _, err := os.Stat("/sys/module/ovpn_dco"); err == nil {
		return true
	}
	// Попытка загрузить модуль (требует NET_ADMIN + доступа к /lib/modules)
	_ = exec.Command("modprobe", "ovpn").Run()
	if _, err := os.Stat("/sys/module/ovpn"); err == nil {
		return true
	}
	return false
}
```

- [ ] **Step 4: GREEN**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -race -run TestDetectDCOSupport -v ./...`
Expected: PASS (на macOS — `available=false`, no error).

- [ ] **Step 5: Commit**

```bash
git add server_config.go server_config_test.go
git commit -m "feat(server-config): DCO kernel-module auto-detection"
```

---

## Task 6: change categorization (soft/hard)

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config.go`
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config_test.go`

- [ ] **Step 1: Тесты categorizeChanges (RED)**

Append:

```go
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
	new.Verb = 5      // soft
	new.Port = 8443   // hard
	if got := categorizeChanges(old, new); got != "hard" {
		t.Errorf("hard must win over soft, got %q", got)
	}
}
```

- [ ] **Step 2: RED**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run TestCategorizeChanges -v ./...`
Expected: undefined.

- [ ] **Step 3: Имплементация**

Append:

```go
import "reflect"

// categorizeChanges возвращает "none" | "soft" | "hard" в зависимости от того
// какие поля изменились. Если затронуто хотя бы одно "hard" поле — возвращает "hard".
func categorizeChanges(old, new ServerConfig) string {
	hard := false
	soft := false

	hardCheckers := []func() bool{
		func() bool { return old.Proto != new.Proto },
		func() bool { return old.Port != new.Port },
		func() bool { return old.TunMTU != new.TunMTU },
		func() bool { return old.MssFix != new.MssFix },
		func() bool { return !reflect.DeepEqual(old.DataCiphers, new.DataCiphers) },
		func() bool { return old.TLSVersionMin != new.TLSVersionMin },
		func() bool { return old.TLSAuthMode != new.TLSAuthMode },
		func() bool { return old.DCOEnabled != new.DCOEnabled },
		func() bool { return old.Compression != new.Compression },
		func() bool { return old.ClientToClient != new.ClientToClient },
		func() bool { return old.DuplicateCN != new.DuplicateCN },
		func() bool { return old.Network != new.Network },
		func() bool { return old.NetworkMask != new.NetworkMask },
	}
	for _, f := range hardCheckers {
		if f() {
			hard = true
			break
		}
	}

	if !hard {
		softCheckers := []func() bool{
			func() bool { return old.Verb != new.Verb },
			func() bool { return !reflect.DeepEqual(old.DNSServers, new.DNSServers) },
			func() bool { return old.RedirectGateway != new.RedirectGateway },
			func() bool { return old.KeepaliveInterval != new.KeepaliveInterval },
			func() bool { return old.KeepaliveTimeout != new.KeepaliveTimeout },
			func() bool { return old.MaxClients != new.MaxClients },
			func() bool { return !reflect.DeepEqual(old.PushExtra, new.PushExtra) },
			func() bool { return !reflect.DeepEqual(old.CustomDirectives, new.CustomDirectives) },
		}
		for _, f := range softCheckers {
			if f() {
				soft = true
				break
			}
		}
	}

	if hard {
		return "hard"
	}
	if soft {
		return "soft"
	}
	return "none"
}
```

- [ ] **Step 4: GREEN**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -race -run TestCategorizeChanges -v ./...`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add server_config.go server_config_test.go
git commit -m "feat(server-config): categorize soft/hard reload changes"
```

---

## Task 7: Persistence — JSON-файл + K8s Secret

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config.go`
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/kubernetes.go` — добавить k8s helpers
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config_test.go`

- [ ] **Step 1: Тесты persist (RED)**

Append:

```go
import (
	"path/filepath"
)

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
```

- [ ] **Step 2: RED**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run "TestServerConfig_FilePersist|TestServerConfig_AtomicWrite|TestServerConfig_Serialize|TestServerConfig_Deserialize" -v ./...`
Expected: undefined.

- [ ] **Step 3: Имплементация persistence**

Append to `server_config.go`:

```go
import "encoding/json"

const serverConfigSecretName = "ovpn-admin-server-config"
const serverConfigSecretKey = "data"

func serializeServerConfig(cfg ServerConfig) ([]byte, error) {
	if cfg.DataCiphers == nil {
		cfg.DataCiphers = []string{}
	}
	if cfg.DNSServers == nil {
		cfg.DNSServers = []string{}
	}
	if cfg.PushExtra == nil {
		cfg.PushExtra = []string{}
	}
	if cfg.CustomDirectives == nil {
		cfg.CustomDirectives = []string{}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func deserializeServerConfig(data []byte) (ServerConfig, error) {
	if len(data) == 0 {
		return defaultServerConfig(), nil
	}
	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ServerConfig{}, err
	}
	if cfg.DataCiphers == nil {
		cfg.DataCiphers = []string{}
	}
	if cfg.DNSServers == nil {
		cfg.DNSServers = []string{}
	}
	if cfg.PushExtra == nil {
		cfg.PushExtra = []string{}
	}
	if cfg.CustomDirectives == nil {
		cfg.CustomDirectives = []string{}
	}
	return cfg, nil
}

func loadServerConfigFromFile(path string) (ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultServerConfig(), nil
		}
		return ServerConfig{}, err
	}
	return deserializeServerConfig(data)
}

func saveServerConfigToFile(path string, cfg ServerConfig) error {
	data, err := serializeServerConfig(cfg)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
```

- [ ] **Step 4: K8s helpers в `kubernetes.go`**

Append to `kubernetes.go` (после `secretUpdateCommonRoutes`):

```go
func (openVPNPKI *OpenVPNPKI) secretGetServerConfig() ([]byte, error) {
	secret, err := openVPNPKI.secretGetByName(serverConfigSecretName)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, err
	}
	return secret.Data[serverConfigSecretKey], nil
}

func (openVPNPKI *OpenVPNPKI) secretUpdateServerConfig(data []byte) error {
	secret, err := openVPNPKI.secretGetByName(serverConfigSecretName)
	if err != nil && strings.Contains(err.Error(), "not found") {
		objectMeta := metav1.ObjectMeta{
			Name: serverConfigSecretName,
			Labels: map[string]string{
				labelKeyType:      "server-config",
				labelKeyManagedBy: labelValueManagedByApp,
			},
		}
		return openVPNPKI.secretCreate(objectMeta, map[string][]byte{serverConfigSecretKey: data}, v1.SecretTypeOpaque)
	}
	if err != nil {
		return err
	}
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data[serverConfigSecretKey] = data
	return openVPNPKI.secretUpdate(secret.ObjectMeta, secret.Data, v1.SecretTypeOpaque)
}
```

- [ ] **Step 5: GREEN**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -race -run "TestServerConfig_FilePersist|TestServerConfig_AtomicWrite|TestServerConfig_Serialize|TestServerConfig_Deserialize" -v ./...`
Expected: 5 PASS.

- [ ] **Step 6: Build + full**

Run: `go build ./... && go test -race ./...`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add server_config.go kubernetes.go server_config_test.go
git commit -m "feat(server-config): filesystem and k8s.secrets persistence"
```

---

## Task 8: Manager — soft/hard reload через mgmt-interface

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config.go`
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config_test.go`

- [ ] **Step 1: Тесты manager'а с мок mgmt-conn (RED)**

Append:

```go
import (
	"context"
	"net"
	"time"
)

// fakeMgmtServer — мок OpenVPN management-interface для тестов.
// Принимает TCP-подключения, отдаёт welcome-line и подтверждение на signal-команды.
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
	mgr := &serverManager{mgmtAddr: "127.0.0.1:0"} // невалидный addr
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
```

- [ ] **Step 2: RED**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run TestServerManager -v ./...`
Expected: undefined `serverManager`.

- [ ] **Step 3: Имплементация manager'а**

Append to `server_config.go`:

```go
import (
	"bufio"
	"time"
)

// serverManager — координирует render + reload openvpn-процесса.
type serverManager struct {
	store         *serverConfigStore
	storagePath   string // JSON file path (filesystem backend)
	mgmtAddr      string // 127.0.0.1:8989
	confPath      string // /etc/openvpn/server.conf
	dcoAvailable  bool
	ccdEnabled    bool
}

func (m *serverManager) softReload() error {
	return m.sendSignal("SIGHUP")
}

// sendSignal посылает указанный сигнал через OpenVPN management-interface.
func (m *serverManager) sendSignal(sig string) error {
	conn, err := net.DialTimeout("tcp", m.mgmtAddr, 3*time.Second)
	if err != nil {
		return fmt.Errorf("connect mgmt %s: %w", m.mgmtAddr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Read welcome line(s) — OpenVPN may send several >INFO: lines.
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if !strings.HasPrefix(line, ">") {
			break
		}
	}

	if _, err := fmt.Fprintln(conn, "signal "+sig); err != nil {
		return fmt.Errorf("send signal: %w", err)
	}
	// Try to read response (best-effort, not critical for SIGTERM since proc exits)
	resp, _ := reader.ReadString('\n')
	if strings.HasPrefix(resp, "ERROR") {
		return fmt.Errorf("mgmt error: %s", strings.TrimSpace(resp))
	}
	return nil
}

// waitMgmtReady блокируется пока mgmt-interface не примет подключение,
// либо до отмены контекста.
func (m *serverManager) waitMgmtReady(ctx context.Context) error {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		conn, err := net.DialTimeout("tcp", m.mgmtAddr, 1*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("mgmt %s did not become ready: %w", m.mgmtAddr, ctx.Err())
		case <-tick.C:
			// retry
		}
	}
}
```

- [ ] **Step 4: GREEN**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -race -run TestServerManager -v ./...`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add server_config.go server_config_test.go
git commit -m "feat(server-config): serverManager with mgmt-interface signal sender"
```

---

## Task 9: Manager — apply с rollback при hard restart

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config.go`
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config_test.go`

- [ ] **Step 1: Тесты apply (RED)**

Append:

```go
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

	mgr := &serverManager{
		store:       store,
		storagePath: filepath.Join(dir, "store.json"),
		mgmtAddr:    mgmt.addr(),
		confPath:    confPath,
		ccdEnabled:  true,
	}

	cfg := store.snapshot()
	cfg.Verb = 5 // soft change

	kind, err := mgr.apply(context.Background(), cfg, "admin")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if kind != "soft" {
		t.Errorf("expected soft, got %q", kind)
	}
	// SIGHUP должен быть отправлен
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
	// Файл должен быть записан
	if _, err := os.Stat(confPath); err != nil {
		t.Errorf("server.conf not written: %v", err)
	}
}

func TestServerManager_Apply_RejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	store := newServerConfigStore()
	mgr := &serverManager{
		store:       store,
		storagePath: filepath.Join(dir, "store.json"),
		mgmtAddr:    "127.0.0.1:0",
		confPath:    filepath.Join(dir, "server.conf"),
		ccdEnabled:  true,
	}

	cfg := store.snapshot()
	cfg.Port = 99999 // invalid

	_, err := mgr.apply(context.Background(), cfg, "admin")
	if err == nil {
		t.Error("expected validation error")
	}
}
```

- [ ] **Step 2: RED**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run TestServerManager_Apply -v ./...`
Expected: `apply` undefined.

- [ ] **Step 3: Имплементация apply**

Append to `server_config.go`:

```go
// apply применяет новый конфиг: валидирует, рендерит, сохраняет, перезагружает.
// Возвращает kind ("none"|"soft"|"hard"|"rolled-back") и ошибку.
//
// Для hard reload — ждёт mgmtAddr 15 секунд; при таймауте делает rollback на
// предыдущий config и повторяет SIGTERM.
func (m *serverManager) apply(ctx context.Context, newCfg ServerConfig, updatedBy string) (string, error) {
	if err := validateServerConfig(newCfg); err != nil {
		return "", fmt.Errorf("validate: %w", err)
	}

	current := m.store.snapshot()
	kind := categorizeChanges(current, newCfg)
	if kind == "none" {
		return "none", nil
	}

	newCfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	newCfg.UpdatedBy = updatedBy

	rendered, err := renderServerConfig(newCfg, m.dcoAvailable, m.ccdEnabled)
	if err != nil {
		return "", err
	}
	if err := writeFileAtomic(m.confPath, []byte(rendered)); err != nil {
		return "", fmt.Errorf("write conf: %w", err)
	}

	// Сохраняем в store + persistent storage
	backup := current
	m.store.replace(newCfg)
	if err := m.persist(newCfg); err != nil {
		log.Warnf("apply: persist failed: %v", err)
	}

	switch kind {
	case "soft":
		if err := m.softReload(); err != nil {
			log.Warnf("soft reload (SIGHUP) failed: %v — config saved, will pick up at next restart", err)
		}
		return "soft", nil
	case "hard":
		if err := m.sendSignal("SIGTERM"); err != nil {
			// mgmt unreachable — может быть, openvpn уже падает или ещё не стартанул.
			log.Warnf("SIGTERM via mgmt failed: %v", err)
		}
		// Ждём пока openvpn вернётся (kubelet/supervisor рестартанёт container)
		waitCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := m.waitMgmtReady(waitCtx); err != nil {
			log.Warnf("openvpn did not come back after %v — rolling back to previous config", 15*time.Second)
			return m.rollback(backup, updatedBy)
		}
		return "hard", nil
	}
	return kind, nil
}

func (m *serverManager) rollback(backup ServerConfig, updatedBy string) (string, error) {
	backup.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	backup.UpdatedBy = updatedBy + " (rollback)"

	rendered, err := renderServerConfig(backup, m.dcoAvailable, m.ccdEnabled)
	if err != nil {
		return "rolled-back", fmt.Errorf("rollback render: %w", err)
	}
	if err := writeFileAtomic(m.confPath, []byte(rendered)); err != nil {
		return "rolled-back", err
	}
	m.store.replace(backup)
	_ = m.persist(backup)
	_ = m.sendSignal("SIGTERM")
	return "rolled-back", fmt.Errorf("new config invalid (openvpn did not restart); rolled back to previous version")
}

func (m *serverManager) persist(cfg ServerConfig) error {
	if *storageBackend == "kubernetes.secrets" {
		data, err := serializeServerConfig(cfg)
		if err != nil {
			return err
		}
		return app.secretUpdateServerConfig(data)
	}
	return saveServerConfigToFile(m.storagePath, cfg)
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
```

- [ ] **Step 4: GREEN**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -race -run TestServerManager_Apply -v ./...`
Expected: 3 PASS.

- [ ] **Step 5: Build + full**

Run: `go build ./... && go test -race ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add server_config.go server_config_test.go
git commit -m "feat(server-config): apply with validate/render/reload/rollback"
```

---

## Task 10: HTTP handlers

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config.go`
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config_test.go`

- [ ] **Step 1: Тесты handlers (RED)**

Append:

```go
import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

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
	// Force filesystem backend for tests
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
	// Config in store must NOT have changed (dry run)
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
```

- [ ] **Step 2: RED**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run TestServerConfigHandler -v ./...`
Expected: undefined methods.

- [ ] **Step 3: Добавить поля в OvpnAdmin struct (`main.go`)**

В `main.go` (~line 187, struct `OvpnAdmin`) добавить:
```go
type OvpnAdmin struct {
    // ... existing ...
    serverConfigStore *serverConfigStore
    serverManager     *serverManager
}
```

- [ ] **Step 4: Имплементация handlers**

Append to `server_config.go`:

```go
import "net/http"

func (oAdmin *OvpnAdmin) serverConfigHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	switch r.Method {
	case http.MethodGet:
		resp := ServerConfigResponse{
			Config:       oAdmin.serverConfigStore.snapshot(),
			DCOAvailable: oAdmin.serverManager.dcoAvailable,
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPut:
		if oAdmin.role == "slave" {
			http.Error(w, `{"status":"error","message":"slave is read-only"}`, http.StatusLocked)
			return
		}
		var cfg ServerConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		updatedBy := "admin" // TODO: lift from auth context once available
		kind, err := oAdmin.serverManager.apply(r.Context(), cfg, updatedBy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"config":      oAdmin.serverConfigStore.snapshot(),
			"reload_kind": kind,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (oAdmin *OvpnAdmin) serverConfigTestHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var cfg ServerConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateServerConfig(cfg); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"valid":  false,
			"errors": []string{err.Error()},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"valid": true, "errors": []string{}})
}

func (oAdmin *OvpnAdmin) serverConfigDefaultsHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	writeJSON(w, http.StatusOK, defaultServerConfig())
}
```

`writeJSON` уже определён в `common_routes.go`.

- [ ] **Step 5: GREEN**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -race -run TestServerConfigHandler -v ./...`
Expected: 6 PASS.

- [ ] **Step 6: Commit**

```bash
git add server_config.go server_config_test.go main.go
git commit -m "feat(server-config): HTTP handlers (GET/PUT/test/defaults)"
```

---

## Task 11: Wiring в `main.go` — init + регистрация роутов + render at startup

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/main.go`

- [ ] **Step 1: Добавить CLI флаги**

В `var (...)` блок:

```go
serverConfigEnabled = kingpin.Flag("server-config",
	"enable editable server config UI feature").
	Default("true").Envar("OVPN_SERVER_CONFIG").Bool()

serverConfigPath = kingpin.Flag("server-config.conf-path",
	"path where ovpn-admin writes the rendered server.conf").
	Default("/etc/openvpn/server.conf").Envar("OVPN_SERVER_CONFIG_PATH").String()
```

- [ ] **Step 2: Init в main() — после init common-routes**

В `main()` после блока `if *commonRoutesEnabled { ... }`:

```go
if *serverConfigEnabled {
	ovpnAdmin.modules = append(ovpnAdmin.modules, "server-config")

	storagePath := *ccdDir + "/_server_config.json"

	// Load persisted state (или defaults)
	ovpnAdmin.serverConfigStore = newServerConfigStore()
	var initial ServerConfig
	if *storageBackend == "kubernetes.secrets" {
		data, err := app.secretGetServerConfig()
		if err != nil {
			log.Warnf("load server config from secret: %v (using defaults)", err)
			initial = defaultServerConfig()
		} else {
			c, err := deserializeServerConfig(data)
			if err != nil {
				log.Warnf("deserialize server config: %v (using defaults)", err)
				initial = defaultServerConfig()
			} else {
				initial = c
			}
		}
	} else {
		c, err := loadServerConfigFromFile(storagePath)
		if err != nil {
			log.Warnf("load server config from %s: %v (using defaults)", storagePath, err)
			initial = defaultServerConfig()
		} else {
			initial = c
		}
	}
	ovpnAdmin.serverConfigStore.replace(initial)

	dcoAvailable := detectDCOSupport()
	log.Infof("server-config: DCO support detected: %v", dcoAvailable)

	mgmtAddr, ok := ovpnAdmin.mgmtInterfaces["main"]
	if !ok {
		mgmtAddr = "127.0.0.1:8989"
	}

	ovpnAdmin.serverManager = &serverManager{
		store:        ovpnAdmin.serverConfigStore,
		storagePath:  storagePath,
		mgmtAddr:     mgmtAddr,
		confPath:     *serverConfigPath,
		dcoAvailable: dcoAvailable,
		ccdEnabled:   *ccdEnabled,
	}

	// Render initial server.conf at startup (openvpn-container waits for this file)
	rendered, err := renderServerConfig(initial, dcoAvailable, *ccdEnabled)
	if err != nil {
		log.Fatalf("server-config: initial render failed: %v", err)
	}
	if err := writeFileAtomic(*serverConfigPath, []byte(rendered)); err != nil {
		log.Warnf("server-config: cannot write initial %s: %v (openvpn-container won't start)", *serverConfigPath, err)
	} else {
		log.Infof("server-config: rendered initial config to %s", *serverConfigPath)
	}
}
```

- [ ] **Step 3: Регистрация HTTP роутов**

В `main()` рядом с другими `http.HandleFunc` (после common-routes роутов):

```go
http.HandleFunc(*listenBaseUrl+"api/server-config",          ovpnAdmin.requireAuth(ovpnAdmin.serverConfigHandler))
http.HandleFunc(*listenBaseUrl+"api/server-config/test",     ovpnAdmin.requireAuth(ovpnAdmin.serverConfigTestHandler))
http.HandleFunc(*listenBaseUrl+"api/server-config/defaults", ovpnAdmin.requireAuth(ovpnAdmin.serverConfigDefaultsHandler))
```

- [ ] **Step 4: Build + tests**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go build ./... && go test -race ./...`
Expected: clean, all tests pass.

- [ ] **Step 5: Smoke local binary — флаги**

```bash
go build -o /tmp/ovpn-admin-sc . && /tmp/ovpn-admin-sc --help 2>&1 | grep -E "server-config" | head && rm /tmp/ovpn-admin-sc
```
Expected: видим `--server-config`, `--server-config.conf-path`.

- [ ] **Step 6: Commit**

```bash
git add main.go
git commit -m "feat(server-config): wire flags, init, render-at-startup, HTTP routes"
```

---

## Task 12: Frontend api.js

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/frontend/src/api.js`

- [ ] **Step 1: Append API functions**

```js
export async function fetchServerConfig() {
  const { data } = await axios.get('api/server-config')
  return data // { config, dco_available }
}

export async function updateServerConfig(cfg) {
  const { data } = await axios.put('api/server-config', JSON.stringify(cfg), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data // { config, reload_kind }
}

export async function testServerConfig(cfg) {
  const { data } = await axios.post('api/server-config/test', JSON.stringify(cfg), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data // { valid, errors }
}

export async function fetchServerConfigDefaults() {
  const { data } = await axios.get('api/server-config/defaults')
  return data
}
```

- [ ] **Step 2: Build**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin/frontend && npm run build
```
Expected: clean.

- [ ] **Step 3: Commit**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin
git add frontend/src/api.js
git commit -m "feat(server-config): frontend API functions"
```

---

## Task 13: Frontend — SectionCard reusable component

**Files:**
- Create: `/Users/alexp/GolandProjects/ovpn-admin/frontend/src/components/server-config/SectionCard.vue`

- [ ] **Step 1: Создать**

```vue
<!-- frontend/src/components/server-config/SectionCard.vue -->
<script setup>
import { ref } from 'vue'
import { ChevronDown, ChevronRight } from 'lucide-vue-next'

const props = defineProps({
  title: { type: String, required: true },
  description: { type: String, default: '' },
  defaultOpen: { type: Boolean, default: true },
})

const open = ref(props.defaultOpen)
</script>

<template>
  <div class="rounded-lg border border-border bg-card overflow-hidden">
    <button
      type="button"
      class="w-full flex items-center justify-between px-4 py-3 hover:bg-muted/50 transition-colors"
      @click="open = !open"
    >
      <div class="text-left">
        <p class="text-sm font-semibold">{{ title }}</p>
        <p v-if="description" class="text-xs text-muted-foreground mt-0.5">{{ description }}</p>
      </div>
      <component :is="open ? ChevronDown : ChevronRight" :size="16" class="text-muted-foreground" />
    </button>
    <div v-if="open" class="border-t border-border p-4 space-y-3">
      <slot />
    </div>
  </div>
</template>
```

- [ ] **Step 2: Build**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin/frontend && npm run build
```
Expected: clean.

- [ ] **Step 3: Commit**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin
git add frontend/src/components/server-config/SectionCard.vue
git commit -m "feat(server-config): SectionCard collapsible component"
```

---

## Task 14: Frontend — ChipInput для DNS / DataCiphers

**Files:**
- Create: `/Users/alexp/GolandProjects/ovpn-admin/frontend/src/components/server-config/ChipInput.vue`

- [ ] **Step 1: Создать**

```vue
<!-- frontend/src/components/server-config/ChipInput.vue -->
<script setup>
import { ref } from 'vue'
import Input from '@/components/ui/Input.vue'
import { X } from 'lucide-vue-next'

const props = defineProps({
  modelValue: { type: Array, default: () => [] },
  placeholder: { type: String, default: '' },
  validator: { type: Function, default: () => true },
})
const emit = defineEmits(['update:modelValue'])

const draft = ref('')

function addChip() {
  const v = draft.value.trim()
  if (!v) return
  if (!props.validator(v)) return
  if (props.modelValue.includes(v)) {
    draft.value = ''
    return
  }
  emit('update:modelValue', [...props.modelValue, v])
  draft.value = ''
}

function removeChip(i) {
  const next = props.modelValue.slice()
  next.splice(i, 1)
  emit('update:modelValue', next)
}
</script>

<template>
  <div class="space-y-2">
    <div class="flex flex-wrap gap-1.5">
      <span
        v-for="(chip, i) in modelValue"
        :key="chip"
        class="inline-flex items-center gap-1 rounded-md bg-secondary px-2 py-0.5 text-xs font-mono"
      >
        {{ chip }}
        <button type="button" class="text-muted-foreground hover:text-destructive" @click="removeChip(i)">
          <X :size="12" />
        </button>
      </span>
    </div>
    <Input
      v-model="draft"
      :placeholder="placeholder"
      class="font-mono"
      @keydown.enter.prevent="addChip"
      @keydown.,.prevent="addChip"
      @blur="addChip"
    />
  </div>
</template>
```

- [ ] **Step 2: Build**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin/frontend && npm run build
```

- [ ] **Step 3: Commit**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin
git add frontend/src/components/server-config/ChipInput.vue
git commit -m "feat(server-config): ChipInput component for DNS/cipher lists"
```

---

## Task 15: Frontend — ServerConfigView (главная страница)

**Files:**
- Create: `/Users/alexp/GolandProjects/ovpn-admin/frontend/src/components/ServerConfigView.vue`

- [ ] **Step 1: Создать**

```vue
<!-- frontend/src/components/ServerConfigView.vue -->
<script setup>
import { ref, onMounted, computed } from 'vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'
import SectionCard from '@/components/server-config/SectionCard.vue'
import ChipInput from '@/components/server-config/ChipInput.vue'
import { useToast } from '@/composables/useToast'
import {
  fetchServerConfig, updateServerConfig, fetchServerConfigDefaults,
} from '@/api.js'
import { Save, RotateCcw, AlertTriangle, CheckCircle2 } from 'lucide-vue-next'

const props = defineProps({
  serverRole: { type: String, default: 'master' },
})

const cfg = ref(null)
const dcoAvailable = ref(false)
const loading = ref(false)
const submitting = ref(false)

const { toast: _toast } = useToast()
function notify(title, variant = 'default') { _toast({ title, variant }) }

const isMaster = computed(() => props.serverRole === 'master')

const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/

const dataCipherChoices = ['AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305', 'AES-256-CBC', 'AES-128-CBC']

async function reload() {
  loading.value = true
  try {
    const data = await fetchServerConfig()
    cfg.value = data.config
    dcoAvailable.value = data.dco_available
  } finally { loading.value = false }
}

async function save() {
  if (submitting.value) return
  submitting.value = true
  try {
    const r = await updateServerConfig(cfg.value)
    cfg.value = r.config
    if (r.reload_kind === 'hard') {
      notify('Сохранено. OpenVPN перезапущен — клиенты переподключатся.', 'success')
    } else if (r.reload_kind === 'soft') {
      notify('Сохранено. Изменения применены без рестарта.', 'success')
    } else {
      notify('Изменений нет', 'default')
    }
  } catch (e) {
    notify(`Ошибка: ${e.response?.data || e.message}`, 'destructive')
  } finally { submitting.value = false }
}

async function resetToDefaults() {
  if (!confirm('Сбросить все настройки сервера к дефолтам?')) return
  const def = await fetchServerConfigDefaults()
  cfg.value = def
}

function toggleCipher(c) {
  const idx = cfg.value.data_ciphers.indexOf(c)
  if (idx === -1) cfg.value.data_ciphers.push(c)
  else cfg.value.data_ciphers.splice(idx, 1)
}

onMounted(reload)
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-start justify-between">
      <div>
        <p class="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-1">Сервер</p>
        <p class="text-sm text-muted-foreground max-w-2xl">
          Параметры OpenVPN-сервера. Изменения part применяются hot (push routes, verb, keepalive),
          часть требует перезапуска openvpn-процесса (port, proto, MTU, шифр, DCO).
        </p>
      </div>
      <div class="flex gap-2">
        <Button v-if="isMaster" variant="secondary" size="sm" @click="resetToDefaults">
          <RotateCcw :size="14" /> Сбросить
        </Button>
        <Button v-if="isMaster" :loading="submitting" :disabled="!cfg" @click="save">
          <Save :size="14" /> Сохранить
        </Button>
      </div>
    </div>

    <div v-if="loading" class="text-sm text-muted-foreground">Загрузка…</div>
    <div v-else-if="cfg" class="space-y-3">
      <!-- DCO status banner -->
      <div
        :class="[
          'rounded-md border px-3 py-2 text-sm flex items-center gap-2',
          dcoAvailable
            ? 'border-green-500/30 bg-green-500/5 text-green-700 dark:text-green-300'
            : 'border-yellow-500/30 bg-yellow-500/5 text-yellow-700 dark:text-yellow-300'
        ]"
      >
        <CheckCircle2 v-if="dcoAvailable" :size="16" />
        <AlertTriangle v-else :size="16" />
        <span>
          <strong>DCO (kernel offload):</strong>
          {{ dcoAvailable ? 'доступен на этой ноде' : 'не загружен kernel-модуль ovpn — toggle ниже неактивен' }}
        </span>
      </div>

      <!-- Section 1: Network / transport -->
      <SectionCard title="Сеть и транспорт" description="Протокол, порт, MTU, подсеть VPN">
        <div class="grid grid-cols-2 gap-3">
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Proto</span>
            <select v-model="cfg.proto" :disabled="!isMaster" class="w-full h-9 mt-1 rounded-md border border-border bg-background px-2 text-sm font-mono">
              <option value="udp">UDP (быстрее, рекомендуется)</option>
              <option value="tcp">TCP</option>
            </select>
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Port</span>
            <Input v-model.number="cfg.port" type="number" :disabled="!isMaster" class="font-mono mt-1" />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Network</span>
            <Input v-model="cfg.network" :disabled="!isMaster" class="font-mono mt-1" />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Network mask</span>
            <Input v-model="cfg.network_mask" :disabled="!isMaster" class="font-mono mt-1" />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">tun-mtu (576–9000)</span>
            <Input v-model.number="cfg.tun_mtu" type="number" :disabled="!isMaster" class="font-mono mt-1" />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">mssfix (0=выкл, 100–9000)</span>
            <Input v-model.number="cfg.mss_fix" type="number" :disabled="!isMaster" class="font-mono mt-1" />
          </label>
        </div>
      </SectionCard>

      <!-- Section 2: Cryptography -->
      <SectionCard title="Шифрование" description="Cipher, TLS, DCO">
        <div class="space-y-3">
          <div>
            <span class="text-xs text-muted-foreground">Data ciphers (порядок = приоритет NCP)</span>
            <div class="flex flex-wrap gap-1.5 mt-1">
              <button
                v-for="c in dataCipherChoices"
                :key="c"
                type="button"
                :disabled="!isMaster"
                @click="toggleCipher(c)"
                :class="[
                  'inline-flex items-center gap-1 rounded-md border px-2.5 h-7 text-xs font-mono transition-colors',
                  cfg.data_ciphers.includes(c)
                    ? 'border-primary bg-primary text-primary-foreground'
                    : 'border-border bg-background text-muted-foreground hover:bg-accent'
                ]"
              >
                {{ c }}
              </button>
            </div>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <label class="block text-sm">
              <span class="text-xs text-muted-foreground">TLS version min</span>
              <select v-model="cfg.tls_version_min" :disabled="!isMaster" class="w-full h-9 mt-1 rounded-md border border-border bg-background px-2 text-sm font-mono">
                <option value="1.2">1.2</option>
                <option value="1.3">1.3 (рекомендуется)</option>
              </select>
            </label>
            <label class="block text-sm">
              <span class="text-xs text-muted-foreground">TLS auth mode</span>
              <select v-model="cfg.tls_auth_mode" :disabled="!isMaster" class="w-full h-9 mt-1 rounded-md border border-border bg-background px-2 text-sm font-mono">
                <option value="tls-auth">tls-auth (HMAC)</option>
                <option value="tls-crypt">tls-crypt (encrypted, рекомендуется)</option>
              </select>
            </label>
          </div>
          <label class="flex items-center gap-2 text-sm">
            <input type="checkbox" v-model="cfg.dco_enabled" :disabled="!isMaster || !dcoAvailable" />
            DCO (kernel offload) {{ !dcoAvailable ? '— недоступен на этой ноде' : '' }}
          </label>
        </div>
      </SectionCard>

      <!-- Section 3: Behavior -->
      <SectionCard title="Поведение" description="Keepalive, лимиты, логи">
        <div class="grid grid-cols-2 gap-3">
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Keepalive interval (sec)</span>
            <Input v-model.number="cfg.keepalive_interval" type="number" :disabled="!isMaster" class="font-mono mt-1" />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Keepalive timeout (sec)</span>
            <Input v-model.number="cfg.keepalive_timeout" type="number" :disabled="!isMaster" class="font-mono mt-1" />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Max clients (0 = unlimited)</span>
            <Input v-model.number="cfg.max_clients" type="number" :disabled="!isMaster" class="font-mono mt-1" />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Compression</span>
            <select v-model="cfg.compression" :disabled="!isMaster" class="w-full h-9 mt-1 rounded-md border border-border bg-background px-2 text-sm font-mono">
              <option value="">отключено (рекомендуется — VORACLE)</option>
              <option value="lz4-v2">lz4-v2</option>
              <option value="lzo">lzo</option>
            </select>
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Verb (log level 0–11)</span>
            <Input v-model.number="cfg.verb" type="number" :disabled="!isMaster" class="font-mono mt-1" />
          </label>
        </div>
        <div class="flex gap-4 pt-2">
          <label class="inline-flex items-center gap-2 text-sm">
            <input type="checkbox" v-model="cfg.client_to_client" :disabled="!isMaster" />
            client-to-client
          </label>
          <label class="inline-flex items-center gap-2 text-sm">
            <input type="checkbox" v-model="cfg.duplicate_cn" :disabled="!isMaster" />
            duplicate-cn
          </label>
        </div>
      </SectionCard>

      <!-- Section 4: Push to clients -->
      <SectionCard title="Пуш клиентам" description="Маршруты, DNS, gateway">
        <label class="inline-flex items-center gap-2 text-sm">
          <input type="checkbox" v-model="cfg.redirect_gateway" :disabled="!isMaster" />
          redirect-gateway def1 (весь трафик через VPN)
        </label>
        <div>
          <span class="text-xs text-muted-foreground">DNS-серверы (push клиентам)</span>
          <ChipInput
            v-model="cfg.dns_servers"
            placeholder="1.1.1.1 (Enter / запятая)"
            :validator="(v) => ipPattern.test(v)"
          />
        </div>
        <div>
          <span class="text-xs text-muted-foreground">Push extra (одна строка = одна push-директива; whitelist)</span>
          <textarea
            v-model="pushExtraText"
            :disabled="!isMaster"
            rows="3"
            class="w-full mt-1 rounded-md border border-border bg-background px-2 py-1 text-sm font-mono"
            placeholder="route 10.0.0.0 255.0.0.0"
          />
        </div>
      </SectionCard>

      <!-- Section 5: Custom directives -->
      <SectionCard title="Дополнительно" description="Custom OpenVPN directives (whitelist)" :default-open="false">
        <textarea
          v-model="customDirectivesText"
          :disabled="!isMaster"
          rows="5"
          class="w-full rounded-md border border-border bg-background px-2 py-1 text-sm font-mono"
          placeholder="explicit-exit-notify
route 192.168.0.0 255.255.0.0"
        />
        <p class="text-xs text-muted-foreground">
          Разрешены: <span class="font-mono">route, route-nopull, topology, mtu-test, fragment, tx-queue-len, fast-io, explicit-exit-notify, sndbuf, rcvbuf</span>.
        </p>
      </SectionCard>
    </div>
  </div>
</template>

<script>
// Pre-script-setup helpers — bridging text and array fields.
// Kept here since <script setup> doesn't allow direct exports.
import { computed } from 'vue'
</script>
```

Note: above mixes script setup with another script block — that's invalid. Fix it: move `pushExtraText` and `customDirectivesText` as computed inside `<script setup>`. Here is the corrected `<script setup>` add-on (put inside the existing setup block, before the template):

```js
const pushExtraText = computed({
  get: () => (cfg.value?.push_extra || []).join('\n'),
  set: (v) => { cfg.value.push_extra = v.split('\n').map(s => s.trim()).filter(Boolean) },
})

const customDirectivesText = computed({
  get: () => (cfg.value?.custom_directives || []).join('\n'),
  set: (v) => { cfg.value.custom_directives = v.split('\n').map(s => s.trim()).filter(Boolean) },
})
```

Remove the bottom `<script>` block when integrating.

- [ ] **Step 2: Build**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin/frontend && npm run build
```
Expected: clean compile, no Vue errors.

- [ ] **Step 3: Commit**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin
git add frontend/src/components/ServerConfigView.vue
git commit -m "feat(server-config): ServerConfigView main page with 5 sections"
```

---

## Task 16: Frontend — App.vue integration (третья вкладка)

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/frontend/src/App.vue`

- [ ] **Step 1: Импорт**

В `<script setup>` после существующих import'ов:

```js
import ServerConfigView from '@/components/ServerConfigView.vue'
```

- [ ] **Step 2: Добавить tab**

Найти `visibleTabs` computed:

```js
const visibleTabs = computed(() => {
  const tabs = [{ key: 'users', label: 'Пользователи' }]
  if (modulesEnabled.value.includes('common-routes')) {
    tabs.push({ key: 'common-routes', label: 'Общие маршруты' })
  }
  if (modulesEnabled.value.includes('server-config')) {
    tabs.push({ key: 'server-config', label: 'Сервер' })
  }
  return tabs
})
```

- [ ] **Step 3: Добавить branch в template**

Найти `<template v-else-if="activeTab === 'common-routes'">` и после него:

```vue
      <template v-else-if="activeTab === 'server-config'">
        <ServerConfigView :server-role="serverRole" />
      </template>
```

- [ ] **Step 4: Build**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin/frontend && npm run build
```

- [ ] **Step 5: Commit**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin
git add frontend/src/App.vue
git commit -m "feat(server-config): integrate ServerConfigView tab into App"
```

---

## Task 17: Helm chart — drop static ConfigMap, add emptyDir + init-wait

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/charts/openvpn-admin/templates/configmap.yaml`
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/charts/openvpn-admin/templates/deployment.yaml`

- [ ] **Step 1: ConfigMap — удалить блок server.conf**

Если файл `templates/configmap.yaml` содержит ТОЛЬКО `server.conf` под `data:` — удалить файл полностью.

Если есть другие ключи (проверь) — удалить только блок `server.conf: |-` и многострочное содержимое.

- [ ] **Step 2: deployment.yaml — `server-conf` volume → emptyDir + mount в оба контейнера**

Найти существующий volume mount для server-conf в openvpn-container. Поменять:

Volume:
```yaml
volumes:
  - name: server-conf
    emptyDir: {}
```

В openvpn-container — изменить command на wait-loop:
```yaml
        - name: openvpn
          image: "{{ .Values.openvpn.image.repository }}:{{ .Values.openvpn.image.tag | default .Chart.AppVersion }}"
          # ... existing PKI wait ...
          command:
            - sh
            - -c
            - |
              echo "Waiting for ovpn-admin to render server.conf..."
              until [ -f /etc/openvpn/server.conf ]; do sleep 1; done
              echo "server.conf detected, starting OpenVPN"
              # ... existing PKI wait может оставаться внутри ...
              until [ -f /etc/openvpn/pki/ca.crt ]; do sleep 1; done
              exec openvpn --config /etc/openvpn/server.conf
          volumeMounts:
            - name: server-conf
              mountPath: /etc/openvpn/server.conf
              subPath: server.conf
              # NOTE: уже не subPath с readOnly; берём из emptyDir
```

Поменять subPath на mount всего каталога (раз файл генерится в emptyDir):

```yaml
          volumeMounts:
            - name: server-conf
              mountPath: /etc/openvpn  # WAIT — это пересекается с другими mount'ами. Лучше /etc/ovpn-shared.
```

Чтобы не ломать существующий layout — лучше mount-точка `/etc/openvpn/dynamic-conf`, ovpn-admin пишет туда, openvpn-container читает оттуда. Тогда:

```yaml
volumes:
  - name: ovpn-dynamic-conf
    emptyDir: {}

# in openvpn-container:
  volumeMounts:
    - name: ovpn-dynamic-conf
      mountPath: /etc/openvpn-dynamic
  command:
    - sh
    - -c
    - |
      until [ -f /etc/openvpn-dynamic/server.conf ]; do
        echo "Waiting for ovpn-admin to render config..."
        sleep 1
      done
      exec openvpn --config /etc/openvpn-dynamic/server.conf

# in ovpn-admin-container:
  volumeMounts:
    - name: ovpn-dynamic-conf
      mountPath: /etc/openvpn-dynamic
  args:
    - --server-config.conf-path=/etc/openvpn-dynamic/server.conf
```

- [ ] **Step 3: Добавить mount `/lib/modules`** для DCO detection в ovpn-admin-container:

```yaml
  volumeMounts:
    # ... existing ...
    - name: lib-modules
      mountPath: /lib/modules
      readOnly: true

volumes:
    # ... existing ...
  - name: lib-modules
    hostPath:
      path: /lib/modules
      type: DirectoryOrCreate
```

- [ ] **Step 4: Helm render check**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin/charts/openvpn-admin
helm template . > /tmp/rendered.yaml
grep -A 5 "ovpn-dynamic-conf" /tmp/rendered.yaml | head -20
grep "until \[ -f" /tmp/rendered.yaml
rm /tmp/rendered.yaml
cd /Users/alexp/GolandProjects/ovpn-admin
```
Expected: видны emptyDir volume, init-wait-loop, init-mount.

- [ ] **Step 5: Commit**

```bash
git add charts/openvpn-admin/templates/configmap.yaml charts/openvpn-admin/templates/deployment.yaml
git commit -m "feat(server-config): Helm — drop static server.conf, add emptyDir + init-wait"
```

---

## Task 18: docker-compose — emptyDir-equivalent + init-wait + restart policy

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/docker-compose.yaml`
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/setup/configure.sh`
- Delete: `/Users/alexp/GolandProjects/ovpn-admin/setup/openvpn.conf`

- [ ] **Step 1: docker-compose.yaml** — добавить shared volume + restart + wait-loop

```yaml
services:
  openvpn:
    # ... existing ...
    restart: unless-stopped
    volumes:
      - ./easyrsa_master:/etc/openvpn/easyrsa
      - ./ccd_master:/etc/openvpn/ccd
      - dynamic_conf:/etc/openvpn-dynamic
    command:
      - sh
      - -c
      - |
        /etc/openvpn/setup/configure.sh &
        until [ -f /etc/openvpn-dynamic/server.conf ]; do
          echo "Waiting for ovpn-admin to render config..."
          sleep 1
        done
        wait
        exec openvpn --config /etc/openvpn-dynamic/server.conf

  ovpn-admin:
    # ... existing ...
    environment:
      # ... existing ...
      OVPN_SERVER_CONFIG_PATH: "/etc/openvpn-dynamic/server.conf"
    volumes:
      - ./easyrsa_master:/mnt/easyrsa
      - ./ccd_master:/mnt/ccd
      - dynamic_conf:/etc/openvpn-dynamic

volumes:
  dynamic_conf:
```

(Точные правки зависят от текущего вида файла — открой и сделай минимальный диф.)

- [ ] **Step 2: configure.sh — убрать копирование openvpn.conf**

В `/Users/alexp/GolandProjects/ovpn-admin/setup/configure.sh`:
- Удалить строку `cp -f /etc/openvpn/setup/openvpn.conf /etc/openvpn/openvpn.conf`
- Удалить блок `openvpn --config /etc/openvpn/openvpn.conf ...` в конце
- Оставить только: PKI init + iptables MASQUERADE + создание `/dev/net/tun`

После Step 1 docker-compose сама запустит openvpn-команду.

- [ ] **Step 3: Удалить `setup/openvpn.conf`**

```bash
git rm setup/openvpn.conf
```

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yaml setup/configure.sh
git commit -m "feat(server-config): docker-compose — shared volume, init-wait, drop static conf"
```

---

## Task 19: Prometheus metrics

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/server_config.go`
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/main.go`

- [ ] **Step 1: Объявление метрик в `server_config.go`**

```go
import "github.com/prometheus/client_golang/prometheus"

var (
	ovpnServerConfigReloads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ovpn_server_config_reloads_total",
		Help: "Server config reloads by kind",
	}, []string{"kind"})
	ovpnServerConfigErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ovpn_server_config_errors_total",
		Help: "Server config errors by operation",
	}, []string{"op"})
	ovpnServerConfigDCOAvailable = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_config_dco_available",
		Help: "1 if kernel DCO module detected at startup",
	})
)
```

- [ ] **Step 2: Зарегистрировать в `registerMetrics()` (main.go)**

```go
oAdmin.promRegistry.MustRegister(ovpnServerConfigReloads)
oAdmin.promRegistry.MustRegister(ovpnServerConfigErrors)
oAdmin.promRegistry.MustRegister(ovpnServerConfigDCOAvailable)
```

- [ ] **Step 3: Инкременты в коде**

В `apply()`:
```go
// success path:
ovpnServerConfigReloads.WithLabelValues(kind).Inc()
// validate error path:
ovpnServerConfigErrors.WithLabelValues("validate").Inc()
// render error path:
ovpnServerConfigErrors.WithLabelValues("render").Inc()
```

В `main()` после detectDCO:
```go
if dcoAvailable {
    ovpnServerConfigDCOAvailable.Set(1)
} else {
    ovpnServerConfigDCOAvailable.Set(0)
}
```

- [ ] **Step 4: Build + tests**

Run: `go build ./... && go test -race ./...`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add server_config.go main.go
git commit -m "feat(server-config): Prometheus metrics (reloads, errors, dco_available)"
```

---

## Task 20: Smoke compose test

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/docker-compose.test.yml` (опционально — расширить)

- [ ] **Step 1: Full rebuild**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker-compose.test.yml down -v
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker-compose.test.yml build --no-cache
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker-compose.test.yml up -d
```

- [ ] **Step 2: Wait + extract password**

```bash
until curl -fsS http://localhost:8088/ping >/dev/null 2>&1; do sleep 2; done
docker logs ovpn-admin-ovpn-admin-1 2>&1 | grep "Временный пароль" | head -1
```

- [ ] **Step 3: Sanity-check серверного config'а отрендерен**

```bash
docker exec ovpn-admin-ovpn-admin-1 cat /etc/openvpn/server.conf | head -30
```
Expected: видим `proto tcp-server`, `port 1194`, `tls-auth /etc/openvpn/pki/ta.key`, `cipher`-блок и т.д.

- [ ] **Step 4: API smoke**

```bash
PASS=$(docker logs ovpn-admin-ovpn-admin-1 2>&1 | grep "Временный пароль для admin" | head -1 | sed -E 's/.*пароль для admin: ([A-Za-z0-9]+).*/\1/')
COOKIE=$(mktemp)
curl -sS -c $COOKIE -X POST http://localhost:8088/api/login -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=$PASS"

# GET
curl -sS -b $COOKIE http://localhost:8088/api/server-config | head -100

# PUT soft change
curl -sS -b $COOKIE -X PUT http://localhost:8088/api/server-config \
  -H "Content-Type: application/json" \
  -d "$(curl -sS -b $COOKIE http://localhost:8088/api/server-config | jq '.config | .verb = 5')"
```

Expected: GET возвращает config + dco_available; PUT с verb-change → reload_kind=soft.

- [ ] **Step 5: Tear down**

```bash
docker compose -f docker-compose.test.yml down -v
```

- [ ] **Step 6: Commit (если правил test compose)**

```bash
git add docker-compose.test.yml  # если меняли
git commit --allow-empty -m "test(server-config): smoke validated via compose"
```

---

## Task 21: README + CHANGELOG

**Files:**
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/README.md`
- Modify: `/Users/alexp/GolandProjects/ovpn-admin/CHANGELOG.md`

- [ ] **Step 1: README — add Features bullet**

В Features list:
```markdown
* **Editable server config** — proto, port, MTU, cipher, DCO, DNS push, custom directives через web UI без `helm upgrade`. Hybrid reload (SIGHUP soft / SIGTERM hard) с автоматическим rollback при невалидной конфигурации.
```

И секция:
```markdown
## Editable server configuration

The admin UI exposes a "Сервер" tab where you can edit ~15 OpenVPN server
parameters at runtime: protocol (UDP/TCP), port, MTU, data ciphers, TLS
version, DCO (Data Channel Offload), DNS push, redirect-gateway, custom
directives, and more.

### How reload works

- **Soft fields** (DNS push, verb, keepalive, push directives, custom
  directives) — applied via SIGHUP to the running openvpn process. Existing
  clients stay connected; new pushed values take effect on their next
  reconnect.
- **Hard fields** (proto, port, MTU, ciphers, TLS mode, DCO, network) —
  openvpn process is restarted via SIGTERM. All clients drop for ~5 seconds.
  If the new config is invalid (openvpn fails to start within 15s),
  ovpn-admin automatically rolls back to the previous version.

### DCO (kernel offload)

DCO support requires the `ovpn` kernel module (Linux 6.16+) or the
out-of-tree `ovpn-dco` module. ovpn-admin auto-detects availability at
startup. On managed Kubernetes (EKS/GKE/AKS) without custom AMI, DCO is
typically not available — the UI shows a warning and disables the toggle.
```

- [ ] **Step 2: CHANGELOG note**

В `## [Unreleased]`:
```markdown
### Added
- **Editable OpenVPN server config**: new "Сервер" tab edits ~15 server params
  (proto, port, MTU, cipher, DCO, DNS push, custom directives) without
  `helm upgrade`. Auto-detect DCO kernel support. ([spec](docs/superpowers/specs/2026-05-26-server-config-design.md))

### Deprecated
- Helm `values.yaml` openvpn.* fields (`proto`, `port`, `network`,
  `networkMask`, `logLevel`) are now **initial defaults only** — runtime
  values come from the editable server config store. After first start,
  changes via UI are authoritative; values.yaml is ignored on subsequent
  applies.

### Changed
- Helm chart no longer ships a static `server.conf` ConfigMap.
  ovpn-admin renders the file into a shared `emptyDir` volume at startup,
  openvpn-container waits for it via init-loop.
```

- [ ] **Step 3: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs(server-config): README section and CHANGELOG entries"
```

---

## Self-Review (выполнено при написании плана)

**Spec coverage:**

| Spec section | Covered in task |
|---|---|
| ServerConfig types | Task 1 |
| serverConfigStore (RWMutex + deep copy) | Tasks 1, 2 |
| Validation (field-level + custom directives whitelist) | Task 3 |
| Render `server.conf` via text/template | Task 4 |
| DCO auto-detect | Task 5 |
| Soft/hard categorization | Task 6 |
| Persistence (file + K8s secret) | Task 7 |
| serverManager (SIGHUP / SIGTERM / waitMgmt) | Task 8 |
| Apply with rollback | Task 9 |
| HTTP handlers (GET/PUT/test/defaults) | Task 10 |
| main.go wiring (flags, init, routes, render-at-startup) | Task 11 |
| Frontend api.js | Task 12 |
| SectionCard component | Task 13 |
| ChipInput component | Task 14 |
| ServerConfigView (5 sections + status banner) | Task 15 |
| App.vue tab integration | Task 16 |
| Helm chart updates | Task 17 |
| docker-compose + setup script updates | Task 18 |
| Prometheus metrics | Task 19 |
| Smoke test | Task 20 |
| README + CHANGELOG | Task 21 |

**Placeholder scan:** все шаги содержат полный код. Единственные «выбери минимальный диф» — в Tasks 17 и 18 (Helm/compose), потому что точный текущий вид файлов зависит от прошлых правок. Это явно указано.

**Type consistency:** имена методов и полей сверены. `ServerConfig`, `ServerConfigResponse`, `serverConfigStore`, `serverManager`, `serverConfigHandler` — единообразны.

**Известная неточность (требует внимания):**
- В Tasks 17 и 18 — конкретный текущий вид `templates/deployment.yaml` и `docker-compose.yaml` сейчас не на 100% совпадает с предположениями плана (volume `server-conf` уже маунтится определённым образом). Имплементер должен прочитать существующие файлы перед правкой и сделать минимальный диф вокруг описанных изменений, а не блоковую замену.
- В Task 15 после `<script setup>` НЕ должно быть дополнительного `<script>` блока — это пример, который имплементер должен правильно интегрировать (computed'ы `pushExtraText`/`customDirectivesText` идут внутри основного `<script setup>`). Это явно отмечено в Step 1 как примечание.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-26-server-config.md`. Two execution options:

**1. Subagent-Driven (recommended)** — диспатчу свежего сабагента на каждую задачу, ревью между задачами, быстрая итерация.

**2. Inline Execution** — выполнение задач в этой же сессии через executing-plans.

Which approach?

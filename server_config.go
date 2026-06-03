package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"ovpn-admin/internal/storage"
)

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

const serverConfigSecretName = "ovpn-admin-server-config"
const serverConfigSecretKey = "data"

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

	// MgmtClientAuth enables the `management-client-auth` directive in
	// server.conf. When true, every client connect is gated by ovpn-admin
	// via the OpenVPN management interface — pure cert verification is no
	// longer enough; ovpn-admin must reply with `client-auth-nt` (allow)
	// or `client-deny`. This lets ovpn-admin enforce policy beyond cert+CRL
	// (hot revocation, custom rules, etc).
	//
	// When false the directive is omitted and OpenVPN authorizes solely on
	// cert validity + CRL.
	MgmtClientAuth bool `json:"mgmt_client_auth"`

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

	// PublicEndpoint — override for .ovpn client config (defaults to --ovpn.server)
	PublicHostname string `json:"public_hostname,omitempty"`
	PublicPort     int    `json:"public_port,omitempty"`
	PublicProto    string `json:"public_proto,omitempty"`

	// DomainRefreshIntervalHours controls how often the background
	// scheduler re-resolves domain-based routes (Common Routes + per-user)
	// and rewrites CCD files. 0 disables the scheduler entirely (manual
	// refresh only). Default = 24 (once a day).
	DomainRefreshIntervalHours int `json:"domain_refresh_interval_hours"`

	// Bookkeeping
	UpdatedAt string `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`

	// Initialized=true означает что admin явно сохранил настройки через UI
	// хотя бы раз. До этого создание пользователей заблокировано (defaults
	// нужны только чтобы openvpn-сервер мог стартовать).
	Initialized bool `json:"initialized"`
}

// ServerConfigResponse — обёртка для API-ответа, добавляет runtime DCO-detection
// которая НЕ сохраняется в store (свойство ноды, может меняться при rescheduling).
type ServerConfigResponse struct {
	Config       ServerConfig `json:"config"`
	DCOAvailable bool         `json:"dco_available"`
	// Initialized — продублирован из Config.Initialized для удобства
	// frontend (отдельный флаг рядом с runtime-полями).
	Initialized bool `json:"initialized"`
}

// defaultServerConfig — дефолты при первом запуске (store пустой).
// Подобраны под текущие production-значения чтобы upgrade не ломал клиентов.
// Initialized=false (zero value) — admin ещё не сохранял настройки через UI;
// до явного сохранения создание пользователей будет заблокировано.
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
		// DCOEnabled opts in to `data-channel-offload`. Default off because
		// the official Alpine `openvpn` package is built WITHOUT DCO and
		// will refuse to start the server config. Operators who run a
		// DCO-enabled binary can toggle this on via the server-config UI.
		DCOEnabled:        false,
		// MgmtClientAuth=true is the safer default: every connect is gated
		// by ovpn-admin so revocation/policy changes take effect immediately
		// without waiting for CRL refresh on the client side.
		MgmtClientAuth:             true,
		DomainRefreshIntervalHours: 24,
		KeepaliveInterval:          10,
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
	out.DataCiphers = cloneStringsNonNil(s.cfg.DataCiphers)
	out.DNSServers = cloneStringsNonNil(s.cfg.DNSServers)
	out.PushExtra = cloneStringsNonNil(s.cfg.PushExtra)
	out.CustomDirectives = cloneStringsNonNil(s.cfg.CustomDirectives)
	return out
}

// cloneStringsNonNil — deep-copy строкового слайса, гарантирует non-nil результат
// (append([]string(nil), nil...) возвращает nil, что ломает store-инвариант).
func cloneStringsNonNil(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func (s *serverConfigStore) replace(cfg ServerConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalizeServerConfig(&cfg)
	s.cfg = cfg
}

// normalizeServerConfig replaces nil slices with empty ones in-place. JSON
// (de)serialization round-trips would otherwise emit `null` for missing
// fields, which the frontend and tests treat as a contract violation.
// Centralizing here keeps serialize/deserialize/replace in sync.
func normalizeServerConfig(cfg *ServerConfig) {
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
}

var allowedDataCiphers = map[string]struct{}{
	"AES-256-GCM":       {},
	"AES-128-GCM":       {},
	"CHACHA20-POLY1305": {},
	"AES-256-CBC":       {},
	"AES-128-CBC":       {},
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

// allowedDirectivePrefixes — префиксы безопасных директив для CustomDirectives / PushExtra.
// ЗАПРЕЩЕНЫ: script-*, up, down, plugin, ipchange, setenv-safe, learn-address.
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
	if cfg.PublicPort != 0 && (cfg.PublicPort < 1 || cfg.PublicPort > 65535) {
		return fmt.Errorf("public_port must be 1..65535, got %d", cfg.PublicPort)
	}
	if cfg.PublicProto != "" && cfg.PublicProto != "udp" && cfg.PublicProto != "tcp" {
		return fmt.Errorf("public_proto must be udp or tcp, got %q", cfg.PublicProto)
	}
	if cfg.PublicHostname != "" {
		// Accept hostname (RFC1035) or IPv4
		hostnameRE := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)
		if net.ParseIP(cfg.PublicHostname) == nil && !hostnameRE.MatchString(cfg.PublicHostname) {
			return fmt.Errorf("public_hostname must be a valid hostname or IP, got %q", cfg.PublicHostname)
		}
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
		return fmt.Errorf("keepalive_timeout must be > interval and <= 86400, got %d", cfg.KeepaliveTimeout)
	}
	if cfg.MaxClients < 0 {
		return fmt.Errorf("max_clients must be >= 0")
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
	if strings.ContainsAny(line, "\n\r") {
		return fmt.Errorf("directive must not contain newline characters")
	}
	// Double quotes would let an operator break out of any push "..." that
	// downstream templates wrap around the line. Reject defensively.
	if strings.Contains(line, `"`) {
		return fmt.Errorf("directive must not contain double quotes")
	}
	for _, prefix := range allowedDirectivePrefixes {
		if line == strings.TrimSpace(prefix) || strings.HasPrefix(line, prefix) {
			return nil
		}
	}
	return fmt.Errorf("directive %q is not in whitelist", line)
}

const serverConfTemplate = `# Generated by ovpn-admin at {{ .Cfg.UpdatedAt }}
user nobody
group nogroup

mode server
tls-server
dev tun
proto {{ if eq .Cfg.Proto "tcp" }}tcp-server{{ else }}udp{{ end }}
port {{ .Cfg.Port }}
management 127.0.0.1 8989
{{- if .Cfg.MgmtClientAuth }}
management-client-auth
{{- end }}

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

{{- /* DCO in OpenVPN 2.6.x: built with --enable-dco engages kernel offload automatically when an ovpn/ovpn_dco module is loaded. There is no data-channel-offload directive; only --disable-dco to opt out. So we emit nothing for DCO=on, disable-dco for DCO=off. */ -}}
{{- if not .Cfg.DCOEnabled }}
disable-dco
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

// detectDCOSupport проверяет загружен ли в ядре модуль `ovpn` (mainline 6.16+),
// out-of-tree v1 `ovpn_dco` или v2 `ovpn_dco_v2`. Вызывается один раз
// при старте ovpn-admin.
func detectDCOSupport() bool {
	for _, name := range []string{"ovpn", "ovpn_dco", "ovpn_dco_v2"} {
		if _, err := os.Stat("/sys/module/" + name); err == nil {
			return true
		}
	}
	_ = exec.Command("modprobe", "ovpn").Run()
	if _, err := os.Stat("/sys/module/ovpn"); err == nil {
		return true
	}
	return false
}

// categorizeChanges возвращает "none" | "soft" | "hard".
// Hard wins over soft.
//
// Direct if-chains (rather than slice-of-closures) so the comparison is
// short-circuiting AND zero-allocation. The old closure list paid a slice
// allocation on every call just to avoid a few `||` operators.
func categorizeChanges(old, new ServerConfig) string {
	hard := old.Proto != new.Proto ||
		old.Port != new.Port ||
		old.TunMTU != new.TunMTU ||
		old.MssFix != new.MssFix ||
		!reflect.DeepEqual(old.DataCiphers, new.DataCiphers) ||
		old.TLSVersionMin != new.TLSVersionMin ||
		old.TLSAuthMode != new.TLSAuthMode ||
		old.DCOEnabled != new.DCOEnabled ||
		old.MgmtClientAuth != new.MgmtClientAuth ||
		// Push-related fields used to be "soft" (SIGHUP only), but SIGHUP
		// doesn't re-deliver push to already-connected clients — they keep
		// the old DNS/gateway until reconnect. Treating these as hard means
		// every save forces a clean reload so existing sessions pick up the
		// new push config without manual disconnect.
		old.RedirectGateway != new.RedirectGateway ||
		!reflect.DeepEqual(old.DNSServers, new.DNSServers) ||
		!reflect.DeepEqual(old.PushExtra, new.PushExtra) ||
		!reflect.DeepEqual(old.CustomDirectives, new.CustomDirectives) ||
		old.Compression != new.Compression ||
		old.ClientToClient != new.ClientToClient ||
		old.DuplicateCN != new.DuplicateCN ||
		old.Network != new.Network ||
		old.NetworkMask != new.NetworkMask
	if hard {
		return "hard"
	}

	// Soft = the openvpn process can reload via SIGHUP without dropping
	// connected clients. Only fields with zero client-visible impact stay
	// here (log verbosity, max-clients server-side cap, keepalive timings
	// which OpenVPN re-applies at next ping). DomainRefreshIntervalHours
	// is read live by the background scheduler — no openvpn restart at all.
	soft := old.Verb != new.Verb ||
		old.KeepaliveInterval != new.KeepaliveInterval ||
		old.KeepaliveTimeout != new.KeepaliveTimeout ||
		old.MaxClients != new.MaxClients ||
		old.DomainRefreshIntervalHours != new.DomainRefreshIntervalHours
	if soft {
		return "soft"
	}
	return "none"
}

func serializeServerConfig(cfg ServerConfig) ([]byte, error) {
	normalizeServerConfig(&cfg)
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
	normalizeServerConfig(&cfg)
	return cfg, nil
}

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

// serverManager — координирует render + reload openvpn-процесса.
type serverManager struct {
	store          *serverConfigStore
	persistBackend storage.Store
	mgmtAddr       string
	confPath       string
	dcoAvailable   bool
	ccdEnabled     bool
}

func (m *serverManager) softReload() error {
	return m.sendSignal("SIGHUP")
}

func (m *serverManager) sendSignal(sig string) error {
	conn, err := net.DialTimeout("tcp", m.mgmtAddr, 3*time.Second)
	if err != nil {
		return fmt.Errorf("connect mgmt %s: %w", m.mgmtAddr, err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	// Drain async-notification greeting (`>INFO:...`). Lines have no terminator
	// indicating "last greeting", so each read uses a short deadline; once we
	// time out (no more data buffered), we stop draining.
	for {
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if !strings.HasPrefix(line, ">") {
			break
		}
	}

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintln(conn, "signal "+sig); err != nil {
		return fmt.Errorf("send signal: %w", err)
	}
	resp, _ := reader.ReadString('\n')
	if strings.HasPrefix(resp, "ERROR") {
		return fmt.Errorf("mgmt error: %s", strings.TrimSpace(resp))
	}
	return nil
}

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
		}
	}
}

// apply применяет новый конфиг: валидирует, рендерит, сохраняет, перезагружает.
func (m *serverManager) apply(ctx context.Context, newCfg ServerConfig, updatedBy string) (string, error) {
	if err := validateServerConfig(newCfg); err != nil {
		ovpnServerConfigErrors.WithLabelValues("validate").Inc()
		return "", fmt.Errorf("validate: %w", err)
	}

	current := m.store.snapshot()
	kind := categorizeChanges(current, newCfg)
	if kind == "none" {
		// Даже если openvpn-параметры не изменились, факт явного
		// сохранения должен пометить конфиг как инициализированный
		// (admin осознанно подтвердил defaults).
		if newCfg.Initialized && !current.Initialized {
			current.Initialized = true
			current.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			current.UpdatedBy = updatedBy
			m.store.replace(current)
			if err := m.persist(current); err != nil {
				log.Warnf("apply: persist (initialized flag only) failed: %v", err)
			}
		}
		return "none", nil
	}

	newCfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	newCfg.UpdatedBy = updatedBy

	rendered, err := renderServerConfig(newCfg, m.dcoAvailable, m.ccdEnabled)
	if err != nil {
		ovpnServerConfigErrors.WithLabelValues("render").Inc()
		return "", err
	}
	if err := writeFileAtomic(m.confPath, []byte(rendered)); err != nil {
		ovpnServerConfigErrors.WithLabelValues("write").Inc()
		return "", fmt.Errorf("write conf: %w", err)
	}

	// `current` was previously captured as a backup for rollback. Hard
	// reload now self-exits (so the runtime rebinds the network namespace),
	// which means we can't roll back from in-process anyway. The validation
	// step above guards against the bad-config case at save time.
	_ = current
	m.store.replace(newCfg)
	if err := m.persist(newCfg); err != nil {
		log.Warnf("apply: persist failed: %v", err)
	}

	// If the VPN subnet changed (or even if it didn't but we want to
	// guarantee a single correct MASQUERADE rule exists), reconcile
	// iptables. Without this, clients in the new subnet egress with an
	// unroutable private source address — the symptom is "VPN connected
	// but no internet access".
	//
	// Safe to run on every save: the function is idempotent and only
	// touches rules whose shape matches our own "-s X/Y ! -d X/Y -j
	// MASQUERADE" emission, so Docker bridge MASQUERADE is left alone.
	if err := reconcileMasquerade(newCfg.Network, newCfg.NetworkMask); err != nil {
		log.Warnf("apply: masquerade reconcile failed: %v", err)
	}

	switch kind {
	case "soft":
		ovpnServerConfigReloads.WithLabelValues("soft").Inc()
		if err := m.softReload(); err != nil {
			log.Warnf("soft reload (SIGHUP) failed: %v — config saved, will pick up at next restart", err)
		}
		return "soft", nil
	case "hard":
		ovpnServerConfigReloads.WithLabelValues("hard").Inc()
		// SIGTERM into openvpn's mgmt makes the openvpn process exit, which
		// in turn makes the container exit and be recreated by the runtime
		// (`restart: unless-stopped` in docker-compose; kubelet in K8s).
		// The recreated openvpn container has a NEW network namespace.
		//
		// When ovpn-admin is in the same Pod (K8s) the pod's pause container
		// holds the netns, so ovpn-admin keeps networking — fine.
		// In docker-compose with `network_mode: service:openvpn`, ovpn-admin
		// is locked to openvpn's OLD netns ID and becomes orphaned (502 on
		// every UI request). To make this work in both runtimes we exit too
		// after a short delay and let depends_on bring us back attached to
		// the new netns. The HTTP caller has already received the apply()
		// response by the time we exit.
		if err := m.sendSignal("SIGTERM"); err != nil {
			log.Warnf("SIGTERM via mgmt failed: %v", err)
		}
		go func() {
			// Give the HTTP handler ~1s to flush the success response to
			// the client BEFORE the process dies. log.Info is buffered
			// against stdout — sync via log.Fatal would write the line
			// synchronously but also flag-up the exit as an error in
			// healthchecks; use a plain Info + os.Exit instead.
			time.Sleep(1200 * time.Millisecond)
			log.Infof("hard reload: graceful self-exit so runtime rebinds netns to new openvpn (Docker network_mode: service:openvpn or K8s pod)")
			os.Exit(0)
		}()
		return "hard", nil
	}
	return kind, nil
}

func (m *serverManager) persist(cfg ServerConfig) error {
	data, err := serializeServerConfig(cfg)
	if err != nil {
		return err
	}
	return m.persistBackend.SaveServerConfig(data)
}

func writeFileAtomic(path string, data []byte) error {
	// 0640 — rendered server.conf may include push-extra/custom directives
	// that leak topology. Owner (ovpn-admin) writes; group (e.g. openvpn)
	// reads; world has no access.
	return writeFileAtomicMode(path, data, 0o640)
}

// writeFileAtomicSecret is writeFileAtomic with mode 0600. Use for files that
// hold key material or session state (signing key, MFA secrets, revoked-token
// blacklist).
func writeFileAtomicSecret(path string, data []byte) error {
	return writeFileAtomicMode(path, data, 0o600)
}

// writeFileAtomicMode writes data to path atomically with the given perm. It
// uses a unique tmp name in the destination directory so concurrent writers
// can't clobber one another's `path + ".tmp"`, then renames into place — the
// rename is atomic on POSIX when src and dst are on the same filesystem.
// fsync is performed before rename to harden against power loss.
func writeFileAtomicMode(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, base+".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if anything below fails — Remove of an already-renamed
	// file is harmless (ignored ENOENT).
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// serverConfigHandler dispatches GET / PUT on /api/server-config.
func (oAdmin *OvpnAdmin) serverConfigHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	switch r.Method {
	case http.MethodGet:
		snap := oAdmin.serverConfigStore.snapshot()
		resp := ServerConfigResponse{
			Config:       snap,
			DCOAvailable: oAdmin.serverManager.dcoAvailable,
			Initialized:  snap.Initialized,
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPut:
		// Multi-method route — MFA gate inline since GET reads remain open.
		if !oAdmin.adminHasMfa(r) {
			writeJSONError(w, http.StatusPreconditionFailed, "MFA must be enabled to perform this action")
			return
		}
		var cfg ServerConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			log.Debugf("server-config: decode body: %v", err)
			writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		// Любое успешное сохранение через UI помечает конфиг как
		// инициализированный — это и есть сигнал "admin осознанно настроил сервер".
		cfg.Initialized = true
		updatedBy := "admin"
		kind, err := oAdmin.serverManager.apply(r.Context(), cfg, updatedBy)
		if err != nil {
			log.Errorf("server-config: apply: %v", err)
			writeJSONError(w, http.StatusBadRequest, "failed to apply server config")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"config":      oAdmin.serverConfigStore.snapshot(),
			"reload_kind": kind,
		})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// serverConfigTestHandler POST /api/server-config/test — dry-run validation.
// Method check is enforced by the requireMethod middleware.
func (oAdmin *OvpnAdmin) serverConfigTestHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var cfg ServerConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		log.Debugf("server-config-test: decode body: %v", err)
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
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

// serverConfigDefaultsHandler GET /api/server-config/defaults — returns the
// hard-coded defaults used at first startup. Method check is enforced by the
// requireMethod middleware.
func (oAdmin *OvpnAdmin) serverConfigDefaultsHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	writeJSON(w, http.StatusOK, defaultServerConfig())
}

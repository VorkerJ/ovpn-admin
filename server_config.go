package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"text/template"
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

// detectDCOSupport проверяет загружен ли в ядре модуль `ovpn` (mainline 6.16+)
// или out-of-tree `ovpn_dco`. Вызывается один раз при старте ovpn-admin.
func detectDCOSupport() bool {
	if _, err := os.Stat("/sys/module/ovpn"); err == nil {
		return true
	}
	if _, err := os.Stat("/sys/module/ovpn_dco"); err == nil {
		return true
	}
	_ = exec.Command("modprobe", "ovpn").Run()
	if _, err := os.Stat("/sys/module/ovpn"); err == nil {
		return true
	}
	return false
}

// categorizeChanges возвращает "none" | "soft" | "hard".
// Hard wins over soft.
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

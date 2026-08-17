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
	"strconv"
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

	// PasswordAuth enables per-user optional password auth on top of the
	// certificate. When true, server.conf gets auth-user-pass-verify (->
	// setup/auth.sh -> openvpn-user -> users.db) + auth-user-pass-optional
	// (so cert-only users are NOT prompted) + script-security 2. A user is
	// "password-required" iff they have an active password entry in users.db;
	// only those users get `auth-user-pass` in their .ovpn. Cert-only users
	// connect unchanged. Off = no password checks at all.
	PasswordAuth bool `json:"password_auth"`

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

	// RedirectGatewayExclusions — default LAN/CGNAT subnets that bypass the
	// VPN even when full-tunnel (redirect-gateway) is enabled for a user.
	// Applied to every user with Ccd.RedirectGateway = true, on top of any
	// per-user exclusions. Defaults to the RFC1918 + link-local set so home
	// LAN access (printer, NAS, router admin) keeps working out of the box.
	RedirectGatewayExclusions []Subnet `json:"redirect_gateway_exclusions"`

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

// serverDefaultStr / serverDefaultInt seed a first-boot server-config field
// from an env var, falling back to the built-in default when unset/invalid.
// This lets an operator pin the listen proto/port/network declaratively (e.g.
// from the Helm chart) instead of having to set them once in the UI — important
// for a GitOps deploy where the rendered server.conf must listen on a fixed
// port (a fronting L4 proxy targets it) from the very first boot.
func serverDefaultStr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func serverDefaultInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		log.Warnf("server-config: %s=%q is not a valid integer — using default %d", key, v, def)
	}
	return def
}

// defaultServerConfig — дефолты при первом запуске (store пустой).
// Подобраны под текущие production-значения чтобы upgrade не ломал клиентов.
// Proto/Port/Network/NetworkMask могут быть переопределены env-переменными
// (OVPN_SERVER_PROTO / OVPN_SERVER_PORT / OVPN_SERVER_NETWORK /
// OVPN_SERVER_NETWORK_MASK) — чтобы порт прослушивания и подсеть задавались
// декларативно из чарта, а не выставлялись руками в UI после деплоя.
// Initialized=false (zero value) — admin ещё не сохранял настройки через UI;
// до явного сохранения создание пользователей будет заблокировано.
func defaultServerConfig() ServerConfig {
	return ServerConfig{
		Proto:         serverDefaultStr("OVPN_SERVER_PROTO", "tcp"),
		Port:          serverDefaultInt("OVPN_SERVER_PORT", 1194),
		Network:       serverDefaultStr("OVPN_SERVER_NETWORK", "172.16.100.0"),
		NetworkMask:   serverDefaultStr("OVPN_SERVER_NETWORK_MASK", "255.255.255.0"),
		TunMTU:        1500,
		MssFix:        1450,
		DataCiphers:   []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"},
		TLSVersionMin: "1.2",
		TLSAuthMode:   "tls-auth",
		// DCOEnabled opts in to `data-channel-offload`. Default off because
		// the official Alpine `openvpn` package is built WITHOUT DCO and
		// will refuse to start the server config. Operators who run a
		// DCO-enabled binary can toggle this on via the server-config UI.
		DCOEnabled: false,
		// MgmtClientAuth=true is the safer default: every connect is gated
		// by ovpn-admin so revocation/policy changes take effect immediately
		// without waiting for CRL refresh on the client side.
		MgmtClientAuth:             true,
		DomainRefreshIntervalHours: 24,
		KeepaliveInterval:          10,
		KeepaliveTimeout:           60,
		MaxClients:                 0,
		ClientToClient:             true,
		DuplicateCN:                true,
		Compression:                "",
		Verb:                       3,
		RedirectGateway:            false,
		DNSServers:                 []string{"1.1.1.1", "8.8.8.8"},
		PushExtra:                  []string{},
		CustomDirectives:           []string{},
		RedirectGatewayExclusions: []Subnet{
			{Address: "192.168.0.0", Mask: "255.255.0.0", Description: "Home/office LAN"},
			{Address: "10.0.0.0", Mask: "255.0.0.0", Description: "Private 10/8"},
			{Address: "172.16.0.0", Mask: "255.240.0.0", Description: "Private 172.16/12 + Docker"},
			{Address: "169.254.0.0", Mask: "255.255.0.0", Description: "Link-local / mDNS"},
		},
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
	out.RedirectGatewayExclusions = cloneSubnetsNonNil(s.cfg.RedirectGatewayExclusions)
	return out
}

// cloneSubnetsNonNil — deep-copy that guarantees non-nil result so
// JSON round-trips return [] instead of null for an empty list.
func cloneSubnetsNonNil(in []Subnet) []Subnet {
	out := make([]Subnet, len(in))
	copy(out, in)
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
	if cfg.RedirectGatewayExclusions == nil {
		cfg.RedirectGatewayExclusions = []Subnet{}
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
	for i, s := range cfg.RedirectGatewayExclusions {
		if err := validateSubnet(s); err != nil {
			return fmt.Errorf("redirect_gateway_exclusions[%d]: %w", i, err)
		}
	}
	return nil
}

// validateSubnet enforces:
//   - Address parses as IPv4
//   - Mask parses as a contiguous IPv4 netmask (e.g. 255.255.0.0, NOT 255.0.255.0)
//   - Address has no host bits set under Mask (canonical network form)
//   - Description has no shell/template-injection vectors (newlines, double quotes)
//   - Description length cap matching existing route-description policy
func validateSubnet(s Subnet) error {
	ip := net.ParseIP(s.Address)
	if ip == nil {
		return fmt.Errorf("address %q is not a valid IP", s.Address)
	}
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("address %q must be IPv4 (IPv6 not supported)", s.Address)
	}
	mip := net.ParseIP(s.Mask)
	if mip == nil {
		return fmt.Errorf("mask %q is not a valid IP", s.Mask)
	}
	mv4 := mip.To4()
	if mv4 == nil {
		return fmt.Errorf("mask %q must be IPv4 dotted-quad", s.Mask)
	}
	mask := net.IPv4Mask(mv4[0], mv4[1], mv4[2], mv4[3])
	ones, bits := mask.Size()
	if bits == 0 {
		return fmt.Errorf("mask %q is not a contiguous network mask", s.Mask)
	}
	// A /0 exclusion (mask 0.0.0.0) renders as `route 0.0.0.0 0.0.0.0
	// net_gateway`, which sends the entire default route back to the client's
	// gateway and SILENTLY cancels redirect-gateway def1 — i.e. it turns
	// full-tunnel off for whoever the exclusion applies to, with no warning.
	// An exclusion is meant to carve out a LAN, never the whole internet; use
	// the redirect-gateway toggle to disable full-tunnel instead.
	if ones == 0 {
		return fmt.Errorf("mask %q (/0) is not allowed as an exclusion — it would disable full-tunnel entirely; turn off the redirect-gateway toggle instead", s.Mask)
	}
	// Reject host bits in Address: 192.168.0.5/16 → must be 192.168.0.0/16.
	// This catches a common operator mistake that OpenVPN itself silently
	// ignores (it ANDs with the mask), making debugging easier later.
	network := v4.Mask(mask)
	if !network.Equal(v4) {
		return fmt.Errorf("address %q has host bits set under mask %q (canonical form: %s)", s.Address, s.Mask, network.String())
	}
	if ones < 0 || ones > 32 {
		return fmt.Errorf("mask %q out of range", s.Mask)
	}
	if strings.ContainsAny(s.Description, "\n\r") {
		return fmt.Errorf("description must not contain newlines")
	}
	if strings.Contains(s.Description, `"`) {
		return fmt.Errorf("description must not contain double quotes")
	}
	// NUL byte would truncate the comment in OpenVPN's C-string parser
	// (the comment ends at the first \x00), making rendered configs hard
	// to read. Defensive reject — operator should never need a NUL in a
	// human-readable label.
	if strings.ContainsAny(s.Description, "\x00") {
		return fmt.Errorf("description must not contain NUL bytes")
	}
	// Reserved CCD markers in a description would let a crafted exclusion be
	// re-parsed as a different control directive on round-trip. See
	// descriptionHasReservedMarker / parseCcd.
	if descriptionHasReservedMarker(s.Description) {
		return fmt.Errorf("description must not contain reserved markers (__redirect_gateway__, __exclusion_*, __common__, __user_domain__)")
	}
	if len(s.Description) > 200 {
		return fmt.Errorf("description too long (max 200 chars)")
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
{{- if .Cfg.PasswordAuth }}
auth-user-pass-verify /etc/openvpn/scripts/auth.sh via-file
auth-user-pass-optional
script-security 2
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
		old.PasswordAuth != new.PasswordAuth ||
		// Push-related fields used to be "soft" (SIGHUP only), but SIGHUP
		// doesn't re-deliver push to already-connected clients — they keep
		// the old DNS/gateway until reconnect. Treating these as hard means
		// every save forces a clean reload so existing sessions pick up the
		// new push config without manual disconnect.
		old.RedirectGateway != new.RedirectGateway ||
		!reflect.DeepEqual(old.RedirectGatewayExclusions, new.RedirectGatewayExclusions) ||
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
	// Migration for upgrades from pre-v2.0.17: distinguish "field missing"
	// (old config — apply RFC1918 defaults so home LAN keeps working when
	// the operator first enables full-tunnel) from "field present but empty"
	// (operator deliberately cleared the list — respect that).
	// We do this by peeking at the raw JSON before normalizeServerConfig
	// collapses both cases to an empty slice.
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err == nil {
		if _, present := rawMap["redirect_gateway_exclusions"]; !present {
			cfg.RedirectGatewayExclusions = defaultServerConfig().RedirectGatewayExclusions
		}
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

	// MASQUERADE reconcile happens inside the openvpn container at
	// (re)start (ensure_masquerade in configure.sh parses the rendered
	// server.conf and updates iptables). ovpn-admin runs non-root with
	// no-new-privileges and cannot manipulate nf_tables directly even
	// with cap_add NET_ADMIN — file capabilities are blocked by the
	// security_opt. The openvpn process restart that hard reload
	// triggers below also re-runs configure.sh, so the rule follows.

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
		// Capture before apply so we can tell whether CCDs need rerendering
		// (global redirect-gateway exclusions are pulled into every CCD at
		// render time; changing them requires a rewrite + kick to take effect).
		preExclusions := oAdmin.serverConfigStore.snapshot().RedirectGatewayExclusions
		preGlobalRedirect := oAdmin.serverConfigStore.snapshot().RedirectGateway
		kind, err := oAdmin.serverManager.apply(r.Context(), cfg, updatedBy)
		if err != nil {
			log.Errorf("server-config: apply: %v", err)
			writeJSONError(w, http.StatusBadRequest, "failed to apply server config")
			return
		}
		if !reflect.DeepEqual(preExclusions, cfg.RedirectGatewayExclusions) || preGlobalRedirect != cfg.RedirectGateway {
			// Run in background so the API response isn't blocked by render+kick
			// of every user. The user is forced to reconnect anyway by the hard
			// reload that apply() already triggered for push-affecting changes.
			go func() {
				var expanded []ccdCommonRoute
				if oAdmin.commonRoutes != nil {
					expanded = expandCommonRoutes(oAdmin.commonRoutes.snapshot())
				}
				oAdmin.rerenderAllCcds(expanded)
			}()
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

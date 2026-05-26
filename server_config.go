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

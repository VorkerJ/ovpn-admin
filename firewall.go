package main

import (
	"context"
	"fmt"
	"net"
	"sync"
)

// ipMaskToCIDR конвертирует пару IP + dotted-quad netmask в CIDR-нотацию.
// Возвращает ошибку, если IP или маска невалидны, либо маска не contiguous.
func ipMaskToCIDR(addr, mask string) (string, error) {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return "", fmt.Errorf("invalid IP: %q", addr)
	}
	maskIP := net.ParseIP(mask).To4()
	if maskIP == nil {
		return "", fmt.Errorf("invalid mask: %q", mask)
	}
	m := net.IPv4Mask(maskIP[0], maskIP[1], maskIP[2], maskIP[3])
	ones, bits := m.Size()
	if bits == 0 {
		return "", fmt.Errorf("mask %q is not contiguous", mask)
	}
	return fmt.Sprintf("%s/%d", ip.Mask(m).String(), ones), nil
}

type fwEventKind int

const (
	EvConnect fwEventKind = iota
	EvDisconnect
	EvUserChanged
	EvCommonChanged
	EvReconcile
)

type fwEvent struct {
	Kind  fwEventKind
	CN    string
	VpnIP string
}

type fwSession struct {
	CN             string
	VpnIP          string
	AllowedCIDRs   []string
	RulesInstalled bool
}

// iptCmdFunc — функция выполнения iptables. Тестово мок-абельна.
type iptCmdFunc func(args ...string) error

type firewallController struct {
	mu        sync.Mutex
	enabled   bool
	chainName string
	iptBin    string
	vpnNet    *net.IPNet
	sessions  map[string]*fwSession
	pending   map[string]fwEvent
	kick      chan struct{}
	iptCmd    iptCmdFunc
	oAdmin    *OvpnAdmin
	ctx       context.Context
	cancel    context.CancelFunc
}

func newFirewallController(oAdmin *OvpnAdmin, chainName, iptBin string, vpnNet *net.IPNet, iptCmd iptCmdFunc) *firewallController {
	return &firewallController{
		enabled:   true,
		chainName: chainName,
		iptBin:    iptBin,
		vpnNet:    vpnNet,
		sessions:  make(map[string]*fwSession),
		pending:   make(map[string]fwEvent),
		kick:      make(chan struct{}, 1),
		iptCmd:    iptCmd,
		oAdmin:    oAdmin,
	}
}

// initChain создаёт цепочку OVPN_FW (если её нет), очищает, ставит прыжок из FORWARD,
// добавляет stateful-return первым правилом и catch-all DROP последним.
// Идемпотентно: повторный вызов даёт то же состояние.
func (fc *firewallController) initChain() error {
	// 1. Создаём цепочку (если уже есть — iptables вернёт "Chain already exists", глотаем)
	if err := fc.iptCmd("-N", fc.chainName); err != nil {
		// "already exists" — нормально для repeat-init
	}

	// 2. Очищаем содержимое
	if err := fc.iptCmd("-F", fc.chainName); err != nil {
		return fmt.Errorf("flush %s: %w", fc.chainName, err)
	}

	// 3. Прыжок из FORWARD (вставляем в начало, чтобы не зависеть от других правил)
	// -C проверяет существование; если нет — -I добавляет.
	if err := fc.iptCmd("-C", "FORWARD", "-j", fc.chainName); err != nil {
		if err := fc.iptCmd("-I", "FORWARD", "1", "-j", fc.chainName); err != nil {
			return fmt.Errorf("insert FORWARD jump: %w", err)
		}
	}

	// 4. Stateful-return первым правилом
	if err := fc.iptCmd("-A", fc.chainName,
		"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
		"-j", "ACCEPT",
		"-m", "comment", "--comment", "ovpn-admin: stateful-return"); err != nil {
		return fmt.Errorf("append stateful-return: %w", err)
	}

	// 5. Catch-all DROP последним
	if err := fc.installCatchAllDrop(); err != nil {
		return fmt.Errorf("install catch-all DROP: %w", err)
	}

	return nil
}

// cleanupChain снимает прыжок из FORWARD и удаляет цепочку. Best-effort.
func (fc *firewallController) cleanupChain() {
	_ = fc.iptCmd("-D", "FORWARD", "-j", fc.chainName)
	_ = fc.iptCmd("-F", fc.chainName)
	_ = fc.iptCmd("-X", fc.chainName)
}

// installCatchAllDrop ставит финальное DROP-правило для всей VPN-подсети.
func (fc *firewallController) installCatchAllDrop() error {
	return fc.iptCmd("-A", fc.chainName,
		"-s", fc.vpnNet.String(),
		"-j", "DROP",
		"-m", "comment", "--comment", "ovpn-admin: default-deny")
}

// removeCatchAllDrop снимает финальное DROP-правило (нужно для pivot'а при добавлении новых правил).
func (fc *firewallController) removeCatchAllDrop() error {
	return fc.iptCmd("-D", fc.chainName,
		"-s", fc.vpnNet.String(),
		"-j", "DROP",
		"-m", "comment", "--comment", "ovpn-admin: default-deny")
}

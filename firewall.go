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

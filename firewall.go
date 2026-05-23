package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
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

// installRulesFor добавляет ACCEPT-правила для одной сессии (CN, VPN_IP, набор разрешённых CIDR).
// Атомарно через pivot: снимает catch-all DROP → добавляет ACCEPT'ы → возвращает catch-all DROP.
// Caller должен держать fc.mu.
func (fc *firewallController) installRulesFor(cn, vpnIP string, cidrs []string) error {
	comment := "ovpn-admin: " + cn
	if err := fc.removeCatchAllDrop(); err != nil {
		// Catch-all может отсутствовать в момент install (например, при первичной reconcile).
		log.Debugf("installRulesFor: removeCatchAllDrop (might not exist): %v", err)
	}
	for _, cidr := range cidrs {
		if err := fc.iptCmd("-A", fc.chainName,
			"-s", vpnIP, "-d", cidr, "-j", "ACCEPT",
			"-m", "comment", "--comment", comment); err != nil {
			// При ошибке пытаемся восстановить catch-all и пробрасываем
			_ = fc.installCatchAllDrop()
			return fmt.Errorf("install rule %s→%s: %w", vpnIP, cidr, err)
		}
	}
	return fc.installCatchAllDrop()
}

// uninstallRulesFor удаляет ACCEPT-правила сессии. Catch-all DROP не трогаем — он остаётся последним.
// Best-effort: если какое-то правило уже отсутствует, логируем и продолжаем.
// Caller должен держать fc.mu.
func (fc *firewallController) uninstallRulesFor(cn, vpnIP string, cidrs []string) error {
	comment := "ovpn-admin: " + cn
	var firstErr error
	for _, cidr := range cidrs {
		if err := fc.iptCmd("-D", fc.chainName,
			"-s", vpnIP, "-d", cidr, "-j", "ACCEPT",
			"-m", "comment", "--comment", comment); err != nil {
			log.Debugf("uninstallRulesFor: -D failed (rule may be missing): %v", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// applyDiff приводит установленные правила сессии к newCIDRs минимальным числом команд.
// Обновляет s.AllowedCIDRs на newCIDRs при успехе. Caller держит fc.mu.
func (fc *firewallController) applyDiff(s *fwSession, newCIDRs []string) error {
	oldSet := make(map[string]struct{}, len(s.AllowedCIDRs))
	for _, c := range s.AllowedCIDRs {
		oldSet[c] = struct{}{}
	}
	newSet := make(map[string]struct{}, len(newCIDRs))
	for _, c := range newCIDRs {
		newSet[c] = struct{}{}
	}

	var toDel, toAdd []string
	for c := range oldSet {
		if _, ok := newSet[c]; !ok {
			toDel = append(toDel, c)
		}
	}
	for c := range newSet {
		if _, ok := oldSet[c]; !ok {
			toAdd = append(toAdd, c)
		}
	}

	if len(toDel) == 0 && len(toAdd) == 0 {
		return nil
	}

	if err := fc.removeCatchAllDrop(); err != nil {
		log.Debugf("applyDiff: removeCatchAllDrop: %v", err)
	}

	comment := "ovpn-admin: " + s.CN
	for _, cidr := range toDel {
		if err := fc.iptCmd("-D", fc.chainName,
			"-s", s.VpnIP, "-d", cidr, "-j", "ACCEPT",
			"-m", "comment", "--comment", comment); err != nil {
			log.Debugf("applyDiff: -D %s: %v", cidr, err)
		}
	}
	for _, cidr := range toAdd {
		if err := fc.iptCmd("-A", fc.chainName,
			"-s", s.VpnIP, "-d", cidr, "-j", "ACCEPT",
			"-m", "comment", "--comment", comment); err != nil {
			log.Warnf("applyDiff: -A %s: %v", cidr, err)
		}
	}

	if err := fc.installCatchAllDrop(); err != nil {
		return fmt.Errorf("restore catch-all DROP: %w", err)
	}

	s.AllowedCIDRs = append([]string(nil), newCIDRs...)
	return nil
}

// computeAllowedCIDRs возвращает дедуплицированный набор CIDR'ов, разрешённых для CN.
// Источники: CCD CustomRoutes (через oAdmin.getCcd) + Common Routes (через oAdmin.commonRoutes.snapshot()).
func (fc *firewallController) computeAllowedCIDRs(cn string) ([]string, error) {
	set := make(map[string]struct{})

	if fc.oAdmin != nil {
		ccd := fc.oAdmin.getCcd(cn)
		for _, r := range ccd.CustomRoutes {
			cidr, err := ipMaskToCIDR(r.Address, r.Mask)
			if err != nil {
				log.Warnf("firewall: invalid CCD route for %s: %v", cn, err)
				continue
			}
			set[cidr] = struct{}{}
		}
		if fc.oAdmin.commonRoutes != nil {
			expanded := expandCommonRoutes(fc.oAdmin.commonRoutes.snapshot())
			for _, r := range expanded {
				cidr, err := ipMaskToCIDR(r.Address, r.Mask)
				if err != nil {
					log.Warnf("firewall: invalid common route: %v", err)
					continue
				}
				set[cidr] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	return out, nil
}

// mgmtEventParser — простой стейт-машина для строк mgmt-протокола.
// Один parser на одно TCP-соединение; вызывается feed() для каждой полученной строки.
type mgmtEventParser struct {
	current *fwEvent
	env     map[string]string
}

func newMgmtEventParser() *mgmtEventParser {
	return &mgmtEventParser{}
}

// feed возвращает готовый fwEvent, если эта строка завершила сессию (>CLIENT:ENV,END).
// nil — для промежуточных или нерелевантных строк.
func (p *mgmtEventParser) feed(line string) *fwEvent {
	line = strings.TrimRight(line, "\r\n")

	if strings.HasPrefix(line, ">CLIENT:CONNECT,") {
		p.current = &fwEvent{Kind: EvConnect}
		p.env = make(map[string]string)
		return nil
	}
	if strings.HasPrefix(line, ">CLIENT:DISCONNECT,") {
		p.current = &fwEvent{Kind: EvDisconnect}
		p.env = make(map[string]string)
		return nil
	}
	if !strings.HasPrefix(line, ">CLIENT:ENV,") {
		return nil
	}
	payload := strings.TrimPrefix(line, ">CLIENT:ENV,")

	if payload == "END" {
		if p.current == nil {
			return nil
		}
		p.current.CN = p.env["common_name"]
		p.current.VpnIP = p.env["ifconfig_pool_remote_ip"]
		ev := p.current
		p.current = nil
		p.env = nil
		return ev
	}

	if idx := strings.IndexByte(payload, '='); idx > 0 && p.env != nil {
		p.env[payload[:idx]] = payload[idx+1:]
	}
	return nil
}

// push добавляет событие в очередь с дедупликацией per-CN.
// Если событие для того же CN уже в очереди — заменяет его.
// EvCommonChanged использует фиксированный ключ "__common__", EvReconcile — "__reconcile__".
func (fc *firewallController) push(ev fwEvent) {
	if !fc.enabled {
		return
	}
	key := ev.CN
	if ev.Kind == EvCommonChanged {
		key = "__common__"
	}
	if ev.Kind == EvReconcile {
		key = "__reconcile__"
	}
	fc.mu.Lock()
	fc.pending[key] = ev
	fc.mu.Unlock()
	select {
	case fc.kick <- struct{}{}:
	default:
	}
}

// eventHandlerLoop — единственная горутина-обработчик очереди событий.
func (fc *firewallController) eventHandlerLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-fc.kick:
		}
		fc.mu.Lock()
		batch := fc.pending
		fc.pending = make(map[string]fwEvent)
		fc.mu.Unlock()
		for _, ev := range batch {
			fc.handleEvent(ev)
		}
	}
}

// handleEvent — обработка одного события.
// Лочит fc.mu на время операций.
func (fc *firewallController) handleEvent(ev fwEvent) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	switch ev.Kind {
	case EvConnect:
		cidrs, err := fc.computeAllowedCIDRs(ev.CN)
		if err != nil {
			log.Warnf("firewall: computeAllowedCIDRs(%s) on connect: %v", ev.CN, err)
			return
		}
		if err := fc.installRulesFor(ev.CN, ev.VpnIP, cidrs); err != nil {
			log.Warnf("firewall: installRulesFor(%s): %v", ev.CN, err)
		}
		fc.sessions[ev.CN] = &fwSession{CN: ev.CN, VpnIP: ev.VpnIP, AllowedCIDRs: cidrs, RulesInstalled: true}

	case EvDisconnect:
		s, ok := fc.sessions[ev.CN]
		if !ok {
			return
		}
		if err := fc.uninstallRulesFor(s.CN, s.VpnIP, s.AllowedCIDRs); err != nil {
			log.Warnf("firewall: uninstallRulesFor(%s): %v", ev.CN, err)
		}
		delete(fc.sessions, ev.CN)

	case EvUserChanged:
		s, ok := fc.sessions[ev.CN]
		if !ok {
			return
		}
		newCIDRs, err := fc.computeAllowedCIDRs(ev.CN)
		if err != nil {
			log.Warnf("firewall: computeAllowedCIDRs(%s) on user-changed: %v", ev.CN, err)
			return
		}
		if err := fc.applyDiff(s, newCIDRs); err != nil {
			log.Warnf("firewall: applyDiff(%s): %v", ev.CN, err)
		}

	case EvCommonChanged:
		for cn, s := range fc.sessions {
			newCIDRs, err := fc.computeAllowedCIDRs(cn)
			if err != nil {
				log.Warnf("firewall: computeAllowedCIDRs(%s) on common-changed: %v", cn, err)
				continue
			}
			if err := fc.applyDiff(s, newCIDRs); err != nil {
				log.Warnf("firewall: applyDiff(%s): %v", cn, err)
			}
		}

	case EvReconcile:
		fc.reconcileLocked() // см. Task 9
	}
}

// reconcileLocked — будет реализован в Task 9.
func (fc *firewallController) reconcileLocked() {
	// TODO Task 9
}

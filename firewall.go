package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// firewallReconcilePoll caps how often the firewall polls the mgmt `status` to
// track live VPN sessions. We poll (rather than hold a persistent >CLIENT:
// event stream) because those events need management-client-auth and the held
// connection starved OpenVPN's single-client mgmt console. It bounds the delay
// before a freshly-connected client's per-route ACCEPT rules are installed.
const firewallReconcilePoll = 8 * time.Second

var (
	ovpnFirewallEnabledGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_firewall_enabled",
		Help: "1 if server-side route enforcement is enabled",
	})
	ovpnFirewallActiveSessions = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_firewall_active_sessions",
		Help: "Number of VPN sessions with installed iptables rules",
	})
	ovpnFirewallIptablesErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ovpn_firewall_iptables_errors_total",
		Help: "Number of failed iptables invocations",
	})
	ovpnFirewallEventsProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ovpn_firewall_events_processed_total",
		Help: "Number of firewall events processed, labeled by type",
	}, []string{"type"})
	ovpnFirewallReconciles = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ovpn_firewall_reconciles_total",
		Help: "Number of full reconcile operations",
	})
)

func eventKindName(k fwEventKind) string {
	switch k {
	case EvConnect:
		return "connect"
	case EvDisconnect:
		return "disconnect"
	case EvUserChanged:
		return "user_changed"
	case EvCommonChanged:
		return "common_changed"
	case EvReconcile:
		return "reconcile"
	}
	return "unknown"
}

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

// ipToHostCIDR превращает один IP-адрес в host-CIDR: /32 для IPv4, /128 для IPv6.
// Используется для domain-маршрутов, у которых нет Address/Mask — только
// разрезолвленные IP (ResolvedIPs).
func ipToHostCIDR(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP: %q", ip)
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String() + "/32", nil
	}
	return parsed.String() + "/128", nil
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
	CN           string
	VpnIP        string
	AllowedCIDRs []string
	// pendingDeletes holds CIDRs whose `-D` failed in a previous applyDiff. They
	// are folded back into the delete-diff on every subsequent applyDiff so a
	// stuck delete is retried until iptables finally removes the rule.
	pendingDeletes map[string]struct{}
	RulesInstalled bool
}

// sessionKey identifies a live VPN session. Duplicate-cn is on by default, so a
// single CN can hold several concurrent sessions on distinct VPN IPs; keying by
// (CN, VpnIP) keeps their iptables rules independent. A VPN-IP change for a CN
// then naturally removes the old-IP rules and installs the new-IP rules.
type sessionKey struct {
	CN    string
	VpnIP string
}

// iptCmdFunc — функция выполнения iptables. Тестово мок-абельна.
type iptCmdFunc func(args ...string) error

// CcdReader — минимальный интерфейс, через который firewall читает маршруты.
// Реализуется *OvpnAdmin; в тестах — fakeCcdReader.
type CcdReader interface {
	getCcd(username string) Ccd
	commonRoutesSnapshot() CommonRoutesConfig
}

type firewallController struct {
	mu        sync.Mutex
	enabled   bool
	chainName string
	iptBin    string
	vpnNet    *net.IPNet
	sessions  map[sessionKey]*fwSession
	pending   map[string]fwEvent
	kick      chan struct{}
	iptCmd    iptCmdFunc
	ccdReader CcdReader
	ctx       context.Context
	cancel    context.CancelFunc
	// mgmtSnapshot returns the live sessions and an ok flag; ok=false means the
	// mgmt poll failed (console busy) and the snapshot is UNKNOWN, not empty.
	mgmtSnapshot func() ([]clientStatus, bool)
}

func newFirewallController(ccdReader CcdReader, chainName, iptBin string, vpnNet *net.IPNet, iptCmd iptCmdFunc) *firewallController {
	return &firewallController{
		enabled:   true,
		chainName: chainName,
		iptBin:    iptBin,
		vpnNet:    vpnNet,
		sessions:  make(map[sessionKey]*fwSession),
		pending:   make(map[string]fwEvent),
		kick:      make(chan struct{}, 1),
		iptCmd:    iptCmd,
		ccdReader: ccdReader,
	}
}

// initChain создаёт цепочку OVPN_FW (если её нет), очищает, ставит прыжок из FORWARD,
// добавляет stateful-return первым правилом и catch-all DROP последним.
// Идемпотентно: повторный вызов даёт то же состояние.
func (fc *firewallController) initChain() error {
	// 1. Создаём цепочку (если уже есть — iptables вернёт "Chain already exists", глотаем)
	// Идемпотентно: "already exists" — нормально для repeat-init, любая другая ошибка
	// всплывёт ниже на -F (flush несуществующей цепочки тоже падает).
	_ = fc.iptCmd("-N", fc.chainName)

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

// installRulesFor добавляет ACCEPT-правила для одной сессии (CN, VPN_IP, набор разрешённых CIDR).
//
// Fail-CLOSED: каждое ACCEPT-правило ВСТАВЛЯЕТСЯ над catch-all DROP через
// `-I <chain> 2` (позиция 2 = сразу после stateful-return, который initChain
// ставит первым правилом). Финальный DROP при этом НИКОГДА не снимается, поэтому
// сбой iptables в середине может оставить лишь МЕНЬШЕ ACCEPT'ов, но не открытую
// подсеть. Прежний вариант (снять DROP → добавить ACCEPT'ы → вернуть DROP) мог
// оставить цепочку без защитного DROP при ошибке в середине (fail-OPEN).
//
// При любой ошибке возвращаем её — caller НЕ должен помечать сессию установленной,
// чтобы следующий reconcile повторил установку. Caller должен держать fc.mu.
func (fc *firewallController) installRulesFor(cn, vpnIP string, cidrs []string) error {
	comment := "ovpn-admin: " + cn
	for _, cidr := range cidrs {
		if err := fc.iptCmd("-I", fc.chainName, "2",
			"-s", vpnIP, "-d", cidr, "-j", "ACCEPT",
			"-m", "comment", "--comment", comment); err != nil {
			return fmt.Errorf("install rule %s→%s: %w", vpnIP, cidr, err)
		}
	}
	return nil
}

// uninstallRulesFor удаляет ACCEPT-правила сессии. Catch-all DROP не трогаем — он остаётся последним.
// Caller должен держать fc.mu.
//
// Возвращает remaining — CIDR'ы, чьё `-D` ПРОВАЛИЛОСЬ (правило, возможно, всё ещё
// живёт в цепочке), и первую ошибку. Fail-CLOSED: caller НЕ должен удалять сессию,
// пока remaining непуст — он оставляет её с AllowedCIDRs=remaining, чтобы следующий
// reconcile повторил снятие только застрявших правил.
func (fc *firewallController) uninstallRulesFor(cn, vpnIP string, cidrs []string) (remaining []string, err error) {
	comment := "ovpn-admin: " + cn
	for _, cidr := range cidrs {
		if e := fc.iptCmd("-D", fc.chainName,
			"-s", vpnIP, "-d", cidr, "-j", "ACCEPT",
			"-m", "comment", "--comment", comment); e != nil {
			log.Debugf("uninstallRulesFor: -D failed (rule may still be live): %v", e)
			remaining = append(remaining, cidr)
			if err == nil {
				err = e
			}
		}
	}
	return remaining, err
}

// applyDiff приводит установленные правила сессии к newCIDRs минимальным числом команд.
//
// Транзакционно относительно состояния: s.AllowedCIDRs обновляется на ФАКТИЧЕСКИ
// применённый набор, а НЕ безусловно на newCIDRs. То есть:
//   - CIDR, чьё `-D` провалилось, СОХРАНЯЕТСЯ в AllowedCIDRs (fail-CLOSED: правило,
//     возможно, ещё живёт) и запоминается в s.pendingDeletes для повторной попытки;
//   - CIDR, чей `-I` провалился, НЕ попадает в AllowedCIDRs, поэтому следующий
//     applyDiff/reconcile повторит его добавление.
//
// Ранее застрявшие удаления (s.pendingDeletes) вкладываются обратно в delete-diff
// на каждом вызове. Возвращает первую ошибку, чтобы caller мог инициировать retry.
// Caller держит fc.mu.
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
	// Fold previously-stuck deletes back in so a failed -D is retried until it
	// finally succeeds. Skip a CIDR that has come back into the allowed set, or
	// one already queued above (still present in AllowedCIDRs).
	for c := range s.pendingDeletes {
		if _, ok := newSet[c]; ok {
			continue
		}
		if _, ok := oldSet[c]; ok {
			continue
		}
		toDel = append(toDel, c)
	}
	for c := range newSet {
		if _, ok := oldSet[c]; !ok {
			toAdd = append(toAdd, c)
		}
	}

	if len(toDel) == 0 && len(toAdd) == 0 {
		return nil
	}

	comment := "ovpn-admin: " + s.CN
	var firstErr error

	// applied — набор CIDR'ов, которые реально считаются установленными после
	// этого прохода. Начинаем с желаемого набора и корректируем по факту команд.
	applied := make(map[string]struct{}, len(newSet))
	for c := range newSet {
		applied[c] = struct{}{}
	}
	newPending := make(map[string]struct{})

	// Удаление ACCEPT'ов не трогает catch-all DROP. Если `-D` провалилось —
	// оставляем CIDR в applied (правило, возможно, ещё живёт) и запоминаем для
	// повторной попытки (fail-CLOSED).
	for _, cidr := range toDel {
		if err := fc.iptCmd("-D", fc.chainName,
			"-s", s.VpnIP, "-d", cidr, "-j", "ACCEPT",
			"-m", "comment", "--comment", comment); err != nil {
			log.Debugf("applyDiff: -D %s: %v", cidr, err)
			applied[cidr] = struct{}{}
			newPending[cidr] = struct{}{}
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	// Fail-CLOSED: новые ACCEPT'ы ВСТАВЛЯЕМ над catch-all DROP (`-I <chain> 2`,
	// как в installRulesFor). DROP при этом никогда не снимается — цепочка не
	// может остаться открытой при сбое iptables в середине. Если `-I` провалилось —
	// НЕ считаем CIDR установленным, чтобы следующий проход повторил добавление.
	for _, cidr := range toAdd {
		if err := fc.iptCmd("-I", fc.chainName, "2",
			"-s", s.VpnIP, "-d", cidr, "-j", "ACCEPT",
			"-m", "comment", "--comment", comment); err != nil {
			log.Warnf("applyDiff: -I %s: %v", cidr, err)
			delete(applied, cidr)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	out := make([]string, 0, len(applied))
	for c := range applied {
		out = append(out, c)
	}
	s.AllowedCIDRs = out
	s.pendingDeletes = newPending
	return firstErr
}

// computeAllowedCIDRs возвращает дедуплицированный набор CIDR'ов, разрешённых для CN.
// Источники: CCD CustomRoutes + Common Routes (через CcdReader интерфейс).
func (fc *firewallController) computeAllowedCIDRs(cn string) ([]string, error) {
	set := make(map[string]struct{})

	if fc.ccdReader != nil {
		ccd := fc.ccdReader.getCcd(cn)
		for _, r := range ccd.CustomRoutes {
			// Domain routes carry no Address/Mask — only ResolvedIPs. Emit a host
			// CIDR (/32 IPv4, /128 IPv6) per resolved IP. (Common routes are already
			// expanded to host CIDRs via expandCommonRoutes below.)
			if r.Kind == "domain" {
				for _, ip := range r.ResolvedIPs {
					cidr, err := ipToHostCIDR(ip)
					if err != nil {
						log.Warnf("firewall: invalid resolved IP for domain route %q (%s): %v", r.Domain, cn, err)
						continue
					}
					set[cidr] = struct{}{}
				}
				continue
			}
			cidr, err := ipMaskToCIDR(r.Address, r.Mask)
			if err != nil {
				log.Warnf("firewall: invalid CCD route for %s: %v", cn, err)
				continue
			}
			set[cidr] = struct{}{}
		}
		expanded := expandCommonRoutes(fc.ccdReader.commonRoutesSnapshot())
		for _, r := range expanded {
			cidr, err := ipMaskToCIDR(r.Address, r.Mask)
			if err != nil {
				log.Warnf("firewall: invalid common route: %v", err)
				continue
			}
			set[cidr] = struct{}{}
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
	defer ovpnFirewallEventsProcessed.WithLabelValues(eventKindName(ev.Kind)).Inc()
	defer func() { ovpnFirewallActiveSessions.Set(float64(len(fc.sessions))) }()

	switch ev.Kind {
	case EvConnect:
		cidrs, err := fc.computeAllowedCIDRs(ev.CN)
		if err != nil {
			log.Warnf("firewall: computeAllowedCIDRs(%s) on connect: %v", ev.CN, err)
			return
		}
		if err := fc.installRulesFor(ev.CN, ev.VpnIP, cidrs); err != nil {
			// Fail-CLOSED: НЕ помечаем сессию установленной. Оставляем её вне
			// fc.sessions, чтобы следующий reconcile (selfHealLoop) повторил
			// установку правил, вместо того чтобы навсегда пропустить её.
			log.Warnf("firewall: installRulesFor(%s): %v", ev.CN, err)
			return
		}
		fc.sessions[sessionKey{CN: ev.CN, VpnIP: ev.VpnIP}] = &fwSession{CN: ev.CN, VpnIP: ev.VpnIP, AllowedCIDRs: cidrs, RulesInstalled: true}

	case EvDisconnect:
		// Match by CN; when the event carries a VPN IP, match that session only.
		// An empty VpnIP disconnects ALL sessions for the CN. Fail-CLOSED: if rule
		// removal fails we KEEP the session (AllowedCIDRs=remaining) so the next
		// reconcile retries only the stuck rules.
		for key, s := range fc.sessions {
			if key.CN != ev.CN {
				continue
			}
			if ev.VpnIP != "" && key.VpnIP != ev.VpnIP {
				continue
			}
			remaining, err := fc.uninstallRulesFor(s.CN, s.VpnIP, s.AllowedCIDRs)
			if err != nil {
				log.Warnf("firewall: uninstallRulesFor(%s): %v", ev.CN, err)
				s.AllowedCIDRs = remaining
				continue
			}
			delete(fc.sessions, key)
		}

	case EvUserChanged:
		// A CN may hold several sessions (duplicate-cn). Recompute once and apply
		// the diff to every session of that CN.
		var newCIDRs []string
		computed := false
		for key, s := range fc.sessions {
			if key.CN != ev.CN {
				continue
			}
			if !computed {
				c, err := fc.computeAllowedCIDRs(ev.CN)
				if err != nil {
					log.Warnf("firewall: computeAllowedCIDRs(%s) on user-changed: %v", ev.CN, err)
					return
				}
				newCIDRs = c
				computed = true
			}
			if err := fc.applyDiff(s, newCIDRs); err != nil {
				log.Warnf("firewall: applyDiff(%s): %v", ev.CN, err)
			}
		}

	case EvCommonChanged:
		for _, s := range fc.sessions {
			newCIDRs, err := fc.computeAllowedCIDRs(s.CN)
			if err != nil {
				log.Warnf("firewall: computeAllowedCIDRs(%s) on common-changed: %v", s.CN, err)
				continue
			}
			if err := fc.applyDiff(s, newCIDRs); err != nil {
				log.Warnf("firewall: applyDiff(%s): %v", s.CN, err)
			}
		}

	case EvReconcile:
		fc.reconcileLocked() // см. Task 9
	}
}

// reconcileLocked полностью сверяет fc.sessions с реальностью из mgmt-snapshot'а.
// Caller держит fc.mu. Используется при старте, при обрыве mgmt-стрима и периодически.
//
// TODO(firewall): this reconcile compares fc.sessions against the mgmt `status`
// snapshot (which clients are connected), NOT against the live iptables chain.
// A true live-iptables reconcile would parse `iptables -S <chain>` and re-add any
// ACCEPT/DROP that drifted out of the kernel table. That is deferred because the
// iptCmd abstraction returns no stdout (only an error), so there is nothing to
// diff against; wiring it up needs an iptCmd variant that captures output.
func (fc *firewallController) reconcileLocked() {
	snapshot, ok := fc.mgmtSnapshot()
	if !ok {
		// mgmt poll failed (single-client console momentarily busy). Treat as
		// UNKNOWN, not "no clients" — skip so we don't uninstall rules for
		// still-connected users. The next poll (firewallReconcilePoll) retries.
		return
	}
	// Key live sessions by (CN, VPN IP): duplicate-cn lets one CN hold several
	// sessions, and a VPN-IP change shows up here as an old key disappearing and
	// a new key appearing — old-IP rules are removed, new-IP rules installed.
	live := make(map[sessionKey]*clientStatus)
	for i := range snapshot {
		k := sessionKey{CN: snapshot[i].CommonName, VpnIP: snapshot[i].VirtualAddress}
		live[k] = &snapshot[i]
	}
	// Закрываем sessions которых нет в live — uninstall. Fail-CLOSED: если снятие
	// правил провалилось, СОХРАНЯЕМ сессию (AllowedCIDRs=remaining), чтобы следующий
	// reconcile повторил только застрявшие правила, а не потерял их из учёта.
	for key, s := range fc.sessions {
		if _, ok := live[key]; ok {
			continue
		}
		remaining, err := fc.uninstallRulesFor(s.CN, s.VpnIP, s.AllowedCIDRs)
		if err != nil {
			log.Warnf("firewall: reconcile uninstall(%s): %v", key.CN, err)
			s.AllowedCIDRs = remaining
			continue
		}
		delete(fc.sessions, key)
	}
	// Добавляем тех, кто есть в live, но нет в fc.sessions
	for key, c := range live {
		if _, ok := fc.sessions[key]; ok {
			continue
		}
		cidrs, err := fc.computeAllowedCIDRs(key.CN)
		if err != nil {
			log.Warnf("firewall: reconcile compute(%s): %v", key.CN, err)
			continue
		}
		if err := fc.installRulesFor(key.CN, c.VirtualAddress, cidrs); err != nil {
			log.Warnf("firewall: reconcile install(%s): %v", key.CN, err)
			continue
		}
		fc.sessions[key] = &fwSession{CN: key.CN, VpnIP: c.VirtualAddress, AllowedCIDRs: cidrs, RulesInstalled: true}
	}
	ovpnFirewallReconciles.Inc()
}

// Start выполняет initChain, запускает горутины (event-handler + status-poll reconcile)
// и делает initial reconcile. Возвращает ошибку только если initChain провалился.
func (fc *firewallController) Start(ctx context.Context, mgmtAddr string, reconcileInterval time.Duration) error {
	fc.ctx, fc.cancel = context.WithCancel(ctx)

	if err := fc.initChain(); err != nil {
		return fmt.Errorf("initChain: %w", err)
	}

	go fc.eventHandlerLoop(fc.ctx)
	// Track live sessions by POLLING the mgmt `status` (via reconcileLocked ->
	// mgmtSnapshot) on short-lived connections, rather than holding a persistent
	// `log on` stream for real-time >CLIENT: events. Two reasons the old stream
	// approach failed in prod: (1) those >CLIENT: events are only emitted under
	// `management-client-auth`, which is off by default (it forces every client
	// to send a login/password and breaks cert-only clients); (2) the persistent
	// connection monopolised OpenVPN's SINGLE-CLIENT mgmt console, so the
	// `status` polls that reconcileLocked AND the connected-users view rely on
	// were refused ("mgmt interface not reachable") — the firewall then saw zero
	// live sessions and installed no per-route ACCEPTs. Polling caps the delay
	// for a new client's routes at one interval and never holds the console.
	poll := reconcileInterval
	if poll <= 0 || poll > firewallReconcilePoll {
		poll = firewallReconcilePoll
	}
	go fc.selfHealLoop(fc.ctx, poll)

	// initial reconcile
	fc.push(fwEvent{Kind: EvReconcile})

	ovpnFirewallEnabledGauge.Set(1)
	return nil
}

// Stop отменяет контекст и делает best-effort cleanup цепочки.
func (fc *firewallController) Stop() {
	ovpnFirewallEnabledGauge.Set(0)
	if fc.cancel != nil {
		fc.cancel()
	}
	fc.cleanupChain()
}

// realIptCmd возвращает функцию, вызывающую реальный iptables бинарь.
// Используется в проде; в тестах — мок.
func realIptCmd(iptBin string) iptCmdFunc {
	return func(args ...string) error {
		cmd := exec.Command(iptBin, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			ovpnFirewallIptablesErrors.Inc()
			return fmt.Errorf("%s %v: %w (output: %s)", iptBin, args, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// selfHealLoop периодически пушит EvReconcile для self-heal'а от дрифта.
func (fc *firewallController) selfHealLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fc.push(fwEvent{Kind: EvReconcile})
		}
	}
}

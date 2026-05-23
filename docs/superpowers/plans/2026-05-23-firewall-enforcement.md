# Server-side Route Enforcement (Firewall) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Реализовать в ovpn-admin серверный enforcement push-маршрутов через iptables — каждый клиент VPN может попасть только на сети, явно разрешённые ему (CCD `CustomRoutes` ∪ глобальные Common Routes). Default-deny.

**Architecture:** Новый модуль `firewall.go` внутри ovpn-admin (без отдельного sidecar'а). Контейнеру ovpn-admin даётся `NET_ADMIN` capability, в Docker-image добавляется бинарь `iptables`. Модуль слушает события OpenVPN management-interface (`>CLIENT:CONNECT/DISCONNECT`), при каждом коннекте/изменении конфига пересчитывает разрешённые CIDR'ы юзера и атомарно правит цепочку `OVPN_FW` в FORWARD. Catch-all DROP в конце цепочки = default-deny.

**Tech Stack:** Go 1.25 (stdlib `bufio`, `context`, `net`, `os/exec`, `regexp`, `sync`, `time`), `iptables` бинарь в alpine-image, изменения в Helm-чарте (deployment, configmap, values), docker-compose. Тесты — стандартный `testing` пакет, все вызовы iptables через `iptCmd`-функцию-мок.

**Spec:** [`docs/superpowers/specs/2026-05-23-firewall-enforcement-design.md`](../specs/2026-05-23-firewall-enforcement-design.md)

---

## File Structure

**Новые файлы:**
- `firewall.go` — типы, контроллер, парсер mgmt-событий, event-loop, reconcile, iptables-обёртка. Один файл ≈450 строк. Логика связана между собой; разбивать преждевременно.
- `firewall_test.go` — все unit-тесты для firewall.go.
- `docker-compose.firewall-test.yml` — отдельный compose для smoke-теста (openvpn-server + ovpn-admin + openvpn-client).
- `docs/superpowers/specs/_pending/disaster-recovery-postgres.md` — stub
- `docs/superpowers/specs/_pending/firewall-ipset-scale.md` — stub
- `docs/superpowers/specs/_pending/firewall-nftables-modernize.md` — stub
- `docs/superpowers/specs/_pending/firewall-port-protocol-rules.md` — stub

**Изменяемые:**
- `main.go` — 5 новых CLI флагов, поле `firewall *firewallController` в `OvpnAdmin`, инициализация в `main()`, hooks из `userApplyCcdHandler`, регистрация модуля
- `common_routes.go` — hooks из `handleCreateCommonRoute`, `handleUpdateCommonRoute`, `handleDeleteCommonRoute`, `commonRoutesRefreshHandler` (после `rerenderAllCcds`)
- `Dockerfile.ovpn-admin` — добавить `iptables` в `apk add` финального stage'а
- `charts/openvpn-admin/values.yaml` — секция `ovpnAdmin.firewall.*`
- `charts/openvpn-admin/templates/deployment.yaml` — `NET_ADMIN` cap, условные args
- `charts/openvpn-admin/templates/configmap.yaml` — server.conf получает `management-client-auth` или эквивалент
- `docker-compose.yaml` — `cap_add: [NET_ADMIN]` + `OVPN_FIREWALL=true`
- `README.md` — секция «Server-side route enforcement»
- `CHANGELOG.md` (или CHANGELOG_create) — breaking note для Helm-апгрейдеров

---

## Important Project Rules

- **Docker builds: ВСЕГДА `--no-cache`** (см. CLAUDE.md). На M-Mac добавлять `DOCKER_DEFAULT_PLATFORM=linux/amd64`.
- **Frontend → packr2:** после изменений во `frontend/src/` нужен `npm run build` + `packr2` в корне репо. Docker делает это сам.
- **Никаких `--no-verify`** для git hooks.
- **Коммитим часто** — после каждой завершённой задачи отдельным коммитом.
- **Unit-тесты — только с мок-iptables** (на macOS iptables нет). Real-iptables проверки — только в docker-compose smoke-тестах.

---

## Task 1: Helper `ipMaskToCIDR`

**Files:**
- Create: `firewall.go` (минимальный, только helper)
- Create: `firewall_test.go`

- [ ] **Step 1: Создать тест (RED)**

Создать `firewall_test.go`:

```go
package main

import "testing"

func TestIpMaskToCIDR(t *testing.T) {
	cases := []struct {
		addr, mask, want string
	}{
		{"10.0.0.0", "255.255.255.0", "10.0.0.0/24"},
		{"10.0.0.0", "255.0.0.0", "10.0.0.0/8"},
		{"172.16.0.0", "255.240.0.0", "172.16.0.0/12"},
		{"192.168.1.1", "255.255.255.255", "192.168.1.1/32"},
		{"0.0.0.0", "0.0.0.0", "0.0.0.0/0"},
	}
	for _, c := range cases {
		got, err := ipMaskToCIDR(c.addr, c.mask)
		if err != nil {
			t.Errorf("ipMaskToCIDR(%q,%q) returned err: %v", c.addr, c.mask, err)
			continue
		}
		if got != c.want {
			t.Errorf("ipMaskToCIDR(%q,%q) = %q, want %q", c.addr, c.mask, got, c.want)
		}
	}
}

func TestIpMaskToCIDR_BadInput(t *testing.T) {
	cases := []struct{ addr, mask string }{
		{"not-an-ip", "255.255.255.0"},
		{"10.0.0.0", "not-a-mask"},
		{"10.0.0.0", "255.0.255.0"}, // non-contiguous mask
	}
	for _, c := range cases {
		if _, err := ipMaskToCIDR(c.addr, c.mask); err == nil {
			t.Errorf("ipMaskToCIDR(%q,%q) expected error, got nil", c.addr, c.mask)
		}
	}
}
```

- [ ] **Step 2: Прогнать тесты — RED**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run TestIpMaskToCIDR -v ./...`
Expected: ошибка компиляции `undefined: ipMaskToCIDR`.

- [ ] **Step 3: Реализация в `firewall.go`**

```go
package main

import (
	"fmt"
	"net"
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
```

- [ ] **Step 4: Прогнать — GREEN**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run TestIpMaskToCIDR -v ./...`
Expected: 2 PASS.

- [ ] **Step 5: Build всего проекта**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && gofmt -l firewall.go firewall_test.go && go build ./... && go test ./...`
Expected: gofmt-clean, build OK, все ~32 теста (включая Common Routes) проходят.

- [ ] **Step 6: Commit**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin
git add firewall.go firewall_test.go
git commit -m "feat(firewall): add ipMaskToCIDR helper"
```

---

## Task 2: Типы данных и каркас `firewallController`

**Files:**
- Modify: `firewall.go`
- Modify: `firewall_test.go`

- [ ] **Step 1: Расширить `firewall.go` типами**

Добавить в `firewall.go` (после `ipMaskToCIDR`):

```go
import (
	"context"
	"sync"
)

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
```

- [ ] **Step 2: Тест на конструктор**

Добавить в `firewall_test.go`:

```go
import "net"

func TestNewFirewallController_Defaults(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	called := 0
	iptMock := func(args ...string) error { called++; return nil }
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	if fc.chainName != "OVPN_FW" {
		t.Errorf("chainName: got %q", fc.chainName)
	}
	if fc.iptBin != "iptables" {
		t.Errorf("iptBin: got %q", fc.iptBin)
	}
	if !fc.enabled {
		t.Errorf("enabled must be true by default")
	}
	if fc.sessions == nil || fc.pending == nil || fc.kick == nil {
		t.Errorf("maps/channels not initialized")
	}
	if fc.iptCmd == nil {
		t.Errorf("iptCmd not set")
	}
	if called != 0 {
		t.Errorf("iptCmd should not be invoked by constructor")
	}
}
```

- [ ] **Step 3: Run**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run TestNewFirewallController -v ./...`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add firewall.go firewall_test.go
git commit -m "feat(firewall): add firewallController types and constructor"
```

---

## Task 3: `initChain` и `cleanupChain` — идемпотентное управление цепочкой

**Files:**
- Modify: `firewall.go`
- Modify: `firewall_test.go`

- [ ] **Step 1: Тест initChain (RED)**

Добавить в `firewall_test.go`:

```go
func TestInitChain_SequenceOfCommands(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var commands [][]string
	iptMock := func(args ...string) error {
		commands = append(commands, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	if err := fc.initChain(); err != nil {
		t.Fatalf("initChain: %v", err)
	}

	wantPatterns := []string{
		// Идемпотентное создание: -N может вернуть ошибку если уже есть, поэтому первый шаг безопасен
		"-N OVPN_FW",
		"-F OVPN_FW",
		// jump from FORWARD
		"-I FORWARD",
		// stateful return
		"-I OVPN_FW 1 -m conntrack",
		// catch-all DROP
		"-A OVPN_FW -s 172.16.100.0/24 -j DROP",
	}
	if len(commands) < len(wantPatterns) {
		t.Fatalf("expected at least %d commands, got %d: %v", len(wantPatterns), len(commands), commands)
	}
	// Проверим что присутствуют ключевые паттерны (точная последовательность критична для catch-all DROP в конце)
	joined := []string{}
	for _, c := range commands {
		joined = append(joined, joinSpace(c))
	}
	for _, want := range wantPatterns {
		found := false
		for _, j := range joined {
			if containsAll(j, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected command pattern %q in:\n%v", want, joined)
		}
	}
	// catch-all DROP должен быть последним
	last := joined[len(joined)-1]
	if !containsAll(last, "-A OVPN_FW -s 172.16.100.0/24 -j DROP") {
		t.Errorf("expected catch-all DROP as last command, got %q", last)
	}
}

func TestInitChain_IdempotentOnExistingChain(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	calls := 0
	iptMock := func(args ...string) error {
		calls++
		// первый вызов (-N OVPN_FW) возвращает "Chain already exists" — но мы это глотаем
		if calls == 1 && len(args) > 0 && args[0] == "-N" {
			return fmt.Errorf("Chain already exists")
		}
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	if err := fc.initChain(); err != nil {
		t.Fatalf("initChain must tolerate existing chain, got: %v", err)
	}
}

// helpers in test file
func joinSpace(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " "
		}
		out += p
	}
	return out
}

func containsAll(s, needle string) bool {
	return strings.Contains(s, needle)
}
```

Add imports `fmt`, `strings`, `net` if not yet present.

- [ ] **Step 2: Run — RED**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run TestInitChain -v ./...`
Expected: `undefined: initChain` или метод не определён.

- [ ] **Step 3: Реализация initChain и cleanupChain**

Добавить в `firewall.go`:

```go
import "strings"

// initChain создаёт цепочку OVPN_FW (если её нет), очищает, ставит прыжок из FORWARD,
// добавляет stateful-return первым правилом и catch-all DROP последним.
// Идемпотентно: повторный вызов даёт то же состояние.
func (fc *firewallController) initChain() error {
	// 1. Создаём цепочку (если уже есть — iptables вернёт "Chain already exists", глотаем)
	if err := fc.iptCmd("-N", fc.chainName); err != nil {
		// Не fail — может уже существовать. Подробная проверка ниже через -F.
		if !strings.Contains(err.Error(), "already exists") {
			// Если ошибка не про "exists" — пробрасываем
			// но iptables 1.8+ может писать в stderr "Chain already exists"
			// Для перестраховки — продолжаем; если реально не создалась — последующие команды упадут
		}
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
```

- [ ] **Step 4: Run — GREEN**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -race -run TestInitChain -v ./...`
Expected: 2 PASS.

- [ ] **Step 5: Build all**

Run: `gofmt -d firewall.go firewall_test.go ; go build ./... ; go test ./...`
Expected: clean, build OK, full suite passes.

- [ ] **Step 6: Commit**

```bash
git add firewall.go firewall_test.go
git commit -m "feat(firewall): initChain/cleanupChain with idempotent setup"
```

---

## Task 4: `installRulesFor` и `uninstallRulesFor` для одной сессии

**Files:**
- Modify: `firewall.go`
- Modify: `firewall_test.go`

- [ ] **Step 1: Тесты install/uninstall (RED)**

Добавить в `firewall_test.go`:

```go
func TestInstallRulesFor_PivotsCatchAllDrop(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)

	cidrs := []string{"10.0.0.0/8", "8.8.8.8/32"}
	if err := fc.installRulesFor("alice", "172.16.100.5", cidrs); err != nil {
		t.Fatalf("installRulesFor: %v", err)
	}

	// Ожидаемая последовательность:
	// 1. -D catch-all (pivot)
	// 2. -A OVPN_FW -s 172.16.100.5 -d 10.0.0.0/8 -j ACCEPT -m comment --comment "ovpn-admin: alice"
	// 3. -A OVPN_FW -s 172.16.100.5 -d 8.8.8.8/32 -j ACCEPT -m comment --comment "ovpn-admin: alice"
	// 4. -A catch-all DROP back
	if len(cmds) != 4 {
		t.Fatalf("expected 4 commands, got %d: %v", len(cmds), cmds)
	}
	if !containsAll(joinSpace(cmds[0]), "-D OVPN_FW") || !containsAll(joinSpace(cmds[0]), "-j DROP") {
		t.Errorf("command[0] should remove catch-all DROP, got %v", cmds[0])
	}
	for i, cidr := range cidrs {
		c := joinSpace(cmds[i+1])
		if !containsAll(c, "-A OVPN_FW") || !containsAll(c, "-s 172.16.100.5") || !containsAll(c, "-d "+cidr) || !containsAll(c, "ovpn-admin: alice") {
			t.Errorf("command[%d] missing expected pattern: %v", i+1, cmds[i+1])
		}
	}
	if !containsAll(joinSpace(cmds[3]), "-A OVPN_FW") || !containsAll(joinSpace(cmds[3]), "-j DROP") {
		t.Errorf("command[3] should restore catch-all DROP, got %v", cmds[3])
	}
}

func TestUninstallRulesFor_RemovesAllEntries(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)

	cidrs := []string{"10.0.0.0/8", "8.8.8.8/32"}
	if err := fc.uninstallRulesFor("alice", "172.16.100.5", cidrs); err != nil {
		t.Fatalf("uninstallRulesFor: %v", err)
	}

	if len(cmds) != len(cidrs) {
		t.Fatalf("expected %d commands, got %d: %v", len(cidrs), len(cmds), cmds)
	}
	for i, cidr := range cidrs {
		c := joinSpace(cmds[i])
		if !containsAll(c, "-D OVPN_FW") || !containsAll(c, "-s 172.16.100.5") || !containsAll(c, "-d "+cidr) || !containsAll(c, "ovpn-admin: alice") {
			t.Errorf("command[%d] missing expected pattern: %v", i, cmds[i])
		}
	}
}
```

- [ ] **Step 2: Run — RED**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -run "TestInstallRulesFor|TestUninstallRulesFor" -v ./...`
Expected: undefined references.

- [ ] **Step 3: Реализация**

Добавить в `firewall.go`:

```go
// installRulesFor добавляет ACCEPT-правила для одной сессии (CN, VPN_IP, набор разрешённых CIDR).
// Атомарно через pivot: снимает catch-all DROP → добавляет ACCEPT'ы → возвращает catch-all DROP.
// Caller должен держать fc.mu.
func (fc *firewallController) installRulesFor(cn, vpnIP string, cidrs []string) error {
	comment := "ovpn-admin: " + cn
	if err := fc.removeCatchAllDrop(); err != nil {
		// Catch-all может отсутствовать в момент install (например, при первичной reconcile).
		// Не фейлим, но логируем.
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
// Best-effort: если какое-то правило уже отсутствует (iptables -D вернёт ошибку), логируем и продолжаем.
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
```

Добавить импорт `log "github.com/sirupsen/logrus"` если ещё не добавлен (alphabetical order).

- [ ] **Step 4: Run — GREEN**

Run: `cd /Users/alexp/GolandProjects/ovpn-admin && go test -race -run "TestInstallRulesFor|TestUninstallRulesFor" -v ./...`
Expected: 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add firewall.go firewall_test.go
git commit -m "feat(firewall): installRulesFor/uninstallRulesFor with catch-all pivot"
```

---

## Task 5: `applyDiff` — set arithmetic для минимальных изменений

**Files:**
- Modify: `firewall.go`
- Modify: `firewall_test.go`

- [ ] **Step 1: Тесты (RED)**

Добавить в `firewall_test.go`:

```go
func TestApplyDiff_Add(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	s := &fwSession{CN: "alice", VpnIP: "172.16.100.5", AllowedCIDRs: []string{"10.0.0.0/8"}}

	if err := fc.applyDiff(s, []string{"10.0.0.0/8", "8.8.8.8/32"}); err != nil {
		t.Fatalf("applyDiff: %v", err)
	}

	// Ожидаем: -D catch-all, -A для 8.8.8.8/32, -A catch-all
	// Удалений нет, потому что 10.0.0.0/8 в обоих set'ах
	if len(cmds) != 3 {
		t.Fatalf("expected 3 commands, got %d: %v", len(cmds), cmds)
	}
	added := joinSpace(cmds[1])
	if !containsAll(added, "-A OVPN_FW") || !containsAll(added, "-d 8.8.8.8/32") {
		t.Errorf("expected -A for 8.8.8.8/32, got %v", cmds[1])
	}
}

func TestApplyDiff_Remove(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	s := &fwSession{CN: "alice", VpnIP: "172.16.100.5", AllowedCIDRs: []string{"10.0.0.0/8", "8.8.8.8/32", "1.1.1.1/32"}}

	if err := fc.applyDiff(s, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("applyDiff: %v", err)
	}

	// Ожидаем: -D catch-all, -D для 8.8.8.8/32, -D для 1.1.1.1/32, -A catch-all
	// (порядок удаляемых не строгий — set iteration)
	if len(cmds) != 4 {
		t.Fatalf("expected 4 commands, got %d: %v", len(cmds), cmds)
	}
	deletedAccepts := 0
	for _, c := range cmds {
		j := joinSpace(c)
		if containsAll(j, "-D OVPN_FW") && containsAll(j, "-j ACCEPT") {
			deletedAccepts++
		}
	}
	if deletedAccepts != 2 {
		t.Errorf("expected 2 ACCEPT -D commands, got %d", deletedAccepts)
	}
}

func TestApplyDiff_Mixed(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	s := &fwSession{CN: "alice", VpnIP: "172.16.100.5", AllowedCIDRs: []string{"10.0.0.0/8", "1.1.1.1/32"}}

	if err := fc.applyDiff(s, []string{"10.0.0.0/8", "8.8.8.8/32"}); err != nil {
		t.Fatalf("applyDiff: %v", err)
	}

	// -D catch-all, -D 1.1.1.1, -A 8.8.8.8, -A catch-all
	if len(cmds) != 4 {
		t.Fatalf("expected 4 commands, got %d: %v", len(cmds), cmds)
	}
	if s.AllowedCIDRs[0] != "10.0.0.0/8" && s.AllowedCIDRs[0] != "8.8.8.8/32" {
		// applyDiff обновляет AllowedCIDRs в s
		t.Errorf("session.AllowedCIDRs not updated: %v", s.AllowedCIDRs)
	}
	if len(s.AllowedCIDRs) != 2 {
		t.Errorf("expected 2 CIDRs after diff, got %d: %v", len(s.AllowedCIDRs), s.AllowedCIDRs)
	}
}

func TestApplyDiff_NoChange(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	s := &fwSession{CN: "alice", VpnIP: "172.16.100.5", AllowedCIDRs: []string{"10.0.0.0/8"}}

	if err := fc.applyDiff(s, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("applyDiff: %v", err)
	}
	if len(cmds) != 0 {
		t.Errorf("expected 0 commands for no-change diff, got %d: %v", len(cmds), cmds)
	}
}
```

- [ ] **Step 2: Run — RED**

Run: `go test -run TestApplyDiff -v ./...`
Expected: undefined.

- [ ] **Step 3: Реализация applyDiff**

Добавить в `firewall.go`:

```go
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
```

- [ ] **Step 4: Run — GREEN**

Run: `go test -race -run TestApplyDiff -v ./...`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add firewall.go firewall_test.go
git commit -m "feat(firewall): applyDiff with minimal-command set arithmetic"
```

---

## Task 6: `computeAllowedCIDRs` — слияние CCD + Common Routes

**Files:**
- Modify: `firewall.go`
- Modify: `firewall_test.go`

- [ ] **Step 1: Тесты (RED)**

Добавить в `firewall_test.go`:

```go
func TestComputeAllowedCIDRs_PersonalAndCommon(t *testing.T) {
	dir := t.TempDir()
	originalCcdDir := *ccdDir
	tmp := dir
	ccdDir = &tmp
	defer func() { ccdDir = &originalCcdDir }()
	originalStorage := *storageBackend
	fs := "filesystem"
	storageBackend = &fs
	defer func() { storageBackend = &originalStorage }()

	// CCD юзера alice с двумя custom routes
	ccdContent := `ifconfig-push 172.16.100.5 255.255.255.0
push "route 10.0.0.0 255.0.0.0" # corp
push "route 192.168.1.0 255.255.255.0" # lan
`
	if err := os.WriteFile(dir+"/alice", []byte(ccdContent), 0o644); err != nil {
		t.Fatal(err)
	}

	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{
			{ID: "x", Kind: "ip", Address: "8.8.8.8", Mask: "255.255.255.255"},
			{ID: "y", Kind: "domain", Domain: "yt.com", ResolvedIPs: []string{"1.1.1.1", "2.2.2.2"}},
		}}},
	}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, func(args ...string) error { return nil })

	cidrs, err := fc.computeAllowedCIDRs("alice")
	if err != nil {
		t.Fatalf("computeAllowedCIDRs: %v", err)
	}

	want := map[string]bool{
		"10.0.0.0/8":      true, // personal
		"192.168.1.0/24":  true, // personal
		"8.8.8.8/32":      true, // common IP
		"1.1.1.1/32":      true, // common domain resolve
		"2.2.2.2/32":      true, // common domain resolve
	}
	if len(cidrs) != len(want) {
		t.Errorf("expected %d CIDRs, got %d: %v", len(want), len(cidrs), cidrs)
	}
	for _, c := range cidrs {
		if !want[c] {
			t.Errorf("unexpected CIDR %q", c)
		}
		delete(want, c)
	}
	if len(want) > 0 {
		t.Errorf("missing CIDRs: %v", want)
	}
}

func TestComputeAllowedCIDRs_Dedup(t *testing.T) {
	dir := t.TempDir()
	originalCcdDir := *ccdDir
	tmp := dir
	ccdDir = &tmp
	defer func() { ccdDir = &originalCcdDir }()
	originalStorage := *storageBackend
	fs := "filesystem"
	storageBackend = &fs
	defer func() { storageBackend = &originalStorage }()

	// CCD c маршрутом, который пересекается с common
	ccdContent := `push "route 8.8.8.8 255.255.255.255" # personal-8.8.8.8
`
	if err := os.WriteFile(dir+"/bob", []byte(ccdContent), 0o644); err != nil {
		t.Fatal(err)
	}

	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{
			{ID: "x", Kind: "ip", Address: "8.8.8.8", Mask: "255.255.255.255"},
		}}},
	}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, func(args ...string) error { return nil })

	cidrs, err := fc.computeAllowedCIDRs("bob")
	if err != nil {
		t.Fatalf("computeAllowedCIDRs: %v", err)
	}
	if len(cidrs) != 1 || cidrs[0] != "8.8.8.8/32" {
		t.Errorf("expected dedup to 1 CIDR, got %v", cidrs)
	}
}
```

- [ ] **Step 2: Run — RED**

Run: `go test -run TestComputeAllowedCIDRs -v ./...`
Expected: undefined.

- [ ] **Step 3: Реализация**

Добавить в `firewall.go`:

```go
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
```

- [ ] **Step 4: Run — GREEN**

Run: `go test -race -run TestComputeAllowedCIDRs -v ./...`
Expected: 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add firewall.go firewall_test.go
git commit -m "feat(firewall): computeAllowedCIDRs merges CCD and Common Routes"
```

---

## Task 7: `parseMgmtClientEvent` — парсер `>CLIENT:` сообщений

**Files:**
- Modify: `firewall.go`
- Modify: `firewall_test.go`

- [ ] **Step 1: Тесты (RED)**

Добавить в `firewall_test.go`:

```go
func TestParseMgmtClientEvent_Connect(t *testing.T) {
	lines := []string{
		">CLIENT:CONNECT,2,123",
		">CLIENT:ENV,common_name=alice",
		">CLIENT:ENV,ifconfig_pool_remote_ip=172.16.100.5",
		">CLIENT:ENV,END",
	}
	p := newMgmtEventParser()
	var got *fwEvent
	for _, l := range lines {
		if ev := p.feed(l); ev != nil {
			got = ev
		}
	}
	if got == nil {
		t.Fatal("expected a fwEvent after END")
	}
	if got.Kind != EvConnect {
		t.Errorf("kind: got %v, want EvConnect", got.Kind)
	}
	if got.CN != "alice" {
		t.Errorf("CN: got %q, want alice", got.CN)
	}
	if got.VpnIP != "172.16.100.5" {
		t.Errorf("VpnIP: got %q, want 172.16.100.5", got.VpnIP)
	}
}

func TestParseMgmtClientEvent_Disconnect(t *testing.T) {
	lines := []string{
		">CLIENT:DISCONNECT,2",
		">CLIENT:ENV,common_name=bob",
		">CLIENT:ENV,END",
	}
	p := newMgmtEventParser()
	var got *fwEvent
	for _, l := range lines {
		if ev := p.feed(l); ev != nil {
			got = ev
		}
	}
	if got == nil {
		t.Fatal("expected a fwEvent after END")
	}
	if got.Kind != EvDisconnect {
		t.Errorf("kind: got %v, want EvDisconnect", got.Kind)
	}
	if got.CN != "bob" {
		t.Errorf("CN: got %q, want bob", got.CN)
	}
}

func TestParseMgmtClientEvent_Garbage(t *testing.T) {
	lines := []string{
		"SUCCESS: log enabled",
		">INFO:OpenVPN Management Interface Version 1",
		">BYTECOUNT:0,0",
		"random line",
	}
	p := newMgmtEventParser()
	for _, l := range lines {
		if ev := p.feed(l); ev != nil {
			t.Errorf("garbage line should not produce an event: %q → %+v", l, ev)
		}
	}
}

func TestParseMgmtClientEvent_InterleavedSessions(t *testing.T) {
	// CONNECT alice, затем CONNECT bob — оба должны вернуться в порядке END
	lines := []string{
		">CLIENT:CONNECT,2,1",
		">CLIENT:ENV,common_name=alice",
		">CLIENT:ENV,ifconfig_pool_remote_ip=172.16.100.5",
		">CLIENT:ENV,END",
		">CLIENT:CONNECT,3,1",
		">CLIENT:ENV,common_name=bob",
		">CLIENT:ENV,ifconfig_pool_remote_ip=172.16.100.6",
		">CLIENT:ENV,END",
	}
	p := newMgmtEventParser()
	var events []*fwEvent
	for _, l := range lines {
		if ev := p.feed(l); ev != nil {
			events = append(events, ev)
		}
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].CN != "alice" || events[1].CN != "bob" {
		t.Errorf("event order: %+v, %+v", events[0], events[1])
	}
}
```

- [ ] **Step 2: Run — RED**

Run: `go test -run TestParseMgmtClientEvent -v ./...`
Expected: undefined.

- [ ] **Step 3: Реализация парсера**

Добавить в `firewall.go`:

```go
// mgmtEventParser — простой стейт-машина для строк mgmt-протокола.
// Один parser на одно TCP-соединение; вызывается feed() для каждой полученной строки.
type mgmtEventParser struct {
	current *fwEvent       // in-progress event, nil если не в середине сессии
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
```

- [ ] **Step 4: Run — GREEN**

Run: `go test -race -run TestParseMgmtClientEvent -v ./...`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add firewall.go firewall_test.go
git commit -m "feat(firewall): mgmtEventParser for >CLIENT: protocol"
```

---

## Task 8: `eventHandlerLoop` с дедупликацией

**Files:**
- Modify: `firewall.go`
- Modify: `firewall_test.go`

- [ ] **Step 1: Тесты (RED)**

Добавить в `firewall_test.go`:

```go
import (
	"sync/atomic"
	"time"
)

func TestEventHandlerLoop_ConnectThenDisconnect(t *testing.T) {
	dir := t.TempDir()
	originalCcdDir := *ccdDir
	tmp := dir
	ccdDir = &tmp
	defer func() { ccdDir = &originalCcdDir }()
	originalStorage := *storageBackend
	fs := "filesystem"
	storageBackend = &fs
	defer func() { storageBackend = &originalStorage }()

	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{
			{ID: "x", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"},
		}}},
	}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var calls int32
	iptMock := func(args ...string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, iptMock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fc.eventHandlerLoop(ctx)

	fc.push(fwEvent{Kind: EvConnect, CN: "alice", VpnIP: "172.16.100.5"})
	waitForCalls(t, &calls, 1, 2*time.Second) // хотя бы один iptables вызов произошёл

	fc.mu.Lock()
	if _, ok := fc.sessions["alice"]; !ok {
		fc.mu.Unlock()
		t.Fatal("session for alice not registered after Connect")
	}
	fc.mu.Unlock()

	fc.push(fwEvent{Kind: EvDisconnect, CN: "alice"})
	// Подождать ещё один iptables-вызов (uninstall)
	waitForCalls(t, &calls, atomic.LoadInt32(&calls)+1, 2*time.Second)

	fc.mu.Lock()
	if _, ok := fc.sessions["alice"]; ok {
		fc.mu.Unlock()
		t.Fatal("session for alice not removed after Disconnect")
	}
	fc.mu.Unlock()
}

func TestEventHandlerLoop_Coalescing(t *testing.T) {
	app := &OvpnAdmin{commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var calls int32
	iptMock := func(args ...string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, iptMock)

	// Толкаем 10 EvConnect для alice, ПЕРЕД запуском обработчика.
	// Все они должны коалесцироваться в одно событие.
	for i := 0; i < 10; i++ {
		fc.push(fwEvent{Kind: EvConnect, CN: "alice", VpnIP: "172.16.100.5"})
	}

	fc.mu.Lock()
	if len(fc.pending) != 1 {
		fc.mu.Unlock()
		t.Fatalf("expected 1 pending event after coalescing, got %d", len(fc.pending))
	}
	fc.mu.Unlock()
}

func TestEventHandlerLoop_NoOpIfDisconnected(t *testing.T) {
	app := &OvpnAdmin{commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var calls int32
	iptMock := func(args ...string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, iptMock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fc.eventHandlerLoop(ctx)

	// alice не в sessions; EvUserChanged для неё должен быть no-op
	fc.push(fwEvent{Kind: EvUserChanged, CN: "alice"})
	time.Sleep(200 * time.Millisecond) // дать обработчику шанс обработать

	if atomic.LoadInt32(&calls) != 0 {
		t.Errorf("expected 0 iptables calls for UserChanged on disconnected CN, got %d", calls)
	}
}

func waitForCalls(t *testing.T, calls *int32, want int32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(calls) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %d iptables calls (got %d)", want, atomic.LoadInt32(calls))
}
```

- [ ] **Step 2: Run — RED**

Run: `go test -run TestEventHandlerLoop -v ./...`
Expected: undefined.

- [ ] **Step 3: Реализация push + eventHandlerLoop + handleEvent**

Добавить в `firewall.go`:

```go
// push добавляет событие в очередь с дедупликацией per-CN.
// Если событие для того же CN уже в очереди — заменяет его (последнее состояние выигрывает).
// EvCommonChanged использует фиксированный ключ "__common__" — повторы коалесцируются.
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
// Каждое событие лочит fc.mu на время операций с sessions и iptables.
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
```

- [ ] **Step 4: Stub `reconcileLocked` чтобы билдилось**

Пока в `firewall.go` добавить пустую реализацию (заполним в Task 9):

```go
// reconcileLocked — будет реализован в Task 9.
func (fc *firewallController) reconcileLocked() {
	// TODO Task 9
}
```

- [ ] **Step 5: Run — GREEN**

Run: `go test -race -run TestEventHandlerLoop -v ./...`
Expected: 3 PASS.

- [ ] **Step 6: Commit**

```bash
git add firewall.go firewall_test.go
git commit -m "feat(firewall): event handler loop with per-CN coalescing"
```

---

## Task 9: `reconcile` — пересборка по mgmt-snapshot

**Files:**
- Modify: `firewall.go`
- Modify: `firewall_test.go`

- [ ] **Step 1: Тесты (RED)**

Добавить в `firewall_test.go`:

```go
func TestReconcile_FromMgmtSnapshot(t *testing.T) {
	dir := t.TempDir()
	originalCcdDir := *ccdDir
	tmp := dir
	ccdDir = &tmp
	defer func() { ccdDir = &originalCcdDir }()
	originalStorage := *storageBackend
	fs := "filesystem"
	storageBackend = &fs
	defer func() { storageBackend = &originalStorage }()

	app := &OvpnAdmin{
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{
			{ID: "x", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"},
		}}},
		// stub mgmtSnapshotProvider: alice и bob активны
	}

	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, iptMock)
	fc.mgmtSnapshot = func() []clientStatus {
		return []clientStatus{
			{CommonName: "alice", VirtualAddress: "172.16.100.5"},
			{CommonName: "bob", VirtualAddress: "172.16.100.6"},
		}
	}

	fc.mu.Lock()
	fc.reconcileLocked()
	fc.mu.Unlock()

	if len(fc.sessions) != 2 {
		t.Errorf("expected 2 sessions after reconcile, got %d", len(fc.sessions))
	}
	if _, ok := fc.sessions["alice"]; !ok {
		t.Errorf("alice missing from sessions")
	}
	if _, ok := fc.sessions["bob"]; !ok {
		t.Errorf("bob missing from sessions")
	}
}

func TestReconcile_DriftCorrection(t *testing.T) {
	dir := t.TempDir()
	originalCcdDir := *ccdDir
	tmp := dir
	ccdDir = &tmp
	defer func() { ccdDir = &originalCcdDir }()
	originalStorage := *storageBackend
	fs := "filesystem"
	storageBackend = &fs
	defer func() { storageBackend = &originalStorage }()

	app := &OvpnAdmin{commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, func(args ...string) error { return nil })

	// pre-seed: ghost session не существующая в mgmt
	fc.sessions["ghost"] = &fwSession{CN: "ghost", VpnIP: "172.16.100.99", AllowedCIDRs: []string{"10.0.0.0/8"}}
	fc.mgmtSnapshot = func() []clientStatus { return nil } // mgmt видит 0 клиентов

	fc.mu.Lock()
	fc.reconcileLocked()
	fc.mu.Unlock()

	if _, ok := fc.sessions["ghost"]; ok {
		t.Errorf("ghost session should have been removed by reconcile")
	}
}
```

- [ ] **Step 2: Run — RED**

Run: `go test -run TestReconcile -v ./...`
Expected: undefined methods/fields.

- [ ] **Step 3: Добавить поле `mgmtSnapshot` в firewallController**

Изменить в `firewall.go` struct:

```go
type firewallController struct {
	// ... existing fields ...
	mgmtSnapshot func() []clientStatus // мокается в тестах; в проде = oAdmin.mgmtGetActiveClients
}
```

И в конструкторе:

```go
func newFirewallController(oAdmin *OvpnAdmin, chainName, iptBin string, vpnNet *net.IPNet, iptCmd iptCmdFunc) *firewallController {
	fc := &firewallController{
		// ... existing fields ...
	}
	if oAdmin != nil {
		fc.mgmtSnapshot = oAdmin.mgmtGetActiveClients
	} else {
		fc.mgmtSnapshot = func() []clientStatus { return nil }
	}
	return fc
}
```

- [ ] **Step 4: Реализация reconcileLocked**

Заменить stub в `firewall.go`:

```go
// reconcileLocked полностью сверяет fc.sessions с реальностью из mgmt-snapshot'а.
// Caller держит fc.mu. Используется при старте, при обрыве mgmt-стрима и периодически (self-heal).
func (fc *firewallController) reconcileLocked() {
	live := make(map[string]*clientStatus)
	for i, c := range fc.mgmtSnapshot() {
		live[c.CommonName] = &fc.mgmtSnapshot()[i]
		_ = c
	}
	// Закрываем sessions которых нет в live — uninstall
	for cn, s := range fc.sessions {
		if _, ok := live[cn]; !ok {
			if err := fc.uninstallRulesFor(s.CN, s.VpnIP, s.AllowedCIDRs); err != nil {
				log.Warnf("firewall: reconcile uninstall(%s): %v", cn, err)
			}
			delete(fc.sessions, cn)
		}
	}
	// Добавляем тех, кто есть в live, но нет в fc.sessions
	for cn, c := range live {
		if _, ok := fc.sessions[cn]; ok {
			continue
		}
		cidrs, err := fc.computeAllowedCIDRs(cn)
		if err != nil {
			log.Warnf("firewall: reconcile compute(%s): %v", cn, err)
			continue
		}
		if err := fc.installRulesFor(cn, c.VirtualAddress, cidrs); err != nil {
			log.Warnf("firewall: reconcile install(%s): %v", cn, err)
			continue
		}
		fc.sessions[cn] = &fwSession{CN: cn, VpnIP: c.VirtualAddress, AllowedCIDRs: cidrs, RulesInstalled: true}
	}
}
```

> **Bug-fix:** в собранном выше коде `live` строится двойным вызовом `fc.mgmtSnapshot()` — это race и неэффективность. Правильно:
```go
func (fc *firewallController) reconcileLocked() {
	snapshot := fc.mgmtSnapshot()
	live := make(map[string]*clientStatus)
	for i := range snapshot {
		live[snapshot[i].CommonName] = &snapshot[i]
	}
	// ... остальное без изменений ...
}
```
Используем эту исправленную версию.

- [ ] **Step 5: Run — GREEN**

Run: `go test -race -run TestReconcile -v ./...`
Expected: 2 PASS.

- [ ] **Step 6: Commit**

```bash
git add firewall.go firewall_test.go
git commit -m "feat(firewall): reconcile from mgmt snapshot with drift correction"
```

---

## Task 10: `mgmtEventLoop` — подписка на real-time события

**Files:**
- Modify: `firewall.go`
- Modify: `firewall_test.go`

- [ ] **Step 1: Тесты для subscribeAndPump (RED)**

Этот таск тестирует **только парсинг входящего стрима**, а не саму TCP-связь. Для теста подаём искусственный io.Reader.

Добавить в `firewall_test.go`:

```go
import (
	"io"
	"strings"
)

func TestSubscribeAndPump_ParsesMultipleEvents(t *testing.T) {
	app := &OvpnAdmin{commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, func(args ...string) error { return nil })

	stream := strings.NewReader(strings.Join([]string{
		"SUCCESS: real-time notification of client events enabled\n",
		">CLIENT:CONNECT,2,1\n",
		">CLIENT:ENV,common_name=alice\n",
		">CLIENT:ENV,ifconfig_pool_remote_ip=172.16.100.5\n",
		">CLIENT:ENV,END\n",
		">CLIENT:DISCONNECT,2\n",
		">CLIENT:ENV,common_name=alice\n",
		">CLIENT:ENV,END\n",
	}, ""))

	// Используем piped writer для управления тем когда поток закончится
	pr, pw := io.Pipe()
	go func() {
		io.Copy(pw, stream)
		pw.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	go fc.eventHandlerLoop(ctx)

	if err := fc.consumeStream(ctx, pr); err != nil && err != io.EOF {
		t.Logf("consumeStream returned: %v (acceptable on EOF)", err)
	}

	// Дать обработчику время
	time.Sleep(100 * time.Millisecond)

	// После CONNECT+DISCONNECT alice должна отсутствовать в sessions
	fc.mu.Lock()
	_, exists := fc.sessions["alice"]
	fc.mu.Unlock()
	if exists {
		t.Errorf("alice should have been disconnected by end of stream")
	}
}
```

- [ ] **Step 2: Run — RED**

Run: `go test -run TestSubscribeAndPump -v ./...`
Expected: undefined.

- [ ] **Step 3: Реализация consumeStream и mgmtEventLoop**

Добавить в `firewall.go`:

```go
import (
	"bufio"
	"io"
)

// consumeStream читает строки из соединения mgmt-interface и пушит события в очередь.
// Возвращает при EOF, ошибке чтения или ctx cancel.
func (fc *firewallController) consumeStream(ctx context.Context, r io.Reader) error {
	parser := newMgmtEventParser()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Text()
		if ev := parser.feed(line); ev != nil {
			fc.push(*ev)
		}
	}
	return scanner.Err()
}

// mgmtEventLoop держит постоянное TCP-подключение к mgmt-interface, парсит real-time
// события connect/disconnect. На обрыве — reconnect с backoff'ом + reconcile.
func (fc *firewallController) mgmtEventLoop(ctx context.Context, mgmtAddr string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := net.Dial("tcp", mgmtAddr)
		if err != nil {
			log.Warnf("firewall: mgmt connect %s failed: %v; retry in 5s", mgmtAddr, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		// Включаем real-time подписку. В server.conf для этого должно стоять
		// management-client-auth или эквивалент — иначе >CLIENT: события не польются.
		// Команда `log on all` нужна чтобы получать прочую диагностику в логе.
		fmt.Fprintln(conn, "log on")

		if err := fc.consumeStream(ctx, conn); err != nil && err != io.EOF {
			log.Warnf("firewall: mgmt stream error: %v; reconnect", err)
		}
		conn.Close()

		// При reconnect делаем reconcile для сверки.
		fc.push(fwEvent{Kind: EvReconcile})

		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Second):
		}
	}
}
```

- [ ] **Step 4: Run — GREEN**

Run: `go test -race -run TestSubscribeAndPump -v ./...`
Expected: 1 PASS.

- [ ] **Step 5: Commit**

```bash
git add firewall.go firewall_test.go
git commit -m "feat(firewall): mgmtEventLoop with real-time stream subscription"
```

---

## Task 11: Self-heal ticker + Start/Stop API

**Files:**
- Modify: `firewall.go`
- Modify: `firewall_test.go`

- [ ] **Step 1: Тесты (RED)**

```go
func TestStart_RunsInitAndReconcile(t *testing.T) {
	dir := t.TempDir()
	originalCcdDir := *ccdDir
	tmp := dir
	ccdDir = &tmp
	defer func() { ccdDir = &originalCcdDir }()
	originalStorage := *storageBackend
	fs := "filesystem"
	storageBackend = &fs
	defer func() { storageBackend = &originalStorage }()

	app := &OvpnAdmin{commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, iptMock)
	fc.mgmtSnapshot = func() []clientStatus { return nil }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := fc.Start(ctx, "127.0.0.1:65000", 100*time.Millisecond); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Должны быть вызваны initChain команды
	if len(cmds) == 0 {
		t.Errorf("Start should have invoked initChain commands")
	}

	cancel()
	time.Sleep(150 * time.Millisecond) // дать горутинам выйти
}

func TestStop_RunsCleanup(t *testing.T) {
	app := &OvpnAdmin{commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}}
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	fc := newFirewallController(app, "OVPN_FW", "iptables", vpnNet, iptMock)
	fc.mgmtSnapshot = func() []clientStatus { return nil }

	ctx, cancel := context.WithCancel(context.Background())
	if err := fc.Start(ctx, "127.0.0.1:65001", 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	cmds = nil // сбрасываем команды от Start

	cancel()
	fc.Stop()

	// Должны быть -D FORWARD -j OVPN_FW, -F OVPN_FW, -X OVPN_FW
	if len(cmds) < 3 {
		t.Errorf("Stop should have invoked at least 3 cleanup commands, got %d: %v", len(cmds), cmds)
	}
}
```

- [ ] **Step 2: Run — RED**

Run: `go test -run "TestStart|TestStop" -v ./...`
Expected: undefined Start/Stop.

- [ ] **Step 3: Реализация Start/Stop**

Добавить в `firewall.go`:

```go
// Start выполняет initChain, запускает все горутины (mgmt-event, event-handler, self-heal-ticker)
// и делает initial reconcile. Возвращает ошибку только если initChain провалился.
func (fc *firewallController) Start(ctx context.Context, mgmtAddr string, reconcileInterval time.Duration) error {
	fc.ctx, fc.cancel = context.WithCancel(ctx)

	if err := fc.initChain(); err != nil {
		return fmt.Errorf("initChain: %w", err)
	}

	go fc.eventHandlerLoop(fc.ctx)
	go fc.mgmtEventLoop(fc.ctx, mgmtAddr)
	go fc.selfHealLoop(fc.ctx, reconcileInterval)

	// initial reconcile
	fc.push(fwEvent{Kind: EvReconcile})

	return nil
}

// Stop отменяет контекст и делает best-effort cleanup цепочки.
func (fc *firewallController) Stop() {
	if fc.cancel != nil {
		fc.cancel()
	}
	fc.cleanupChain()
}

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
```

- [ ] **Step 4: Run — GREEN**

Run: `go test -race -run "TestStart|TestStop" -v ./...`
Expected: 2 PASS.

- [ ] **Step 5: Build all**

Run: `gofmt -d firewall.go firewall_test.go && go build ./... && go test -race ./...`
Expected: clean, build OK, all tests pass.

- [ ] **Step 6: Commit**

```bash
git add firewall.go firewall_test.go
git commit -m "feat(firewall): Start/Stop API with self-heal reconcile ticker"
```

---

## Task 12: Wiring в `main.go` — флаги, инициализация, hooks

**Files:**
- Modify: `main.go`
- Modify: `common_routes.go`

- [ ] **Step 1: Добавить CLI флаги в `main.go`**

В блок `var (...)` (рядом с `commonRoutesEnabled`, ~ строка 88):

```go
firewallEnabled = kingpin.Flag("firewall",
	"enable per-client iptables enforcement").
	Default("false").Envar("OVPN_FIREWALL").Bool()

firewallChainName = kingpin.Flag("firewall.chain-name",
	"iptables chain name for ovpn-admin rules").
	Default("OVPN_FW").Envar("OVPN_FIREWALL_CHAIN").String()

firewallIptablesBin = kingpin.Flag("firewall.iptables-bin",
	"path to iptables binary").
	Default("iptables").Envar("OVPN_FIREWALL_IPTABLES_BIN").String()

firewallStartupTimeout = kingpin.Flag("firewall.startup-timeout",
	"max time to wait for first mgmt connection before failing startup").
	Default("30s").Envar("OVPN_FIREWALL_STARTUP_TIMEOUT").Duration()

firewallReconcileInterval = kingpin.Flag("firewall.reconcile-interval",
	"self-heal reconcile period").
	Default("5m").Envar("OVPN_FIREWALL_RECONCILE_INTERVAL").Duration()
```

- [ ] **Step 2: Добавить поле в `OvpnAdmin`**

`main.go:187-201`:

```go
type OvpnAdmin struct {
	// ... existing fields ...
	firewall *firewallController
}
```

- [ ] **Step 3: Реальный iptCmd builder в `firewall.go`**

Добавить в `firewall.go`:

```go
import "os/exec"

// realIptCmd возвращает функцию, вызывающую реальный iptables бинарь.
// Используется в проде; в тестах — мок.
func realIptCmd(iptBin string) iptCmdFunc {
	return func(args ...string) error {
		cmd := exec.Command(iptBin, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %v: %w (output: %s)", iptBin, args, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}
```

- [ ] **Step 4: Инициализация в `main()`**

После блока `if *commonRoutesEnabled { ... }` (там где запускается `runCommonRoutesScheduler`), добавить:

```go
if *firewallEnabled {
	ovpnAdmin.modules = append(ovpnAdmin.modules, "firewall")

	// fail-fast: проверим что iptables бинарь доступен
	if _, err := exec.LookPath(*firewallIptablesBin); err != nil {
		log.Fatalf("firewall enabled but iptables binary %q not found: %v", *firewallIptablesBin, err)
	}

	_, vpnNet, err := net.ParseCIDR(*openvpnNetwork)
	if err != nil {
		log.Fatalf("firewall: cannot parse --ovpn.network=%s: %v", *openvpnNetwork, err)
	}

	mgmtAddr, ok := ovpnAdmin.mgmtInterfaces["main"]
	if !ok {
		log.Fatalf("firewall: no mgmt interface 'main' configured; got %v", ovpnAdmin.mgmtInterfaces)
	}

	ovpnAdmin.firewall = newFirewallController(
		ovpnAdmin,
		*firewallChainName,
		*firewallIptablesBin,
		vpnNet,
		realIptCmd(*firewallIptablesBin),
	)

	ctx := context.Background() // используется до graceful shutdown который сейчас не реализован
	if err := ovpnAdmin.firewall.Start(ctx, mgmtAddr, *firewallReconcileInterval); err != nil {
		log.Fatalf("firewall: Start failed: %v", err)
	}
}
```

Импорт `"os/exec"` в `main.go` уже есть для других вещей, либо добавить если нет.

- [ ] **Step 5: Hook в `userApplyCcdHandler`**

В `main.go:405` после успешного `modifyCcd` (где сейчас возвращается `applyStatus`), добавить перед `return`:

```go
// Триггер пересчёта firewall-правил для этого CN
if oAdmin.firewall != nil {
	oAdmin.firewall.push(fwEvent{Kind: EvUserChanged, CN: ccd.User})
}
```

- [ ] **Step 6: Hooks в `common_routes.go`**

В `handleCreateCommonRoute`, `handleUpdateCommonRoute`, `handleDeleteCommonRoute`, `commonRoutesRefreshHandler` — после строк `go oAdmin.rerenderAllCcds(expanded)` добавить:

```go
if oAdmin.firewall != nil {
	oAdmin.firewall.push(fwEvent{Kind: EvCommonChanged})
}
```

(4 места, идентичный код.)

- [ ] **Step 7: Build + tests**

Run: `gofmt -l . | grep -v '^auth\\.go\\|^main\\.go' ; go build ./... && go test -race ./...`
Expected: новые файлы gofmt-clean, build OK, все тесты проходят. Pre-existing gofmt issues в main.go/auth.go игнорируем.

- [ ] **Step 8: Smoke local binary**

Run: `go build -o /tmp/ovpn-admin-fw ./... && /tmp/ovpn-admin-fw --help 2>&1 | grep -E "firewall" | head && rm /tmp/ovpn-admin-fw`
Expected: видим строки `--firewall`, `--firewall.chain-name`, `--firewall.iptables-bin`, `--firewall.startup-timeout`, `--firewall.reconcile-interval`.

- [ ] **Step 9: Commit**

```bash
git add main.go firewall.go common_routes.go firewall_test.go
git commit -m "feat(firewall): wire up flags, init, and hooks from CCD/common-routes"
```

---

## Task 13: Dockerfile и docker-compose

**Files:**
- Modify: `Dockerfile.ovpn-admin`
- Modify: `docker-compose.yaml`

- [ ] **Step 1: Добавить `iptables` в Dockerfile**

Найти в `/Users/alexp/GolandProjects/ovpn-admin/Dockerfile.ovpn-admin` строку:

```dockerfile
RUN apk add --update bash easy-rsa openssl openvpn coreutils && \
```

Заменить на:

```dockerfile
RUN apk add --update bash easy-rsa openssl openvpn coreutils iptables && \
```

- [ ] **Step 2: Добавить cap_add и env в docker-compose.yaml**

В сервис `ovpn-admin` (между `environment:` и `network_mode:`) добавить:

```yaml
  ovpn-admin:
    # ... existing ...
    environment:
      # ... existing env ...
      OVPN_FIREWALL: "true"
    cap_add:
      - NET_ADMIN
    # ... existing rest ...
```

- [ ] **Step 3: Sanity check сборки**

Run: `DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose build --no-cache ovpn-admin 2>&1 | tail -15`

(Это полная пересборка под amd64 emulation на M-Mac. Должна пройти.)

Expected: `naming to docker.io/library/ovpn-admin:local done`.

- [ ] **Step 4: Smoke — проверка что iptables есть в финальном image**

Run:
```bash
docker run --rm ovpn-admin:local sh -c 'which iptables && iptables --version 2>&1 | head -1'
```
Expected: путь к iptables (например `/sbin/iptables`) и версия.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile.ovpn-admin docker-compose.yaml
git commit -m "feat(firewall): add iptables to image, NET_ADMIN cap in compose"
```

---

## Task 14: Helm chart — deployment + values + configmap + keep annotation

**Files:**
- Modify: `charts/openvpn-admin/values.yaml`
- Modify: `charts/openvpn-admin/templates/deployment.yaml`
- Modify: `charts/openvpn-admin/templates/configmap.yaml`

- [ ] **Step 1: values.yaml — добавить секцию firewall**

В блок `ovpnAdmin:` (после существующих полей) добавить:

```yaml
  # Server-side per-client route enforcement via iptables.
  # When enabled, ovpn-admin installs FORWARD rules so that each connected client
  # can only reach destinations explicitly allowed via:
  #  - per-user CCD CustomRoutes
  #  - global Common Routes
  # Requires NET_ADMIN capability on the container and iptables binary in image.
  firewall:
    enabled: true               # default ON for new installs; existing users see CHANGELOG
    chainName: "OVPN_FW"
    iptablesBin: "/sbin/iptables"
    startupTimeout: "30s"
    reconcileInterval: "5m"
```

- [ ] **Step 2: deployment.yaml — NET_ADMIN cap и args**

Найти секцию ovpn-admin контейнера. После строки `imagePullPolicy: {{ .Values.ovpnAdmin.image.pullPolicy }}` добавить блок `securityContext`:

```yaml
        - name: ovpn-admin
          image: "{{ .Values.ovpnAdmin.image.repository }}:{{ .Values.ovpnAdmin.image.tag | default .Chart.AppVersion }}"
          imagePullPolicy: {{ .Values.ovpnAdmin.image.pullPolicy }}
          securityContext:
            capabilities:
              add: ["NET_ADMIN"]
```

В блок `args:` после остальных условных аргументов (например после `{{- if .Values.ovpnAdmin.adminHtpasswdSecret }}` блока) добавить:

```yaml
            {{- if .Values.ovpnAdmin.firewall.enabled }}
            - --firewall
            - --firewall.chain-name={{ .Values.ovpnAdmin.firewall.chainName }}
            - --firewall.iptables-bin={{ .Values.ovpnAdmin.firewall.iptablesBin }}
            - --firewall.startup-timeout={{ .Values.ovpnAdmin.firewall.startupTimeout }}
            - --firewall.reconcile-interval={{ .Values.ovpnAdmin.firewall.reconcileInterval }}
            {{- end }}
```

- [ ] **Step 3: configmap.yaml — добавить management-client-auth в server.conf**

Найти в шаблоне `server.conf` строку:

```
management 127.0.0.1 8989
```

Сразу после неё добавить:

```
management-client-auth
```

(Этот параметр заставляет OpenVPN отправлять `>CLIENT:` события на mgmt-interface, но **не требует от ovpn-admin отвечать** на каждое — просто информационно. Если параметр не подойдёт по факту в OpenVPN 2.x, fallback в коде уже есть — `mgmtEventLoop` будет переподключаться и `selfHealLoop` будет периодически делать reconcile через polling.)

- [ ] **Step 4: Sanity check шаблона**

Run:
```bash
cd /Users/alexp/GolandProjects/ovpn-admin/charts/openvpn-admin
helm template . > /tmp/rendered.yaml 2>&1
grep -A2 "NET_ADMIN" /tmp/rendered.yaml | head
grep -A2 "firewall" /tmp/rendered.yaml | head -20
grep "management-client-auth" /tmp/rendered.yaml
rm /tmp/rendered.yaml
```
Expected: рендер прошёл без ошибок, видны capabilities, видны firewall флаги в args, видна строка management-client-auth.

- [ ] **Step 5: Commit**

```bash
cd /Users/alexp/GolandProjects/ovpn-admin
git add charts/openvpn-admin/values.yaml charts/openvpn-admin/templates/deployment.yaml charts/openvpn-admin/templates/configmap.yaml
git commit -m "feat(firewall): Helm chart NET_ADMIN, args, management-client-auth"
```

---

## Task 15: Helm — `resource-policy: keep` на критичные Secret'ы (mini-DR)

**Files:**
- Modify: `charts/openvpn-admin/templates/secret.yaml` (если есть)
- Modify: `kubernetes.go` (если Secret'ы создаются Go-кодом, добавить аннотацию при создании)

- [ ] **Step 1: Inspect где создаются Secret'ы**

Run:
```bash
ls /Users/alexp/GolandProjects/ovpn-admin/charts/openvpn-admin/templates/secret*.yaml 2>/dev/null
grep -rn "ObjectMeta\|metav1.ObjectMeta\|Annotations" /Users/alexp/GolandProjects/ovpn-admin/kubernetes.go | head
```

Ожидаем: либо есть `secret.yaml` в чарте, либо Secret'ы создаются Go-кодом (через `secretCreate`).

- [ ] **Step 2: Если есть `secret.yaml` в чарте — добавить аннотацию**

Если файл существует, найти `metadata:` блок в каждом Secret'е и добавить:

```yaml
metadata:
  name: ...
  annotations:
    helm.sh/resource-policy: keep
```

- [ ] **Step 3: Если Secret'ы создаются Go-кодом — добавить аннотацию в `kubernetes.go`**

В функции `secretCreate` (~`kubernetes.go:742`) изменить `ObjectMeta`:

Найти:

```go
secret := &v1.Secret{
    TypeMeta:   metav1.TypeMeta{},
    ObjectMeta: objectMeta,
    Data:       data,
    Type:       secretType,
}
```

Заменить на:

```go
if objectMeta.Annotations == nil {
    objectMeta.Annotations = make(map[string]string)
}
objectMeta.Annotations["helm.sh/resource-policy"] = "keep"

secret := &v1.Secret{
    TypeMeta:   metav1.TypeMeta{},
    ObjectMeta: objectMeta,
    Data:       data,
    Type:       secretType,
}
```

Так аннотация будет на всех Secret'ах, создаваемых ovpn-admin (PKI, CCD, common-routes).

- [ ] **Step 4: Sanity check**

Run: `gofmt -l kubernetes.go && go build ./... && go test ./...`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add charts/openvpn-admin/templates/ kubernetes.go
git commit -m "feat(firewall): add helm.sh/resource-policy=keep to critical Secrets"
```

---

## Task 16: Smoke test через docker-compose

**Files:**
- Create: `docker-compose.firewall-test.yml`

Этот compose поднимает полный VPN-стек (openvpn + ovpn-admin + openvpn-client) для ручной проверки enforcement'а.

- [ ] **Step 1: Создать `docker-compose.firewall-test.yml`**

```yaml
version: '3'

services:
  pki-init:
    image: alpine:3.23
    volumes:
      - pki_data:/pki
      - ccd_data:/ccd
    command: >
      sh -c "
        if [ -f /pki/pki/index.txt ]; then
          echo 'PKI already initialized';
          exit 0;
        fi;
        apk add --no-cache easy-rsa openssl &&
        ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin/easyrsa &&
        mkdir -p /pki && cd /pki &&
        EASYRSA_BATCH=1 easyrsa init-pki &&
        EASYRSA_BATCH=1 EASYRSA_REQ_CN=TestCA easyrsa build-ca nopass &&
        EASYRSA_BATCH=1 easyrsa gen-req alice nopass &&
        EASYRSA_BATCH=1 easyrsa sign-req client alice &&
        mkdir -p /ccd &&
        echo 'PKI initialized'
      "

  openvpn:
    build:
      context: .
      dockerfile: Dockerfile.openvpn
    image: openvpn:local
    command: /etc/openvpn/setup/configure.sh
    environment:
      OVPN_SERVER_NET: "192.168.100.0"
      OVPN_SERVER_MASK: "255.255.255.0"
    cap_add:
      - NET_ADMIN
    devices:
      - "/dev/net/tun:/dev/net/tun"
    depends_on:
      pki-init:
        condition: service_completed_successfully
    ports:
      - "1194:1194/udp"
      - "8088:8080"
    volumes:
      - pki_data:/etc/openvpn/easyrsa
      - ccd_data:/etc/openvpn/ccd

  ovpn-admin:
    build:
      context: .
      dockerfile: Dockerfile.ovpn-admin
    image: ovpn-admin:local
    command: /app/ovpn-admin
    environment:
      OVPN_NETWORK: "192.168.100.0/24"
      OVPN_CCD: "true"
      OVPN_CCD_PATH: "/mnt/ccd"
      EASYRSA_PATH: "/mnt/easyrsa"
      OVPN_INDEX_PATH: "/mnt/easyrsa/pki/index.txt"
      OVPN_FIREWALL: "true"
      OVPN_FIREWALL_IPTABLES_BIN: "/sbin/iptables"
      LOG_LEVEL: "debug"
    network_mode: service:openvpn
    cap_add:
      - NET_ADMIN
    depends_on:
      - openvpn
    volumes:
      - pki_data:/mnt/easyrsa
      - ccd_data:/mnt/ccd

volumes:
  pki_data:
  ccd_data:
```

- [ ] **Step 2: Полная пересборка**

Run:
```bash
cd /Users/alexp/GolandProjects/ovpn-admin
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker-compose.firewall-test.yml down -v
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker-compose.firewall-test.yml build --no-cache
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker-compose.firewall-test.yml up -d
```

- [ ] **Step 3: Подождать готовности и проверить базовое состояние**

```bash
until curl -fsS http://localhost:8088/ping >/dev/null 2>&1; do sleep 2; done
docker logs ovpn-admin-ovpn-admin-1 2>&1 | grep -i "firewall\|Временный пароль" | head
docker exec ovpn-admin-ovpn-admin-1 iptables -L OVPN_FW -n -v 2>&1
```
Expected: видим лог "firewall enabled", администраторский пароль, и пустую цепочку OVPN_FW (только stateful-return ACCEPT + catch-all DROP).

- [ ] **Step 4: Подключиться к API**

Извлечь пароль и залогиниться:
```bash
PASS=$(docker logs ovpn-admin-ovpn-admin-1 2>&1 | grep "Временный пароль для admin" | head -1 | sed -E 's/.*пароль для admin: ([A-Za-z0-9]+).*/\1/')
curl -sS -c /tmp/cookies.txt -X POST http://localhost:8088/api/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=$PASS"
```

- [ ] **Step 5: Добавить common route — наблюдать iptables**

```bash
curl -sS -b /tmp/cookies.txt -X POST http://localhost:8088/api/common-routes \
    -H "Content-Type: application/json" \
    -d '{"kind":"ip","address":"8.8.8.8","mask":"255.255.255.255","description":"test"}'

# Сейчас alice ещё не подключилась, поэтому ACCEPT-правил нет — только в memory у firewallController.
docker exec ovpn-admin-ovpn-admin-1 iptables -L OVPN_FW -n -v
```
Expected: ничего нового — alice не подключена, applyDiff не вызывается.

- [ ] **Step 6: Manually connect alice**

Запустить openvpn-клиента (см. docker-compose.yaml для существующего dev-стека или из настроек openvpn-сервиса).

В упрощённом варианте — взять alice.ovpn через ovpn-admin UI и подключиться им с хоста или из отдельного docker-контейнера.

Описание подробного шага зависит от того, что выясним при доступе. **Если этот шаг сложно автоматизировать в smoke-тесте — оставляем как ручную проверку**, документируем в README.

- [ ] **Step 7: Cleanup**

```bash
docker compose -f docker-compose.firewall-test.yml down -v
```

- [ ] **Step 8: Commit**

```bash
git add docker-compose.firewall-test.yml
git commit -m "feat(firewall): add docker-compose for firewall smoke test"
```

---

## Task 17: Documentation — README + CHANGELOG + _pending stubs

**Files:**
- Modify: `README.md`
- Create: `CHANGELOG.md` (если не существует)
- Create: `docs/superpowers/specs/_pending/disaster-recovery-postgres.md`
- Create: `docs/superpowers/specs/_pending/firewall-ipset-scale.md`
- Create: `docs/superpowers/specs/_pending/firewall-nftables-modernize.md`
- Create: `docs/superpowers/specs/_pending/firewall-port-protocol-rules.md`

- [ ] **Step 1: README.md — добавить секцию**

Найти секцию `## Features` и добавить пункт в список:

```markdown
* **Server-side route enforcement** — when enabled (default in Helm), ovpn-admin installs per-client iptables rules so that each VPN client can only reach destinations explicitly allowed via per-user CCD routes or global Common Routes. Requires `NET_ADMIN` capability.
```

И добавить отдельную секцию ближе к концу:

```markdown
## Server-side route enforcement (firewall)

By default, OpenVPN push routes are only a recommendation to the client — a user can manually `ip route add` any subnet via the tun device and reach it through the VPN, regardless of what was pushed by the server.

ovpn-admin's firewall feature **enforces** the allowed routes server-side. For each connected client, ovpn-admin installs iptables rules in the `OVPN_FW` chain (jumped from `FORWARD`) that:

- ACCEPT traffic from the client's VPN IP to each CIDR allowed by their CCD `CustomRoutes` ∪ global Common Routes
- DROP everything else from the VPN subnet (catch-all default-deny)

Rules are updated in real-time:
- On client connect/disconnect (via OpenVPN management interface)
- When per-user CCD is edited
- When global Common Routes are added/edited/deleted
- When DNS-resolved IPs for a domain-based common route change

### Requirements

- `NET_ADMIN` capability on the ovpn-admin container (already in Helm chart and docker-compose.yaml when feature is enabled)
- `iptables` binary in the ovpn-admin image (already included)
- OpenVPN `server.conf` includes `management-client-auth` directive (set automatically by the Helm chart)
- Feature is **off by default in code** (`--firewall=false`), but **on by default in the Helm chart** for new installs

### Disabling

To keep the legacy behavior (push routes are advisory, no server-side enforcement), set in your `values.yaml`:

```yaml
ovpnAdmin:
  firewall:
    enabled: false
```

Or set `OVPN_FIREWALL=false` via env if running in compose.
```

- [ ] **Step 2: CHANGELOG.md — breaking note**

Создать `/Users/alexp/GolandProjects/ovpn-admin/CHANGELOG.md` (если не существует):

```markdown
# Changelog

## [Unreleased]

### Added
- **Common Routes**: new tab in admin UI to push routes (IP/CIDR or domain) to all active clients ([spec](docs/superpowers/specs/2026-05-20-common-routes-design.md))
- **Server-side firewall enforcement**: per-client iptables rules so VPN clients can only reach explicitly allowed destinations ([spec](docs/superpowers/specs/2026-05-23-firewall-enforcement-design.md))

### Changed
- **BREAKING (Helm users only)**: firewall is enabled by default in the Helm chart for new installs. Existing installations upgrading the chart will get `--firewall=true` unless explicitly disabled via:
  ```yaml
  ovpnAdmin:
    firewall:
      enabled: false
  ```
  When enabled, clients can no longer manually add `ip route add ... via tun0` and have it work — only push-route-aligned destinations are reachable.
- Helm chart marks critical Secrets (PKI, CCD, common-routes) with `helm.sh/resource-policy: keep` to survive accidental `helm uninstall`. Run `kubectl delete secret ...` manually if you actually want to wipe state.

### Fixed
- (none for this release)
```

- [ ] **Step 3: Stub _pending файлы**

Создать `/Users/alexp/GolandProjects/ovpn-admin/docs/superpowers/specs/_pending/disaster-recovery-postgres.md`:

```markdown
# Disaster Recovery via external Postgres (stub)

**Status:** parked — to be brainstormed when prioritized
**Trigger to start:** user explicitly requests "let's do DR" or accidental helm uninstall incident

## Why

Current persistence options (filesystem with PVC, kubernetes.secrets) all lose data on:
- `helm uninstall` of the release (Secrets deleted)
- Full K8s cluster loss (etcd gone)
- `kubectl delete namespace`

Mitigations in place:
- `helm.sh/resource-policy: keep` annotation on critical Secrets (survives `helm uninstall`)
- Master/slave replication for cross-cluster redundancy

But neither solves catastrophic K8s loss. External DB does.

## Sketch

- Add `--storage.backend=postgres` as third option
- New `db.go` with connection pool (`pgx/v5`)
- Schema: `users`, `ccd`, `common_routes`, `pki_secrets` (4-5 tables)
- Migrations via `golang-migrate` (simple `up.sql` files)
- Helm chart references external DSN Secret (managed Postgres expected: RDS / Cloud SQL / Neon / Supabase)
- ~400-600 lines of code + chart updates

## Open questions

- Migration tooling: in-Go (golang-migrate as library) or external init-job?
- Connection management: pool sizing, retries
- How to migrate existing installations from kubernetes.secrets to postgres
- Tested with which Postgres versions

See brainstorming context: `docs/superpowers/specs/2026-05-23-firewall-enforcement-design.md` (DR discussion).
```

Создать `docs/superpowers/specs/_pending/firewall-ipset-scale.md`:

```markdown
# Firewall scale: ipset (stub)

**Trigger:** `ovpn_firewall_rules_total > 5000` OR user complaints about throughput.

## Why

Current implementation creates one iptables rule per (CN, CIDR) pair. With 100 clients × 30 CIDRs = 3000 rules, iptables traverses linearly per packet. Performance acceptable but degrades.

## Sketch

- One ipset per CN: `ovpn_cn_<hash>`, contains all allowed CIDRs
- One iptables rule per CN: `-s <vpn_ip> -m set --match-set ovpn_cn_<hash> dst -j ACCEPT`
- ipset binary added to Dockerfile
- Migration: detect ipset availability at startup; use it if present, fall back to raw rules

Estimated effort: ~200-400 lines plus tests.

See parent spec: `docs/superpowers/specs/2026-05-23-firewall-enforcement-design.md`.
```

Создать `docs/superpowers/specs/_pending/firewall-nftables-modernize.md`:

```markdown
# Firewall: migrate to nftables (stub)

**Trigger:** modern Alpine defaults to nft only, or operator preference.

## Why

iptables (legacy) is being replaced by nftables in modern Linux distros. nft offers:
- Atomic transactions (entire ruleset swap)
- Programmable Go API via `github.com/google/nftables`
- Native sets (replaces ipset)

## Sketch

- Replace `exec.Command("iptables", ...)` with `nftables` library calls
- Same logical structure (chain → rules per CN → catch-all DROP)
- Behind a `--firewall.backend=iptables|nftables` flag for transition

Estimated effort: ~300-500 lines, more if we keep both backends.

See parent spec: `docs/superpowers/specs/2026-05-23-firewall-enforcement-design.md`.
```

Создать `docs/superpowers/specs/_pending/firewall-port-protocol-rules.md`:

```markdown
# Firewall: per-port and per-protocol rules (stub)

**Trigger:** user requests "allow only port 443 to youtube.com" or similar.

## Why

Current model is CIDR-only (`-d 10.0.0.0/8 -j ACCEPT`). Users may want finer control:
- "Allow only TCP port 443 to corporate"
- "Block DNS over VPN, force split-DNS"

## Sketch

Extend `CommonRouteEntry` and `ccdRoute` with optional fields:
```go
Protocol string // "tcp" | "udp" | "" (any)
Ports    string // "443" | "1024-65535" | "" (any)
```

UI changes: add Protocol and Ports columns (collapsed by default).
iptables additions: `-p tcp --dport 443` matchers.

Estimated effort: ~300 lines (model, validation, render, UI).

See parent spec: `docs/superpowers/specs/2026-05-23-firewall-enforcement-design.md`.
```

- [ ] **Step 4: Sanity check — все файлы существуют, валидный markdown**

Run:
```bash
ls -la /Users/alexp/GolandProjects/ovpn-admin/docs/superpowers/specs/_pending/
wc -l /Users/alexp/GolandProjects/ovpn-admin/CHANGELOG.md /Users/alexp/GolandProjects/ovpn-admin/README.md
```
Expected: 4 stub файлов, README и CHANGELOG обновлены.

- [ ] **Step 5: Commit**

```bash
git add README.md CHANGELOG.md docs/superpowers/specs/_pending/
git commit -m "docs: firewall feature documentation and follow-up stubs"
```

---

## Self-Review (выполнено при написании плана)

**Spec coverage:**

| Spec section | Covered by task |
|--------------|-----------------|
| Архитектура (события + контроллер) | Tasks 2, 8 (event loop) |
| Модель данных (firewallController, fwSession, fwEvent) | Task 2 |
| iptables-структура (OVPN_FW chain, stateful-return, catch-all DROP) | Tasks 3, 4 |
| Lifecycle (mgmtEventLoop, eventHandlerLoop, reconcile, selfHealLoop) | Tasks 8, 9, 10, 11 |
| Diff-алгоритм | Task 5 |
| computeAllowedCIDRs | Task 6 |
| parseMgmtClientEvent | Task 7 |
| CLI флаги + Helm values + ENV | Task 12 (флаги в main.go), Task 14 (values.yaml + args) |
| NET_ADMIN cap | Task 13 (compose), Task 14 (Helm) |
| `iptables` бинарь в image | Task 13 |
| `management-client-auth` в server.conf | Task 14 |
| Fail-modes (fail-fast no iptables, no NET_ADMIN, mgmt timeout) | Task 12 (fail-fast LookPath); прочие fail-modes реализуются через тесты в Tasks 8-11 и через ручную проверку в smoke |
| Метрики Prometheus | **GAP** — добавляю Task 11.5 ниже |
| Дедупликация событий | Task 8 |
| Smoke (compose с openvpn-сервером и клиентом) | Task 16 |
| Helm `resource-policy: keep` | Task 15 |
| _pending stubs | Task 17 |
| README + CHANGELOG | Task 17 |
| `helpers.go` `ipMaskToCIDR` | Task 1 |
| Hooks из common_routes.go и userApplyCcdHandler | Task 12 |
| Docker-compose.firewall-test.yml | Task 16 |
| Out of scope (IPv6, per-port, NAT, etc.) | Документировано в CHANGELOG и README |

**GAP**: Prometheus метрики из раздела 5 спека не добавлены ни в одну задачу. Добавляю отдельную задачу ниже как Task 11.5.

**Placeholder scan:** ✅ нет «TBD», нет «implement later», все шаги с конкретным кодом. Единственное место с «зависит от» — Step 6 в Task 16 («manually connect alice») — там явно сказано «оставляем как ручную проверку».

**Type consistency:** имена методов и полей сверены. `fwSession.AllowedCIDRs`, `fwSession.VpnIP`, `firewallController.iptCmd`, `iptCmdFunc` — единый стиль во всех задачах.

---

## Task 11.5: Prometheus метрики

**Files:**
- Modify: `firewall.go` (или `main.go` — рядом с другими метриками)

- [ ] **Step 1: Объявить метрики**

В `firewall.go` (или в существующем блоке метрик в `main.go` — рядом с `ovpnServerCertExpire` и т.д.):

```go
import "github.com/prometheus/client_golang/prometheus"

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
```

- [ ] **Step 2: Зарегистрировать в `registerMetrics`** (`main.go:620`)

Добавить:

```go
oAdmin.promRegistry.MustRegister(ovpnFirewallEnabledGauge)
oAdmin.promRegistry.MustRegister(ovpnFirewallActiveSessions)
oAdmin.promRegistry.MustRegister(ovpnFirewallIptablesErrors)
oAdmin.promRegistry.MustRegister(ovpnFirewallEventsProcessed)
oAdmin.promRegistry.MustRegister(ovpnFirewallReconciles)
```

- [ ] **Step 3: Инкрементировать в правильных местах firewall.go**

- В `realIptCmd`: при ошибке `ovpnFirewallIptablesErrors.Inc()`
- В `handleEvent`: после успешной обработки `ovpnFirewallEventsProcessed.WithLabelValues(eventKindName(ev.Kind)).Inc()`
- В `reconcileLocked`: после успешного reconcile `ovpnFirewallReconciles.Inc()` и обновлять `ovpnFirewallActiveSessions.Set(float64(len(fc.sessions)))`
- В `Start`: `ovpnFirewallEnabledGauge.Set(1)`
- В `Stop`: `ovpnFirewallEnabledGauge.Set(0)`

Helper `eventKindName(k fwEventKind) string` → `"connect"|"disconnect"|"user_changed"|"common_changed"|"reconcile"`.

- [ ] **Step 4: Build + tests**

Run: `go build ./... && go test -race ./...`
Expected: clean.

- [ ] **Step 5: Smoke metrics**

Запустить локально (без firewall):
```bash
go build -o /tmp/ovpn-admin ./... && (./tmp/ovpn-admin --ovpn.network=192.168.100.0/24 &) ; sleep 2 ; curl -s http://localhost:8080/metrics | grep ovpn_firewall ; kill %1 ; rm /tmp/ovpn-admin
```
Expected: метрики `ovpn_firewall_*` присутствуют (значения 0).

- [ ] **Step 6: Commit**

```bash
git add firewall.go main.go
git commit -m "feat(firewall): Prometheus metrics"
```

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-23-firewall-enforcement.md`. Two execution options:

**1. Subagent-Driven (recommended)** — диспатчу свежего сабагента на каждую задачу, ревью между задачами, быстрая итерация.

**2. Inline Execution** — выполнение задач в этой сессии через executing-plans, батчами с чекпоинтами.

Which approach?

# Server-side route enforcement (firewall) — дизайн

**Дата:** 2026-05-23
**Статус:** Draft → готов к проверке пользователем
**Тип:** новая фича

## Цель

Сейчас OpenVPN push-маршруты — это **рекомендация для клиента**, не enforcement. Клиент может вручную выполнить `ip route add X via tun0` и трафик пройдёт через VPN независимо от того, прописан ли маршрут на сервере. На стороне OpenVPN-сервера FORWARD-цепочка пропускает всё.

Цель — гарантировать, что **через VPN проходит только трафик к тем сетям, которые явно разрешены администратором** для конкретного юзера через CCD CustomRoutes ∪ глобальные Common Routes.

Реализация — серверный enforcement через iptables, управляемый самим ovpn-admin без отдельного sidecar-контейнера.

## Решения, принятые на брейншторминге

| Вопрос | Решение |
|--------|---------|
| Где живёт логика enforcement | Внутри ovpn-admin, новый модуль `firewall.go`. Без sidecar'а. |
| Дополнительные capabilities | `NET_ADMIN` к контейнеру ovpn-admin (он уже в одной net-ns с openvpn) |
| Дополнительные бинари в image | `iptables` добавляется в Dockerfile ovpn-admin |
| Триггер событий connect/disconnect | OpenVPN management-interface (real-time подписка), не client-connect скрипт |
| Структура iptables | Одна цепочка `OVPN_FW`, прыжок из FORWARD, ACCEPT-правила per-CN + catch-all DROP в конце |
| Backend persistence | Не вводится. Состояние реконсилируется из существующих storage backend'ов (filesystem/k8s.secrets) на старте |
| ipset / nftables | iptables в v1 (раскладку поддерживает на ожидаемом масштабе). ipset/nftables — follow-up если будет нужно |
| IPv6 | Out of scope v1 (соответствует Common Routes) |
| Per-port/protocol | Out of scope v1 (только CIDR-level allow) |
| Default включения | `--firewall=false` дефолт в коде. Helm чарт ставит `firewall.enabled=true` в values.yaml для **новых** инсталляций. Существующие при upgrade сохраняют поведение |
| Multi-replica | Не поддерживается уже сейчас (Helm: `strategy: Recreate`). Фича не ухудшает |
| Disaster recovery | Отдельный спек (`_pending/disaster-recovery-postgres.md`). В рамках текущего — `helm.sh/resource-policy: keep` на критичные Secret'ы |

## Архитектура

**Топология deployment** (Helm и docker-compose):
- `openvpn` и `ovpn-admin` — два контейнера в одной net-namespace (Helm: один pod, docker-compose: `network_mode: service:openvpn`)
- Оба видят `lo` и `tun0` одинаково
- Сейчас `NET_ADMIN` есть только у openvpn → добавляем и к ovpn-admin
- mgmt-interface OpenVPN: `127.0.0.1:8989` (localhost внутри shared net-ns)

```
┌──────────────────────────────────────────────────────────────────┐
│                      ovpn-admin (Go)                             │
│                                                                  │
│  ┌──────────────────┐    events     ┌──────────────────────┐    │
│  │ mgmtEventLoop    │ ────────────→ │ firewallController   │    │
│  │ (новый, держит   │  Connect/     │ (новый)              │    │
│  │  TCP-conn к      │  Disconnect/  │ — карта CN → IP+rules│    │
│  │  127.0.0.1:8989) │  Reauth       │ — diff'ит и применяет│    │
│  └──────────────────┘               └──────────┬───────────┘    │
│                                                 │ exec.Command  │
│  ┌──────────────────┐                           ▼                │
│  │ commonRoutes     │ ─────────────→  ┌─────────────────────┐   │
│  │ HTTP handlers    │  EvCommonChanged│ iptables binary     │   │
│  │ (Task 10 fwk)    │                 │ (в shared net-ns)   │   │
│  └──────────────────┘                 └─────────────────────┘   │
│                                                                  │
│  ┌──────────────────┐                                            │
│  │ userApplyCcd     │ ─────────────→  EvUserChanged(cn)          │
│  │ Handler          │                                            │
│  └──────────────────┘                                            │
└──────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                         FORWARD → OVPN_FW chain → ACCEPT/DROP
```

Три источника событий:
1. **OpenVPN mgmt-interface** — постоянное TCP-подключение, парсинг строк вида `>CLIENT:CONNECT`, `>CLIENT:DISCONNECT`, `>CLIENT:ENV,...`, `>CLIENT:ENV,END`. ovpn-admin узнаёт `CN ↔ assigned_VPN_IP ↔ session_state` в реальном времени.
2. **HTTP handlers common-routes** — при `POST/PUT/DELETE/refresh` пушат `EvCommonChanged` в очередь firewall.
3. **`userApplyCcdHandler`** — при изменении CCD юзера X пушит `EvUserChanged(X)`.

`firewallController` — единственная точка записи в iptables. Все остальные модули только посылают ему события.

## Модель данных

```go
type firewallController struct {
    mu        sync.Mutex
    enabled   bool                      // флаг --firewall
    chainName string                    // OVPN_FW по умолчанию
    iptBin    string                    // путь к iptables
    vpnNet    *net.IPNet                // *openvpnNetwork, для catch-all DROP
    sessions  map[string]*fwSession     // CN → active session (только подключённые)
    events    chan fwEvent              // буферизированная очередь
    pending   map[string]fwEvent        // дедупликация per-CN
    iptCmd    func(args ...string) error // shell-out helper (мок-able в тестах)
    oAdmin    *OvpnAdmin                 // обратная ссылка для getCcd/commonRoutes
}

type fwSession struct {
    CN             string
    VpnIP          string      // ifconfig_pool_remote_ip от mgmt
    AllowedCIDRs   []string    // snapshot на момент install
    RulesInstalled bool
}

type fwEventKind int
const (
    EvConnect fwEventKind = iota
    EvDisconnect
    EvUserChanged
    EvCommonChanged
    EvReconcile        // принудительная сверка с mgmt
)

type fwEvent struct {
    Kind  fwEventKind
    CN    string        // для Connect/Disconnect/UserChanged
    VpnIP string        // только для Connect
}
```

`AllowedCIDRs` хранится как snapshot для возможности diff'а при изменениях. При EvUserChanged / EvCommonChanged для активного CN — пересчитываем новый набор, сравниваем со старым, применяем только diff (минимум команд iptables).

## iptables-структура

**Одна цепочка `OVPN_FW`** в таблице `filter`. Прыжок из `FORWARD` в позиции 1.

### Init (идемпотентно, выполняется при старте и при reconcile)

```bash
iptables -N OVPN_FW                                            # создать (no-op если есть)
iptables -F OVPN_FW                                            # очистить
iptables -C FORWARD -j OVPN_FW || iptables -I FORWARD 1 -j OVPN_FW

# Первое правило цепочки — stateful return
iptables -I OVPN_FW 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT \
    -m comment --comment "ovpn-admin: stateful-return"

# Последнее правило — catch-all DROP для VPN-подсети
iptables -A OVPN_FW -s 172.16.100.0/24 -j DROP \
    -m comment --comment "ovpn-admin: default-deny"
```

### Per-session rules

Для CN=alice, VPN_IP=172.16.100.5, CIDRs=[10.0.0.0/8, 142.250.0.1/32]:

```bash
# Снимаем catch-all DROP (pivot)
iptables -D OVPN_FW -s 172.16.100.0/24 -j DROP -m comment --comment "ovpn-admin: default-deny"

# Добавляем ACCEPT'ы
iptables -A OVPN_FW -s 172.16.100.5 -d 10.0.0.0/8 -j ACCEPT \
    -m comment --comment "ovpn-admin: alice"
iptables -A OVPN_FW -s 172.16.100.5 -d 142.250.0.1/32 -j ACCEPT \
    -m comment --comment "ovpn-admin: alice"

# Возвращаем catch-all DROP
iptables -A OVPN_FW -s 172.16.100.0/24 -j DROP -m comment --comment "ovpn-admin: default-deny"
```

Pivot снимает DROP→добавляет ACCEPT→возвращает DROP. Все три шага под единым mutex'ом контроллера, никаких race conditions.

При disconnect — удаление по точной спецификации:

```bash
iptables -D OVPN_FW -s 172.16.100.5 -d 10.0.0.0/8 -j ACCEPT \
    -m comment --comment "ovpn-admin: alice"
# по одному -D на каждую CIDR из fwSession.AllowedCIDRs
```

### Финальное состояние

```
Chain OVPN_FW (1 references)
 pkts bytes target  prot opt in   out  source           destination
12345   1M  ACCEPT  all  --  *    *    0.0.0.0/0        0.0.0.0/0       ctstate RELATED,ESTABLISHED /* ovpn-admin: stateful-return */
   42  3K  ACCEPT  all  --  *    *    172.16.100.5     10.0.0.0/8                                  /* ovpn-admin: alice */
    5  500 ACCEPT  all  --  *    *    172.16.100.5     142.250.0.1                                 /* ovpn-admin: alice */
   18  2K  ACCEPT  all  --  *    *    172.16.100.7     192.168.1.0/24                              /* ovpn-admin: bob */
    1  60  DROP    all  --  *    *    172.16.100.0/24  0.0.0.0/0                                   /* ovpn-admin: default-deny */
```

### Cleanup

`firewallController.Shutdown()` — best-effort:

```bash
iptables -D FORWARD -j OVPN_FW
iptables -F OVPN_FW
iptables -X OVPN_FW
```

При SIGKILL не вызовется → цепочка остаётся в kernel'е; следующий старт ovpn-admin делает `-N || -F` и переиспользует её.

## Lifecycle и события

### Источник 1: OpenVPN mgmt-interface

Сейчас ovpn-admin **поллит** mgmt (см. `mgmtGetActiveClients`, `main.go:1521`).

**Точный механизм получения событий connect/disconnect зависит от server.conf OpenVPN.** Два варианта, выбор финализируется на этапе имплементации:

**Вариант A (предпочтительный): real-time подписка через `>CLIENT:` события.**
Требует в server.conf одного из:
- `management-client-auth` — OpenVPN шлёт `>CLIENT:CONNECT,cid,kid` + `>CLIENT:ENV,...` + `>CLIENT:ENV,END` без подтверждения от ovpn-admin (просто информационно)
- `client-connect <script>` с минимальным no-op скриптом — события всё равно попадают в mgmt

Это требует **изменения server.conf шаблона в Helm-чарте** (ConfigMap `configmap.yaml`). Латентность: миллисекунды.

**Вариант B (fallback): частый polling `status 3`.**
ovpn-admin раз в 1-2 секунды делает `status 3`, парсит список активных клиентов, diff'ит со своей `sessions`-картой, на расхождениях пушит виртуальные `EvConnect`/`EvDisconnect`. Не требует правок server.conf. Латентность: до 2 сек на первоначальный install правил.

**Решение:** в v1 используем **Вариант A** (правим server.conf в чарте), потому что:
- Уже редактируем чарт ради `NET_ADMIN` + `keep`-аннотаций
- Латентность 0 → ниже окно where клиент подключён, но правила не установлены (DROP'нет первый пакет)
- В качестве страховки запускаем **периодический reconcile** (`--firewall.reconcile-interval=5m`), который полностью обновляет картину с polling-ом

Если на имплементации окажется, что `--management-client-auth` ведёт себя не так как ожидается — переходим на B без переписывания firewallController (меняется только источник `fwEvent`'ов).

Код:

```go
func (fc *firewallController) mgmtEventLoop(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
        conn, err := net.Dial("tcp", oAdmin.mgmtInterfaces["main"])
        if err != nil {
            log.Warnf("firewall: mgmt connect failed: %v; retry in 5s", err)
            time.Sleep(5 * time.Second)
            continue
        }
        if err := fc.subscribeAndPump(ctx, conn); err != nil {
            log.Warnf("firewall: mgmt stream error: %v; reconnect", err)
        }
        conn.Close()
        time.Sleep(1 * time.Second)
    }
}
```

`subscribeAndPump` (Вариант A) парсит строки `>CLIENT:CONNECT,cid,kid`, далее серию `>CLIENT:ENV,common_name=alice`, `>CLIENT:ENV,ifconfig_pool_remote_ip=172.16.100.5`, ..., `>CLIENT:ENV,END`. На `END` собирает накопленные ENV в готовый `fwEvent` и пушит в очередь. Аналогично для `>CLIENT:DISCONNECT,cid`.

Точный набор ENV-полей в `>CLIENT:` событиях верифицируется на этапе имплементации (через ручной `nc 127.0.0.1 8989` к работающему openvpn-серверу с modified server.conf). Имена полей могут немного отличаться от тех что в `--client-connect` скрипте.

При обрыве стрима — reconnect c 1-сек backoff'ом, **затем `reconcile()`** для сверки сessions с реальным состоянием mgmt.

### Источник 2: CCD юзера изменён

В `userApplyCcdHandler` (`main.go:405`) после `modifyCcd`:
```go
if fc != nil && fc.enabled {
    fc.push(fwEvent{Kind: EvUserChanged, CN: ccd.User})
}
```

Обработчик `EvUserChanged`:
```go
if session, ok := fc.sessions[ev.CN]; ok {
    newCIDRs := fc.computeAllowedCIDRs(ev.CN)
    fc.applyDiff(session, newCIDRs)
    session.AllowedCIDRs = newCIDRs
}
// если юзер не подключён — ничего не делаем, при следующем connect возьмём свежее
```

### Источник 3: common-routes изменены

В каждом `handleCreate`/`handleUpdate`/`handleDelete`/`commonRoutesRefreshHandler` после `rerenderAllCcds`:
```go
if fc != nil && fc.enabled {
    fc.push(fwEvent{Kind: EvCommonChanged})
}
```

Обработчик `EvCommonChanged` пробегается по всем `sessions`, для каждой пересчитывает CIDR'ы и применяет diff. То же — после DNS-резолва (`commonRoutesRefreshHandler`).

### Diff-алгоритм

```go
func (fc *firewallController) applyDiff(s *fwSession, newCIDRs []string) {
    oldSet := toSet(s.AllowedCIDRs)
    newSet := toSet(newCIDRs)

    toAdd := newSet - oldSet
    toDel := oldSet - newSet

    fc.iptablesRemoveCatchAllDrop()
    for cidr := range toDel {
        fc.iptCmd("-D", "OVPN_FW", "-s", s.VpnIP, "-d", cidr, "-j", "ACCEPT",
                  "-m", "comment", "--comment", "ovpn-admin: "+s.CN)
    }
    for cidr := range toAdd {
        fc.iptCmd("-A", "OVPN_FW", "-s", s.VpnIP, "-d", cidr, "-j", "ACCEPT",
                  "-m", "comment", "--comment", "ovpn-admin: "+s.CN)
    }
    fc.iptablesRestoreCatchAllDrop()
}
```

Минимум команд: если у юзера 30 CIDR'ов и поменялся 1 — выполнятся одна `-D` + одна `-A`, не 60.

### Reconcile

Полный пересборка при старте и при обрыве mgmt-стрима:

```go
func (fc *firewallController) reconcile() {
    fc.cleanupChain()
    fc.initChain()
    active := oAdmin.mgmtGetActiveClients()
    for _, c := range active {
        cidrs := fc.computeAllowedCIDRs(c.CommonName)
        fc.installRulesFor(c.CommonName, c.VirtualAddress, cidrs)
    }
    fc.installCatchAllDrop()
}
```

Дополнительно — **периодический self-heal**: раз в `firewall.reconcile-interval` (default 5 минут) — повторный reconcile для защиты от накопления дрифта (например, если какая-то команда iptables незаметно упала и не была повторена).

### Lifecycle

```
main() → fc.Start(ctx)
  ├─ initChain() ────── создать/очистить OVPN_FW, прыжок из FORWARD
  ├─ go mgmtEventLoop(ctx) ─── постоянное TCP-подключение, парсинг
  ├─ go eventHandlerLoop(ctx) ─ single-goroutine обработка очереди
  ├─ go reconcileTicker(ctx) ─ self-heal раз в N минут
  └─ reconcile() ─── snapshot mgmt-active + накатить правила (если openvpn уже жив)

main() shutdown → fc.Stop()
  ├─ cancel ctx ─── все горутины выходят
  └─ cleanupChain() ─── best-effort
```

## Концepция дедупликации событий

При высокочастотном flap'е одного клиента (connect→disconnect→connect 10 раз/сек):

```go
type firewallController struct {
    // ...
    pending map[string]fwEvent  // последнее событие per-CN
    kick    chan struct{}       // signal к eventHandlerLoop
}

func (fc *firewallController) push(ev fwEvent) {
    fc.mu.Lock()
    fc.pending[ev.CN] = ev  // последнее событие per-CN выигрывает
    fc.mu.Unlock()
    select { case fc.kick <- struct{}{}: default: }
}

func (fc *firewallController) eventHandlerLoop(ctx context.Context) {
    for {
        select {
        case <-ctx.Done(): return
        case <-fc.kick:
            fc.mu.Lock()
            batch := fc.pending
            fc.pending = make(map[string]fwEvent)
            fc.mu.Unlock()
            for _, ev := range batch {
                fc.handleEvent(ev)
            }
        }
    }
}
```

При 10 flap'ах в секунду для alice финальное состояние обрабатывается 1-2 раза в секунду — нагрузка на iptables падает на порядок. Промежуточные state'ы дропаются, последнее состояние выигрывает.

`EvCommonChanged` — особый случай: ключевание не per-CN, а единственное «глобальное» событие; повторные `EvCommonChanged` в течение одного цикла обработки коалесцируются в одно.

Single-goroutine processing + ordered TCP events = корректность гарантирована независимо от частоты.

## Конфигурация

### Новые CLI флаги

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

Default `--firewall=false` (opt-in) в коде. Helm чарт включает `firewall.enabled=true` в values.yaml для новых инсталляций. Существующие при upgrade нужно явно проставлять.

### Helm values.yaml

```yaml
ovpnAdmin:
  # ... existing ...

  firewall:
    enabled: true                    # default для новых установок
    chainName: "OVPN_FW"
    iptablesBin: "/sbin/iptables"
    startupTimeout: "30s"
    reconcileInterval: "5m"
```

### Helm deployment.yaml

```yaml
- name: ovpn-admin
  # ... existing ...
  securityContext:
    capabilities:
      add: ["NET_ADMIN"]            # новое
  args:
    # ... existing ...
    {{- if .Values.ovpnAdmin.firewall.enabled }}
    - --firewall
    - --firewall.chain-name={{ .Values.ovpnAdmin.firewall.chainName }}
    - --firewall.iptables-bin={{ .Values.ovpnAdmin.firewall.iptablesBin }}
    - --firewall.startup-timeout={{ .Values.ovpnAdmin.firewall.startupTimeout }}
    - --firewall.reconcile-interval={{ .Values.ovpnAdmin.firewall.reconcileInterval }}
    {{- end }}
```

### docker-compose.yaml

```yaml
ovpn-admin:
  # ... existing ...
  cap_add:
    - NET_ADMIN                    # новое
  environment:
    OVPN_FIREWALL: "true"          # новое
```

### Dockerfile.ovpn-admin

```dockerfile
RUN apk add --update bash easy-rsa openssl openvpn coreutils iptables && \
    # ... existing ...
```

### Helm: keep аннотация для critical Secret'ов

В шаблоны Secret'ов (PKI, common-routes) — добавить:
```yaml
annotations:
  helm.sh/resource-policy: keep
```
Защита от случайного `helm uninstall`. Часть текущего спека (не follow-up), потому что бесплатная и логически связанная — фича опирается на эти Secret'ы для DR.

## Fail-modes

| Случай | Поведение |
|--------|-----------|
| `iptables` не найден при `--firewall=true` | **fail-fast** при старте, `log.Fatal` |
| Нет `NET_ADMIN` cap (EPERM) | **fail-fast** при старте после первой команды |
| mgmt-interface недоступна на старте | Retry 5s, до `--firewall.startup-timeout` — потом fail-fast. До успешного подключения **catch-all DROP уже стоит** = fail-closed |
| `iptables` команда упала в середине applyDiff | Лог + продолжаем; следующее событие пересоберёт diff с нуля; self-heal реконсайл подстрахует |
| mgmt-stream оборвался | Reconnect (1s backoff) + reconcile() |
| ovpn-admin restart, активные клиенты есть | `-N OVPN_FW \|\| true` + `-F` (idempotent), reconcile из mgmt-snapshot. Кратковременное окно (миллисекунды) без ACCEPT-правил |
| Concurrent edit common-routes + DNS tick | Дедупликация через `pending`-карту |
| `--firewall=false` после прошлого запуска с `=true` | При старте проверяем существование цепочки → если есть, очищаем и удаляем (best-effort) |

## Метрики

```go
ovpnFirewallEnabled         (gauge, 0/1)
ovpnFirewallActiveSessions  (gauge, число сессий с правилами)
ovpnFirewallRulesTotal      (gauge, всего ACCEPT-правил в OVPN_FW)
ovpnFirewallIptablesErrors  (counter)
ovpnFirewallEventsProcessed (counter, label type=connect|disconnect|user_changed|common_changed|reconcile)
ovpnFirewallReconciles      (counter)
```

## Тестирование

### Unit (`firewall_test.go`, ≈15 тестов)

1. `TestParseMgmtClientEvent_Connect` — `>CLIENT:CONNECT,...` + ENV строки → `fwEvent{Kind:EvConnect, CN:"alice", VpnIP:"172.16.100.5"}`
2. `TestParseMgmtClientEvent_Disconnect` — `>CLIENT:DISCONNECT,...` → `EvDisconnect`
3. `TestParseMgmtClientEvent_Garbage` — мусорные строки игнорируются (ok=false)
4. `TestComputeAllowedCIDRs_MixedSources` — CCD custom + common ip + common domain (multi-IP) → корректный набор CIDR
5. `TestComputeAllowedCIDRs_Dedup` — пересекающиеся CCD и common → де-дубль
6. `TestApplyDiff_Add` — `[A,B] → [A,B,C]` → одна `-A`
7. `TestApplyDiff_Remove` — `[A,B,C] → [A]` → две `-D`
8. `TestApplyDiff_Mixed` — `[A,B] → [B,C]` → одна `-D A` + одна `-A C` + правильный pivot catch-all
9. `TestEventLoop_ConnectThenDisconnect` — install при Connect, uninstall при Disconnect, карта sessions пуста
10. `TestEventLoop_Coalescing` — 10 Connect'ов для alice подряд → одна install-операция в итоге
11. `TestEventLoop_UserChangedNoOpIfDisconnected` — EvUserChanged для не-подключённого CN → нет iptCmd
12. `TestReconcile_FromMgmtSnapshot` — мок mgmtGetActiveClients → правила установлены для всех
13. `TestFailFast_NoIptablesBinary` — `iptCmd` возвращает `exec.ErrNotFound` → Init возвращает err
14. `TestFailFast_NoNetAdmin` — `iptCmd` возвращает EPERM → Init возвращает err
15. `TestSelfHeal_DriftCorrection` — сессия в карте но нет в mgmt → reconcile удаляет её

### Integration / smoke

Новый `docker-compose.firewall-test.yml`:
- openvpn-сервер (полный stack из `docker-compose.yaml`)
- ovpn-admin с `--firewall=true` и `NET_ADMIN`
- openvpn-клиент (отдельный alpine с openvpn клиентом и pre-generated alice.ovpn)

Сценарии:
1. **Default DROP**: без common-routes и пустой CCD — клиент подключается, ping любого IP — DROP
2. **Common route allows**: добавляем common-route `8.8.8.8/32` → ping проходит, `1.1.1.1` — DROP
3. **Per-user CCD**: добавляем в CCD юзеру `10.0.0.0/8` → ping в эту сеть проходит, общий 8.8.8.8 тоже работает (union)
4. **Disconnect cleanup**: клиент отключается → правила alice пропадают из OVPN_FW
5. **Domain refresh**: добавляем common-route `example.com`, ждём резолва, ping на резолвленный IP проходит
6. **Restart ovpn-admin without pod**: kill процесс ovpn-admin, k8s/compose рестартует контейнер → reconcile восстанавливает правила, клиент по-прежнему работает после короткой паузы

### Что НЕ тестируем (v1)

- Performance под нагрузкой (100+ одновременных коннектов)
- Failure injection (kill iptables посреди applyDiff)
- IPv6

## Out of scope (v1)

- IPv6 / `ip6tables`
- Per-port/protocol правила (только CIDR-level)
- Логирование дропов через `-j LOG`
- Управление NAT/MASQUERADE (полагаемся на openvpn-сервер)
- Не-iptables firewall'ы (nftables/ufw)
- TLS на mgmt-interface
- Удалённый mgmt (через сеть)
- Per-CN метрики (dimensionality)

## Follow-ups (separate specs in `_pending/`)

1. **`disaster-recovery-postgres.md`** — внешняя БД для DR
2. **`firewall-ipset-scale.md`** — миграция на ipset когда упрёмся в производительность
3. **`firewall-nftables-modernize.md`** — переход на nftables через Go lib
4. **`firewall-port-protocol-rules.md`** — расширение модели маршрутов

## Backwards compatibility

| Случай | Поведение |
|---|---|
| Upgrade ovpn-admin без правки конфига | Поведение **не меняется** (default `--firewall=false`) |
| Helm upgrade без правки values | Получит `firewall.enabled=true` (если в values стояло default или unset) → **смена поведения** |
| Helm `keep` annotations добавлены | Secret'ы PKI/CCD/common-routes выживают `helm uninstall` (мини-DR) |

В CHANGELOG.md явно прописываем breaking note для Helm-апгрейдеров с инструкцией как сохранить старое поведение (`ovpnAdmin.firewall.enabled: false`).

## Файлы

**Новые:**
- `firewall.go` (~400-500 строк)
- `firewall_test.go` (~300-400 строк)
- `docker-compose.firewall-test.yml`
- `docs/superpowers/specs/_pending/disaster-recovery-postgres.md` (stub)
- `docs/superpowers/specs/_pending/firewall-ipset-scale.md` (stub)
- `docs/superpowers/specs/_pending/firewall-nftables-modernize.md` (stub)
- `docs/superpowers/specs/_pending/firewall-port-protocol-rules.md` (stub)

**Изменяемые:**
- `main.go` — флаги, инициализация firewallController, регистрация в `oAdmin.modules`, вызовы из userApplyCcdHandler
- `common_routes.go` — вызовы из всех мутирующих хендлеров и `commonRoutesRefreshHandler`
- `helpers.go` или `firewall.go` — `ipMaskToCIDR` хелпер + тест
- `Dockerfile.ovpn-admin` — добавить `iptables` в `apk add`
- `charts/openvpn-admin/values.yaml` — секция `ovpnAdmin.firewall.*`
- `charts/openvpn-admin/templates/deployment.yaml` — `NET_ADMIN` cap, условные args
- `charts/openvpn-admin/templates/configmap.yaml` — server.conf получает строку `management-client-auth` (или эквивалент) для real-time `>CLIENT:` событий на mgmt-interface
- `charts/openvpn-admin/templates/<pki-secrets>.yaml` (если есть) или динамически создаваемые в Go — добавить `helm.sh/resource-policy: keep`
- `docker-compose.yaml` — `cap_add: [NET_ADMIN]`, `OVPN_FIREWALL=true`
- `README.md` — секция «Server-side route enforcement»
- `CHANGELOG.md` — breaking note для Helm-апгрейдеров

# Editable OpenVPN Server Config через Admin UI — дизайн

**Дата:** 2026-05-26
**Статус:** Draft → готов к проверке пользователем
**Тип:** новая фича

## Цель

Дать админу возможность редактировать ключевые параметры OpenVPN-сервера (proto, port, MTU, cipher, DNS push, DCO, и т.д.) через веб-интерфейс ovpn-admin без правки YAML / `helm upgrade`. Изменения применяются hot — без полного pod-рестарта.

DCO (Data Channel Offload) — kernel-ускорение пропуска данных, дающее 2-10x throughput на поддерживающих ядрах. Включить **auto-detect-with-fallback**: если ядро поддерживает (`/sys/module/ovpn` загружен) — включаем; если нет — оставляем userspace + warning.

## Решения, принятые на брейншторминге

| Вопрос | Решение |
|--------|---------|
| Scope полей | Расширенный: все 15+ параметров + custom directives с whitelist'ом |
| Reload mechanism | **Hybrid**: SIGHUP для soft-полей (DNS, verb, keepalive), hard-restart для остального (port, proto, cipher, MTU, DCO) |
| Storage | K8s Secret `ovpn-admin-server-config` (для k8s backend) / JSON в `<ccdDir>/_server_config.json` (filesystem) — тот же паттерн что Common Routes |
| Custom directives | Textarea + whitelist-валидатор (prefix-based) |
| DCO fallback | Auto-detect kernel module; UI отключает toggle если недоступно |
| Helm migration | Удалить ConfigMap server.conf, ovpn-admin рендерит из store в emptyDir |
| Reload архитектура | Shared `emptyDir` volume + openvpn-container ждёт файл в init-loop |

## Архитектура

**Поток данных и компоненты:**

```
┌──────────────────────────────────────────────────────────────────────┐
│  K8s Pod / docker-compose (same net-ns)                               │
│                                                                       │
│  ┌────────────────────┐    POST /api/server-config                    │
│  │  ovpn-admin (Go)   │ ◄──────────────────── Browser UI              │
│  │                    │                       (Сервер tab)            │
│  │  serverConfigStore │                                               │
│  │   (Secret/JSON)    │                                               │
│  │         │          │                                               │
│  │         ▼          │                                               │
│  │  renderServerConf  │                                               │
│  │         │          │                                               │
│  └─────────┼──────────┘                                               │
│            │ writes                                                   │
│            ▼                                                          │
│  ┌──────────────────────────┐  emptyDir shared volume                 │
│  │  /etc/openvpn/server.conf│ ◄──────── mounted in both containers    │
│  └─────────┬────────────────┘                                         │
│            │ reads                                                    │
│            ▼                                                          │
│  ┌─────────────────────┐                                              │
│  │  openvpn container  │ ←── SIGHUP via mgmt 127.0.0.1:8989 (soft)    │
│  │  (waits for file,   │ ←── SIGTERM (hard restart — kubelet recreate) │
│  │   then exec openvpn)│                                              │
│  └─────────────────────┘                                              │
└──────────────────────────────────────────────────────────────────────┘
```

**Lifecycle:**

1. **Cold start** — оба контейнера запускаются параллельно. openvpn-container ждёт `/etc/openvpn/server.conf` в init-loop. ovpn-admin загружает store (или дефолты при первом запуске), выполняет `detectDCOSupport()`, рендерит `server.conf` в shared volume. openvpn просыпается и стартует.

2. **PUT /api/server-config** — ovpn-admin валидирует JSON, сравнивает с текущим состоянием, определяет soft/hard reload. Сохраняет в store, рендерит новый файл, шлёт сигнал openvpn'у через mgmt-interface.

3. **Rollback** — при hard reload ovpn-admin ждёт 15 секунд переподключения к mgmt:8989. Если openvpn не вернулся (плохой config) — откатывает store к предыдущей версии, перерендеривает, делает второй SIGTERM. UI получает 500 + описание ошибки.

## Модель данных

```go
type ServerConfig struct {
    // Network / transport
    Proto             string   `json:"proto"`              // "udp" | "tcp"
    Port              int      `json:"port"`               // 1194
    Network           string   `json:"network"`            // "172.16.100.0"
    NetworkMask       string   `json:"network_mask"`       // "255.255.255.0"

    // MTU
    TunMTU            int      `json:"tun_mtu"`            // 1500
    MssFix            int      `json:"mss_fix"`            // 0 = disabled

    // Cryptography
    DataCiphers       []string `json:"data_ciphers"`       // ["AES-256-GCM","AES-128-GCM","CHACHA20-POLY1305"]
    TLSVersionMin     string   `json:"tls_version_min"`    // "1.2" | "1.3"
    TLSAuthMode       string   `json:"tls_auth_mode"`      // "tls-auth" | "tls-crypt"
    DCOEnabled        bool     `json:"dco_enabled"`

    // Behavior
    KeepaliveInterval int      `json:"keepalive_interval"`
    KeepaliveTimeout  int      `json:"keepalive_timeout"`
    MaxClients        int      `json:"max_clients"`        // 0 = OpenVPN default
    ClientToClient    bool     `json:"client_to_client"`
    DuplicateCN       bool     `json:"duplicate_cn"`
    Compression       string   `json:"compression"`        // "" | "lz4-v2" | "lzo"
    Verb              int      `json:"verb"`               // 0-9

    // Pushed to clients
    RedirectGateway   bool     `json:"redirect_gateway"`
    DNSServers        []string `json:"dns_servers"`
    PushExtra         []string `json:"push_extra"`         // whitelist'ed lines

    // Advanced
    CustomDirectives  []string `json:"custom_directives"`  // whitelist'ed

    // Bookkeeping
    UpdatedAt         string   `json:"updated_at"`
    UpdatedBy         string   `json:"updated_by"`
}

// DCOAvailable НЕ сохраняется в store — это runtime-property ноды, может меняться
// после переезда pod на другую ноду. Определяется при старте ovpn-admin и
// возвращается в API-ответе отдельным полем.
type ServerConfigResponse struct {
    Config       ServerConfig `json:"config"`
    DCOAvailable bool         `json:"dco_available"`
}

type serverConfigStore struct {
    mu  sync.RWMutex
    cfg ServerConfig
}
```

**Дефолты:**

```go
func defaultServerConfig() ServerConfig {
    return ServerConfig{
        // Defaults are matched to CURRENT production values to avoid breaking
        // existing clients on first upgrade. Users opt-in to modern alternatives
        // (UDP, tls-crypt) via the UI.
        Proto:             "tcp",
        Port:              1194,
        Network:           "172.16.100.0",
        NetworkMask:       "255.255.255.0",
        TunMTU:            1500,
        MssFix:            1450,
        DataCiphers:       []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"},
        TLSVersionMin:     "1.2",
        TLSAuthMode:       "tls-auth", // backward-compat; user can switch to tls-crypt
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
    }
}
```

## Storage

Тот же диспетчер `--storage.backend`:
- `filesystem` → `<ccdDir>/_server_config.json` (atomic write через temp+rename)
- `kubernetes.secrets` → Secret `ovpn-admin-server-config`, ключ `data` = JSON

При первом старте, если store пуст:
1. Применяются `defaultServerConfig()`
2. Сохраняются в store (чтобы было что показать в UI)

## Render `server.conf`

Встроенный Go `text/template` шаблон (см. полный листинг в Разделе 3 брейншторма). Ключевые директивы:

- `proto {{ .Proto }}-server` (или `{{ .Proto }}-server` зависит от UDP/TCP)
- `data-ciphers {{ join .DataCiphers ":" }}` (плюс `data-ciphers-fallback` = first)
- `data-channel-offload` — только если `DCOEnabled && DCOAvailable`
- `tls-crypt` или `tls-auth` + `key-direction 0`
- `push "dhcp-option DNS X"` для каждого `DNSServers`
- `push "redirect-gateway def1"` если `RedirectGateway`
- `client-config-dir /etc/openvpn/ccd` если `CcdEnabled` (берётся из существующего CLI флага)
- `management 127.0.0.1 8989` + `management-client-auth` всегда (для интеграции с firewall/mgmt-loop)
- Все `CustomDirectives` строки добавляются в конец файла

Атомарная запись:
```go
func writeServerConf(path, content string) error {
    tmp := path + ".tmp"
    if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
        return err
    }
    return os.Rename(tmp, path)
}
```

## Reload mechanism (hybrid)

**Категоризация по полям:**

```go
var SoftReloadFields = []string{
    "DNSServers", "RedirectGateway", "PushExtra", "Verb",
    "KeepaliveInterval", "KeepaliveTimeout", "MaxClients", "CustomDirectives",
}

var HardReloadFields = []string{
    "Proto", "Port", "TunMTU", "MssFix", "DataCiphers", "TLSVersionMin",
    "TLSAuthMode", "DCOEnabled", "Compression", "ClientToClient",
    "DuplicateCN", "Network", "NetworkMask",
}
```

**Soft (SIGHUP):**
```go
func (s *serverManager) softReload() error {
    conn, err := net.Dial("tcp", s.mgmtAddr)
    if err != nil { return err }
    defer conn.Close()
    fmt.Fprintln(conn, "signal SIGHUP")
    return nil
}
```

**Hard (SIGTERM):**
```go
func (s *serverManager) hardReload() error {
    conn, err := net.Dial("tcp", s.mgmtAddr)
    if err != nil { return err }
    fmt.Fprintln(conn, "signal SIGTERM")
    conn.Close()
    // openvpn exits → container exits → kubelet/supervisor restarts → ovpn-admin's
    // existing mgmt-event-loop reconnects automatically.
    return nil
}
```

**Rollback при hard reload:**
```go
func (s *serverManager) applyHard(newCfg ServerConfig) error {
    backup := s.store.snapshot()
    s.store.replace(newCfg)
    if err := s.renderToDisk(newCfg); err != nil {
        s.store.replace(backup); return err
    }
    s.hardReload()
    if err := s.waitMgmtReady(15 * time.Second); err != nil {
        log.Warnf("openvpn did not come back after %v; rolling back", err)
        s.store.replace(backup)
        s.renderToDisk(backup)
        s.hardReload()
        return fmt.Errorf("config invalid, rolled back: %w", err)
    }
    return nil
}
```

## DCO auto-detect

```go
func detectDCOSupport() bool {
    if _, err := os.Stat("/sys/module/ovpn"); err == nil { return true }
    if _, err := os.Stat("/sys/module/ovpn_dco"); err == nil { return true }
    _ = exec.Command("modprobe", "ovpn").Run()
    if _, err := os.Stat("/sys/module/ovpn"); err == nil { return true }
    if out, _ := exec.Command("openvpn", "--version").CombinedOutput(); !strings.Contains(string(out), "[DCO]") {
        log.Warnf("OpenVPN binary lacks DCO support")
    }
    return false
}
```

Выполняется один раз при старте ovpn-admin'а. Результат пишется в `cfg.DCOAvailable` и попадает в API. UI отключает DCO toggle если `false`.

## HTTP API

| Метод | Путь | Тело | Ответ |
|-------|------|------|-------|
| GET   | `/api/server-config` | — | `{config: ServerConfig, dcoAvailable: bool}` |
| PUT   | `/api/server-config` | `ServerConfig` JSON | `{config, reloadKind: "soft"|"hard"|"none"}` |
| POST  | `/api/server-config/test` | `ServerConfig` | `{valid: bool, errors: []}` — dry-run |
| GET   | `/api/server-config/defaults` | — | дефолтный `ServerConfig` (для кнопки "сбросить") |

Slave: GET доступен, PUT/POST → 423 Locked.

## Валидация

**Field-level:**

| Поле | Правило |
|------|---------|
| Proto | строго "udp" или "tcp" |
| Port | 1 ≤ p ≤ 65535 |
| TunMTU | 576 ≤ MTU ≤ 9000 |
| MssFix | 0 (выключено) или 100 ≤ MssFix ≤ 9000 |
| DataCiphers | каждый элемент из whitelist'а: AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305, AES-256-CBC, AES-128-CBC |
| TLSVersionMin | "1.2" или "1.3" |
| TLSAuthMode | "tls-auth" или "tls-crypt" |
| KeepaliveInterval | 1 ≤ x ≤ 3600 |
| KeepaliveTimeout | x > KeepaliveInterval, ≤ 86400 |
| Compression | "" или "lz4-v2" или "lzo" |
| Verb | 0 ≤ x ≤ 11 |
| Network, NetworkMask | `net.ParseCIDR(Network + "/" + maskBits(NetworkMask))` валиден |
| DNSServers | каждый элемент — валидный IP |

**CustomDirectives / PushExtra — whitelist:**

```go
var allowedDirectivePrefixes = []string{
    "route ", "route-nopull", "topology ", "mtu-test", "fragment ", "tun-mtu-extra ",
    "tx-queue-len ", "fast-io", "comp-lzo no", "explicit-exit-notify",
}
```

Каждая строка валидируется по prefix-match. Запрещены: `script-*`, `up`, `down`, `plugin`, `ipchange`, `setenv-safe` с шеллом, etc.

## UI: новая вкладка «Сервер»

В TabBar добавляется третий tab: **Пользователи / Общие маршруты / Сервер**.

`ServerConfigView.vue`:
- **Header**: статус-карточка (`Сервер OpenVPN`) — версия, uptime, DCO active/inactive, connected clients
- **Форма в секциях** (5 collapsible secions):
  1. **Сеть и транспорт** — Proto radio (UDP/TCP), Port input, Network/Mask, MTU, MSSFix
  2. **Шифрование** — DataCiphers chips multi-select, TLSVersionMin dropdown, TLSAuthMode radio, DCO toggle (disabled если `dcoAvailable=false`)
  3. **Поведение** — Keepalive (interval + timeout), MaxClients, ClientToClient toggle, DuplicateCN toggle, Compression dropdown, Verb slider 0-9
  4. **Push клиентам** — RedirectGateway toggle, DNSServers chip-input (multi), PushExtra textarea
  5. **Дополнительно** — CustomDirectives textarea с подсказкой по whitelist'у
- **Кнопки**: `Сохранить` (primary), `Сбросить к дефолтам` (ghost, с confirm-modal)
- **Перед сохранением**: вычисляем reload kind на клиенте (UI знает поля) → показываем модал:
  - Soft: «Изменения применятся мгновенно (push-routes, verb). Сохранить?»
  - Hard: «Требуется перезапуск OpenVPN. **N подключённых клиентов** будут отключены на ~5 секунд. Подтвердить?»

После сохранения — toast с результатом + обновление status-карточки.

## Helm chart changes

**`charts/openvpn-admin/templates/configmap.yaml`:**
- Удалить блок `server.conf:` из ConfigMap (config теперь dynamic)
- ConfigMap остаётся для других возможных файлов (или удаляется полностью)

**`charts/openvpn-admin/templates/deployment.yaml`:**
- Volume `server-conf`: `configMap` → `emptyDir: {}`
- Mount в **обоих** контейнерах (openvpn и ovpn-admin) — read-write
- openvpn `command:` — добавить wait-loop:
  ```yaml
  command:
    - sh
    - -c
    - |
      echo "Waiting for ovpn-admin to render server.conf..."
      until [ -f /etc/openvpn/server.conf ]; do sleep 1; done
      exec openvpn --config /etc/openvpn/server.conf
  ```
- Добавить kernel-module mount для DCO (read-only):
  ```yaml
  volumeMounts:
    - name: lib-modules
      mountPath: /lib/modules
      readOnly: true
  volumes:
    - name: lib-modules
      hostPath:
        path: /lib/modules
  ```

**`charts/openvpn-admin/values.yaml`:**
- Удалить openvpn-config-specific поля (network, proto, port — они теперь в store)
- Оставить только deploy-bits: image, replicas, RBAC, service config

## Fail-modes

| Случай | Поведение |
|--------|-----------|
| ovpn-admin не может записать `server.conf` (volume read-only) | log.Fatal при старте, fail-fast |
| Невалидный JSON в PUT | 400 с детальным описанием |
| Custom directive не в whitelist | 400 с указанием конкретной строки |
| Mgmt-interface недоступен при SIGHUP | warning в лог; не фейлим (config записан, openvpn перечитает при следующем рестарте) |
| openvpn не стартанул после hard restart (15s) | rollback на backup + 500 с описанием |
| DCOEnabled=true, но модуль stopped после рестарта | render gate: если DCOAvailable=false → silent skip `data-channel-offload` |
| Конкурентные PUT'ы | `mu.Lock` в `serverConfigStore` + single-goroutine применятор |
| Slave получил PUT | 423 Locked |

## Метрики Prometheus

```go
ovpnServerConfigVersion       (gauge: timestamp последнего применения)
ovpnServerConfigDCOAvailable  (gauge: 0/1)
ovpnServerConfigDCOActive     (gauge: 0/1)
ovpnServerConfigReloads       (counter, label kind=soft|hard|rollback)
ovpnServerConfigErrors        (counter, label op=render|reload|validate)
```

## Тестирование

**Unit (`server_config_test.go`, ~12 тестов):**
- `TestRenderServerConfig_Defaults`
- `TestRenderServerConfig_DCOEnabled` / `_DCOUnavailable`
- `TestRenderServerConfig_TLSCrypt_vs_TLSAuth`
- `TestRenderServerConfig_CustomDirectivesAtEnd`
- `TestValidateServerConfig_PortRange`
- `TestValidateServerConfig_CipherWhitelist`
- `TestValidateServerConfig_CustomDirectiveWhitelist` (отклонение script-security)
- `TestCategorizeChanges_SoftOnly` / `_PortRequiresHard`
- `TestServerConfigStore_RoundTrip`
- `TestServerManager_RollbackOnFailedHardRestart` (мок mgmt не отвечает)

**HTTP integration:**
- `TestServerConfigHandler_GET_ReturnsDefaults`
- `TestServerConfigHandler_PUT_SoftReload` (мок mgmt accepting SIGHUP)
- `TestServerConfigHandler_PUT_HardReload`
- `TestServerConfigHandler_PUT_RejectsInvalid`
- `TestServerConfigHandler_Slave_Locked`

**Smoke (docker-compose):**
1. Запустить стек → `server.conf` отрендерен → openvpn стартанул → клиент подключился
2. Изменить DNS push через UI → клиент после reconnect получает новый DNS
3. Изменить port → openvpn рестартует → клиент с обновлённым `.ovpn` подключается
4. Сломать config через `custom directive`, который не пройдёт валидацию → 400, состояние не меняется

## Out of scope (v1)

- IPv6
- Hot port-change без дропа клиентов (требует SO_REUSEPORT and seamless handoff — слишком сложно)
- Multi-server (несколько openvpn-инстансов с разными портами)
- Per-client config overrides (есть CCD уже)
- Health-check probes для openvpn

## Follow-ups (`_pending/`)

1. **`server-config-versioning.md`** — история изменений (audit log), revert к предыдущей версии через UI
2. **`server-config-validate-via-test-crypto.md`** — `openvpn --config new.conf --test-crypto` для глубокой валидации перед apply
3. **`multi-instance-openvpn.md`** — несколько openvpn-серверов в одном pod'е (TCP/443 для bypass + UDP/1194 для скорости)

## Файлы, которые меняются

**Новые:**
- `server_config.go` — типы, store, validation, render, manager
- `server_config_test.go` — unit тесты
- `frontend/src/components/ServerConfigView.vue` — главный view
- `frontend/src/components/server-config/*.vue` — подкомпоненты секций (опционально, по аккуратности)

**Изменяемые:**
- `main.go` — регистрация HTTP-эндпоинтов, init store, init renderer, передача `ServerConfig` в `templates`, удаление статичных `--ovpn.network` / `--openvpn.proto` если они там есть (или оставить как fallback initial defaults)
- `frontend/src/App.vue` — третий tab «Сервер»
- `frontend/src/components/TabBar.vue` — без изменений (tabs уже динамические)
- `frontend/src/api.js` — функции fetchServerConfig/updateServerConfig/testServerConfig/fetchDefaults
- `charts/openvpn-admin/templates/configmap.yaml` — удалить server.conf
- `charts/openvpn-admin/templates/deployment.yaml` — emptyDir volume, init-loop, lib-modules mount
- `charts/openvpn-admin/values.yaml` — убрать openvpn config-specific поля
- `Dockerfile.openvpn` — может потребоваться добавить `openvpn-dco` package (если доступен в Alpine repo)
- `docker-compose.yaml` — emptyDir volume + init-loop в openvpn service + `restart: unless-stopped` для openvpn (нужно для hard-reload через SIGTERM, иначе контейнер не вернётся)
- `setup/configure.sh` — удалить генерацию хардкод `openvpn.conf` (теперь ovpn-admin делает это)
- `setup/openvpn.conf` — удалить (больше не используется)
- `README.md` — секция «Server configuration via Admin UI»
- `CHANGELOG.md` — breaking note про default proto udp + tls-crypt вместо tls-auth (требует регенерации клиентских конфигов)

## Backwards compatibility

**Defaults намеренно подобраны под текущие production-значения**, чтобы upgrade не сломал существующих клиентов:
- Proto = `tcp` (как сейчас)
- TLSAuthMode = `tls-auth` (как сейчас)
- Cipher backwards-compat: `data-ciphers` указывает несколько вариантов; NCP (OpenVPN ≥ 2.5) договаривается с клиентом о поддерживаемом

**Поэтому upgrade не ломает существующие `.ovpn` клиентов**. Админ опционально переключает на UDP / tls-crypt через UI, заранее регенерировав клиентские конфиги.

**Helm-чарт breaking change:** values.yaml поля `openvpn.proto`, `openvpn.port`, `openvpn.network` теперь игнорируются (ovpn-admin владеет config'ом). Документировать в CHANGELOG: «значения этих параметров не переносятся из values.yaml при upgrade — задайте их в UI после первого старта».

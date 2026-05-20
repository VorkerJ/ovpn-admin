# Общие маршруты (Common Routes) — дизайн

**Дата:** 2026-05-20
**Статус:** Draft → готов к проверке пользователем
**Тип:** новая фича

## Цель

Дать админу возможность задать набор push-маршрутов, которые применяются ко **всем активным** клиентам OpenVPN. Каждая запись — либо `IP + маска`, либо `домен` (автоматически резолвится в IP-адреса раз в сутки и при добавлении).

Типичный сценарий: «весь YouTube — через VPN», админ вводит `youtube.com`, приложение само поддерживает актуальные IP в CCD-файлах всех юзеров.

## Контекст и решения, принятые на брейншторминге

| Вопрос | Решение |
|--------|---------|
| Что делать при множестве IP за доменом | Все A-записи как отдельные /32 маршруты |
| Что делать при DNS-сбое | Оставлять последние известные IP + предупреждение в UI |
| График обновления | Раз в 24 ч + кнопка «Обновить сейчас» |
| Кому применять | Всем активным (не отозванным) юзерам; применяется при reconnect |
| Хранилище | JSON-файл (filesystem backend) или K8s Secret — тот же паттерн, что у CCD |
| Master/slave | Master редактирует, slave read-only (как сейчас с CCD) |
| UI | Вкладки вверху: «Пользователи» / «Общие маршруты» |
| Механизм применения | Мерж common-маршрутов в каждый CCD-файл при рендере + маркер `# __common__` |

## Архитектура

OpenVPN читает CCD-файл клиента при подключении и не «мержит» несколько файлов. Единственный практичный путь — **сводить общие маршруты в каждый персональный CCD-файл при рендере**. CCD-файлы и так уже рендерятся из шаблона (`templates/ccd.tpl`) для статичного адреса и кастомных push-маршрутов юзера; мы расширяем шаблон, добавив третий блок — общие маршруты с маркером в комментарии.

Альтернатива (модификация `openvpn/server.conf` + рестарт OpenVPN) отклонена: `ovpn-admin` не управляет server.conf, плюс рестарт дропает все активные сессии.

### Поток данных

```
┌──────────────┐     ┌────────────────────┐     ┌─────────────────┐
│   Admin UI   │ ──→ │ /api/common-routes │ ──→ │ CommonRoutes-   │
│ (Vue 3 tab)  │ ←── │      handlers      │     │    Config       │
└──────────────┘     └─────────┬──────────┘     │ (JSON / Secret) │
                               │                 └────────┬────────┘
                               ▼                          │
                     ┌──────────────────┐                 │
                     │  rerenderAllCcds │ ────────────────┤
                     │  (на изменения)  │                 │
                     └─────────┬────────┘                 │
                               ▼                          │
                  ┌────────────────────────┐              │
                  │  modifyCcd(per-user) ──┼──────────────┤
                  │  + expandCommonRoutes  │              │
                  └─────────┬──────────────┘              │
                            ▼                             │
                  ┌────────────────────┐                  │
                  │  ccd/<username>    │                  │
                  │  файлы / Secrets   │                  │
                  └────────────────────┘                  │
                                                          │
              ┌──────────────────────┐                    │
              │  DNS resolver        │ ←──────────────────┘
              │  goroutine (24h)     │  обновляет ResolvedIPs,
              │  + manual refresh    │  триггерит rerender при изменениях
              └──────────────────────┘
```

## Модель данных

```go
type CommonRouteEntry struct {
    ID             string   `json:"id"`              // UUID v4, генерируется бэком
    Kind           string   `json:"kind"`            // "ip" | "domain"
    Address        string   `json:"address,omitempty"` // для kind=ip
    Mask           string   `json:"mask,omitempty"`    // для kind=ip
    Domain         string   `json:"domain,omitempty"`  // для kind=domain
    Description    string   `json:"description"`
    ResolvedIPs    []string `json:"resolved_ips,omitempty"`    // для kind=domain, отсортированные
    LastResolveAt  string   `json:"last_resolve_at,omitempty"` // RFC3339
    LastResolveErr string   `json:"last_resolve_err,omitempty"`// пустая = ок
}

type CommonRoutesConfig struct {
    Routes []CommonRouteEntry `json:"routes"`
}
```

**Маска для kind=domain** фиксирована `255.255.255.255` (/32 на каждый IP), в модели не хранится.

## Хранилище

Повторяет паттерн CCD: тот же `--storage.backend` определяет место хранения.

| Backend | Путь / имя |
|---------|------------|
| `filesystem` | `<ccdDir>/_common_routes.json` (префикс `_` — чтобы не конфликтовать с именами юзеров) |
| `kubernetes.secrets` | Secret `ovpn-admin-common-routes`, ключ `data` = JSON |

**Запись:**
- filesystem: `os.WriteFile` во временный файл `_common_routes.json.tmp` + `os.Rename` (атомарно на POSIX)
- k8s secrets: `Update()` идемпотентен

**Чтение:** при отсутствии — возвращаем пустой `CommonRoutesConfig{Routes: []}`.

## Рендер CCD

### Шаблон `templates/ccd.tpl`

```gotemplate
{{- if (ne .ClientAddress "dynamic") }}
ifconfig-push {{ .ClientAddress }} 255.255.255.0
{{- end }}
{{- range $route := .CustomRoutes }}
push "route {{ $route.Address }} {{ $route.Mask }}" # {{ $route.Description }}
{{- end }}
{{- range $route := .CommonRoutes }}
push "route {{ $route.Address }} {{ $route.Mask }}" # __common__:{{ $route.Tag }} {{ $route.Description }}
{{- end }}
```

`Tag` = `"static"` для kind=ip или имя домена для kind=domain.

### Структуры, передаваемые в шаблон

```go
type ccdCommonRoute struct {
    Address     string
    Mask        string
    Tag         string  // "static" или доменное имя
    Description string
}
```

Существующая `Ccd` структура дополняется полем `CommonRoutes []ccdCommonRoute` (только в render-pipeline, в API она не присутствует).

### `expandCommonRoutes(cfg CommonRoutesConfig) []ccdCommonRoute`

- для `kind=ip`: одна запись (`Address`, `Mask`, `Tag="static"`)
- для `kind=domain`: по одной записи на каждый IP в `ResolvedIPs`, `Mask="255.255.255.255"`, `Tag=domain`
- если у домена пустой `ResolvedIPs` (никогда не резолвился или 0 A-записей) — пропускаем

### Изменения в существующих функциях

**`parseCcd` (`main.go:765-793`)** — при разборе строки `push "route ..."` смотрим на остаток после маски: если содержит `# __common__:` — пропускаем (не добавляем в `ccd.CustomRoutes`). Иначе текущая логика.

**`modifyCcd` (`main.go:795-821`)** — сигнатура меняется на `modifyCcd(ccd Ccd, commonExpanded []ccdCommonRoute) (bool, string)`. Принимает уже **снапшот** развёрнутых common-маршрутов, чтобы не лочить `commonRoutesMu` повторно (см. секцию «Конкурентность»). Перед `t.Execute()`:
```go
ccd.CommonRoutes = commonExpanded
```

**`userApplyCcdHandler`** перед вызовом `modifyCcd` снимает RLock, делает `expanded := expandCommonRoutes(cfg)`, отпускает lock, вызывает `modifyCcd(ccd, expanded)`. Так же поступает любой другой read-then-modify call site.

**Новая `rerenderAllCcds(commonExpanded []ccdCommonRoute)`** в `main.go`:
```go
func (oAdmin *OvpnAdmin) rerenderAllCcds(commonExpanded []ccdCommonRoute) {
    oAdmin.ccdMu.Lock()
    defer oAdmin.ccdMu.Unlock()
    for _, u := range oAdmin.clients {
        if u.AccountStatus == "Active" {
            ccd := oAdmin.getCcd(u.Username)         // без __common__ строк
            oAdmin.modifyCcd(ccd, commonExpanded)    // перезапишет с актуальными
        }
    }
}
```

Вызов из хендлеров: после изменения конфига под write-lock'ом — `expanded := expandCommonRoutes(cfg)`, **затем отпускаем `commonRoutesMu`** (через defer уже сработало), затем `rerenderAllCcds(expanded)`. Это устраняет потенциальный deadlock между `commonRoutesMu` (Write) → `modifyCcd` → RLock того же мьютекса.

## HTTP API

Все эндпоинты под `/api/common-routes/*`, защищены `requireAuth`. На slave мутирующие отвечают `423 Locked`.

| Метод | Путь | Тело | Ответ |
|-------|------|------|-------|
| `GET`  | `/api/common-routes` | — | `{ "routes": [...], "refreshIntervalHours": 24 }` |
| `POST` | `/api/common-routes` | `{kind, address?, mask?, domain?, description}` | `201 { "route": {...} }` (с проставленным `id`) |
| `PUT`  | `/api/common-routes/{id}` | как POST | `200 { "route": {...} }` |
| `DELETE`| `/api/common-routes/{id}` | — | `204 No Content` |
| `POST` | `/api/common-routes/refresh` | — | `200 { "resolved": N, "failed": M, "changed": true|false }` |

### Валидация

| Поле | Правило |
|------|---------|
| `kind` | строго `"ip"` или `"domain"` |
| kind=ip | `address` и `mask` обязательны, проходят `net.ParseIP`; `domain` пустой |
| kind=domain | `domain` обязателен, regex RFC1035: `^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`; `address`/`mask` пустые |
| `description` | опционально, до 200 символов |
| дубль `(kind, address+mask)` или `(kind, domain)` | 409 Conflict `"duplicate entry"` |

### Поведение `POST /refresh`

1. Резолвит все домены через `resolveAllDomains()`.
2. Под write-lock'ом обновляет конфиг и сохраняет.
3. Если хотя бы у одного домена набор IP изменился — вызывает `rerenderAllCcds()`.
4. Возвращает счётчики (для UI-тоста).

### Поведение `POST`/`PUT` при kind=domain

Сразу же синхронный резолв (с тем же 5-сек таймаутом) и сохранение результата, чтобы маршруты применились без ожидания суточного тикера. Если резолв упал — запись сохраняется с `LastResolveErr`, без `ResolvedIPs`. UI получает запись в ответе и показывает предупреждение.

### Регистрация роутов (`main.go:~596`)

```go
http.HandleFunc(*listenBaseUrl+"api/common-routes",          ovpnAdmin.requireAuth(ovpnAdmin.commonRoutesHandler))         // GET/POST
http.HandleFunc(*listenBaseUrl+"api/common-routes/refresh",  ovpnAdmin.requireAuth(ovpnAdmin.commonRoutesRefreshHandler))   // POST
http.HandleFunc(*listenBaseUrl+"api/common-routes/",         ovpnAdmin.requireAuth(ovpnAdmin.commonRoutesItemHandler))      // PUT/DELETE /{id}
```

`http.ServeMux` берёт самый длинный совпадающий паттерн, поэтому `/refresh` (точное совпадение) перекрывает префиксный `/api/common-routes/`. Порядок регистрации не важен, но логически — list/create, потом spec'ы, потом item-handler с trailing slash для остального.

### Module flag

`oAdmin.modules` добавляется `"common-routes"`, чтобы фронт мог скрыть вкладку. Управление через `--common-routes` / `OVPN_COMMON_ROUTES` (default `true`).

## DNS-резолвер

Горутина запускается в `main()` после загрузки конфига и регистрации хендлеров. `context.Context` из `signal.NotifyContext(os.Interrupt, syscall.SIGTERM)` — для graceful shutdown.

- `time.NewTicker(24 * time.Hour)` + первый резолв сразу на старте (чтобы поднять кэш, если он пуст или устарел).
- Для каждого домена: `net.DefaultResolver.LookupIP(ctx, "ip4", domain)` с per-domain `context.WithTimeout(5*time.Second)`.
- IPv4-only в v1. AAAA/IPv6 — out of scope.
- IPs сортируются (`sort.Strings`) для стабильного сравнения с предыдущим набором.
- Запись результата под write-lock'ом, сохранение конфига, затем — если хоть один домен сменил набор — `rerenderAllCcds()`.
- Параллелизма по доменам в v1 нет (десятки доменов × 5с — терпимо, проще без рейсов и rate-limit'а DNS).

## Конкурентность

Две независимые блокировки:

**`commonRoutesMu sync.RWMutex`** — защищает `CommonRoutesConfig` в памяти.
- **RLock**: GET-хендлер, снапшот config при render CCD юзера
- **Lock**: POST/PUT/DELETE/refresh, запись результата DNS-резолва

**`ccdMu sync.Mutex`** — новая, сериализует операции записи CCD-файлов. Защищает пересечение `rerenderAllCcds` с `userApplyCcdHandler` (юзер редактирует свой CCD пока идёт массовый rerender от DNS-обновления).

**Правило отсутствия deadlock'а:**
- `modifyCcd` сам **не лочит** `commonRoutesMu` — принимает уже развёрнутый снапшот `[]ccdCommonRoute`.
- Все call sites действуют по шаблону: захват `commonRoutesMu` → чтение/мутация cfg → expand в локальную переменную → отпустить `commonRoutesMu` → (опционально) `rerenderAllCcds(snapshot)` уже без common-lock'а.
- `rerenderAllCcds` сам захватывает `ccdMu` на всё время итерации.

**DNS-резолвер:** «снял write-lock → достал список доменов → отпустил → пошёл резолвить (5 с/домен) → снова взял write-lock → записал результаты → expand → отпустил → rerender если changed». Сетевые запросы делаются БЕЗ удерживания lock'а.

**Запись JSON-файла:** temp-file + `os.Rename` (атомарно на POSIX). Запись K8s Secret — `Update()` (идемпотентен на стороне kube-apiserver).

## Краевые случаи

| Ситуация | Поведение |
|----------|-----------|
| Дубль | 409 Conflict |
| Домен не резолвится с самого начала | Запись создаётся, `ResolvedIPs=[]`, `LastResolveErr`, в CCD ничего не пушится |
| Домен временно не резолвится при tick | `ResolvedIPs` оставляем, `LastResolveErr` обновляем, перерендер не нужен |
| Резолв вернул 0 IPv4 | Трактуем как ошибку: `LastResolveErr="no A records"`, прошлые IP остаются |
| IP/маска некорректные | 400 с понятным текстом |
| Конфиг отсутствует на диске | При первом сохранении создаётся пустой |
| Slave получает POST/PUT/DELETE | 423 Locked |
| Очень много юзеров и rerender тормозит | Логируем длительность, в v1 не оптимизируем |
| Удалённый CCD-файл вернётся при rerender | Желаемое поведение: общие маршруты применяются ко всем активным независимо от наличия персонального CCD |

## UI

### Навигация (`App.vue`)

Между `AppHeader` и `<main>` добавляется новый компонент `TabBar.vue` с двумя кнопками-вкладками: «Пользователи» / «Общие маршруты». Состояние `activeTab` хранится в `App.vue`, по умолчанию `"users"`.

Если в `modulesEnabled` нет `common-routes` — вкладка скрыта.
На slave вкладка отображается, но всё read-only (как CCD-модал сейчас при `serverRole === 'slave'`).

### Компонент `CommonRoutesView.vue`

1. **Шапка:** заголовок «Общие маршруты», справа кнопка «Обновить DNS сейчас» (вызывает `POST /refresh`, при ответе показывает тост со счётчиками).
2. **Баннер-подсказка** (скрываемый, состояние в localStorage): «ℹ Изменения применяются при следующем подключении клиента. Уже подключённым нужно переподключиться.»
3. **Форма добавления** — компактный блок над таблицей:
   - Сегмент-переключатель: `IP / маска` или `Домен`
   - При IP/маска: два поля `Адрес` + `Маска`
   - При Домен: одно поле `Домен`
   - Поле `Описание` (общее)
   - Кнопка «+ Добавить»
4. **Таблица записей**, колонки:
   - `Тип` (бейдж «IP» или «🌐 Domain»)
   - `Значение` — для IP: `10.0.0.0 / 255.255.255.0`; для домена: `youtube.com` + раскрываемый список IP под ним
   - `Описание`
   - `Статус DNS` (только для доменов) — зелёный «OK · N ч назад» или жёлтый «⚠ DNS error · последний успех M ч назад» (тултип с текстом ошибки)
   - Действия: ✏ Редактировать (открывает `CommonRouteModal.vue`), ✕ Удалить

### `api.js` — новые функции

```js
fetchCommonRoutes()
createCommonRoute({kind, address, mask, domain, description})
updateCommonRoute(id, {...})
deleteCommonRoute(id)
refreshCommonRoutesDns()
```

### Валидация на фронте

Зеркалит бэк: IP-регекс (как в `CcdModal.vue:35`), домен — regex RFC1035. Ошибки в той же стилистике (`bg-destructive/10 border border-destructive/30`).

### Тосты

- «Маршрут добавлен» / «Маршрут обновлён» / «Маршрут удалён»
- «DNS обновлён: резолвлено N, ошибок M»
- «Резолв `<domain>` не удался: …» (если синхронный резолв при добавлении упал — добавление прошло, но с предупреждением)

## Тестирование

### Unit (Go)

- `validateCommonRoute` — все формы валидации и дубли
- `expandCommonRoutes` — преобразование конфига в `[]ccdCommonRoute`
- `parseCcd` — корректно отфильтровывает `# __common__` строки, не теряет персональные
- `modifyCcd` — рендерит шаблон с общими маршрутами поверх персональных
- Сравнение sorted-наборов IP — детектирует изменение

### Integration

- `docker-compose.test.yml`: добавить запись через API → проверить содержимое `ccd/<username>` → подключить тестового клиента → проверить, что route виден в его таблице маршрутизации.

### Manual smoke (после имплементации)

1. Добавить kind=ip `10.20.0.0 / 255.255.0.0` → CCD юзера → reconnect клиента → `route` в системе.
2. Добавить kind=domain `example.com` → клик «Обновить DNS» → IPs видны в UI и в CCD.
3. Удалить запись → CCD очищены от соответствующих push-строк.
4. Перезапуск приложения → кэшированные IP остаются, маршруты применяются сразу.
5. На slave (если разворачивается) → UI read-only.

## Out of scope (v1)

- IPv6 / AAAA-записи
- Конфигурируемый интервал DNS-обновления (фиксированно 24 ч + ручная кнопка)
- Per-route enable/disable флаг
- Per-group или per-user применение
- Аудит-лог изменений
- Импорт/экспорт списка общих маршрутов
- Автоматическая агрегация IP в подсети
- Распараллеленный DNS-резолв

## Файлы, которые затрагиваются

**Новые:**
- `common_routes.go` — модель, хранилище, валидация, expand, DNS-резолвер, хендлеры
- `frontend/src/components/CommonRoutesView.vue`
- `frontend/src/components/modals/CommonRouteModal.vue`
- `frontend/src/components/TabBar.vue`
- `frontend/src/composables/useCommonRoutes.js` (опционально, если разрастётся state)

**Изменяемые:**
- `main.go` — регистрация роутов, флаг `--common-routes`, добавление в `oAdmin.modules`, запуск горутины-резолвера, доработка `parseCcd`/`modifyCcd`, новая `rerenderAllCcds`
- `templates/ccd.tpl` — добавлен блок `range .CommonRoutes`
- `frontend/src/App.vue` — `TabBar`, переключение view
- `frontend/src/api.js` — новые функции

## Совместимость

- Существующие CCD-файлы продолжают работать без изменений: пока не будет ни одной common-route записи, шаблон не выводит ничего лишнего.
- Парсер `parseCcd` обратно совместим: строки без `__common__` обрабатываются как раньше.
- Upgrade path: при первом запуске после деплоя — кэш пуст, фича просто не активна, пока админ не добавит первую запись.

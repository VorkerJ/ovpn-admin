# Common Routes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Добавить вкладку «Общие маршруты», позволяющую админу пушить набор `IP/mask` или `domain` маршрутов всем активным OpenVPN-клиентам с авто-резолвингом доменов раз в сутки.

**Architecture:** Хранение в JSON-файле или K8s Secret (по существующему `--storage.backend`). При рендере CCD-файла каждого юзера общие маршруты домешиваются с маркером `# __common__:<tag>` в комментарии — `parseCcd` их отфильтровывает обратно. Фоновая горутина раз в 24 часа резолвит домены, при изменении набора IP перерендеривает CCD всех активных юзеров.

**Tech Stack:** Go 1.25 (stdlib `net`, `sync`, `time`, `context`, `text/template`), `github.com/google/uuid` (уже в go.mod), Vue 3 + Tailwind, axios. Тесты — стандартный пакет `testing`. Frontend без тестового раннера — ручной smoke + проверка в браузере.

**Spec:** [`docs/superpowers/specs/2026-05-20-common-routes-design.md`](../specs/2026-05-20-common-routes-design.md)

---

## File Structure

**Новые файлы (Go):**
- `common_routes.go` — типы, хранилище (filesystem + k8s), валидация, `expandCommonRoutes`, DNS-резолвер, HTTP-хендлеры. Один файл, потому что все эти функции тесно связаны и в проекте нет паттерна разбиения по слоям.
- `common_routes_test.go` — unit-тесты для валидации, expand, парсинга CCD.

**Новые файлы (Frontend):**
- `frontend/src/components/TabBar.vue` — переключатель вкладок «Пользователи / Общие маршруты».
- `frontend/src/components/CommonRoutesView.vue` — главный view вкладки: шапка с кнопкой refresh, форма добавления, таблица записей.
- `frontend/src/components/modals/CommonRouteModal.vue` — модал редактирования.

**Изменяемые:**
- `main.go` — флаг `--common-routes`, добавление в `oAdmin.modules`, поля `commonRoutesCfg`/`commonRoutesMu`/`ccdMu` в `OvpnAdmin`, регистрация HTTP-роутов, запуск DNS-горутины, доработка `parseCcd` (фильтр `__common__`) и `modifyCcd` (новый параметр `commonExpanded`).
- `templates/ccd.tpl` — блок `{{- range .CommonRoutes }}` с маркером.
- `frontend/src/App.vue` — добавление `TabBar`, состояние `activeTab`, рендер `CommonRoutesView`.
- `frontend/src/api.js` — функции `fetchCommonRoutes`, `createCommonRoute`, `updateCommonRoute`, `deleteCommonRoute`, `refreshCommonRoutesDns`.

---

## Important Project Rules

- **Docker builds: ВСЕГДА `--no-cache`.** Никогда не использовать `docker compose up` без предварительного `build --no-cache`. См. CLAUDE.md — фронт-статика встраивается в бинарник через packr2, кэш молча игнорирует изменения.
- **Frontend → packr2:** после изменений во `frontend/src/` нужно собрать через `npm run build` в каталоге `frontend/`, а потом `packr2` в корне репо, иначе бинарник не подхватит. Это касается ручной локальной сборки; докер делает это сам.
- **Никаких `--no-verify` и пропусков hooks** — если pre-commit hook упал, чинить причину, не обходить.
- **Коммитим часто** — после каждой завершённой задачи отдельным коммитом.

---

## Task 1: Типы и валидация common routes

**Files:**
- Create: `common_routes.go`
- Create: `common_routes_test.go`

- [ ] **Step 1: Создать тесты валидации (RED)**

Создать `common_routes_test.go`:

```go
package main

import (
	"testing"
)

func TestValidateCommonRoute_IP_OK(t *testing.T) {
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.0.0", Description: "lan"}
	if err := validateCommonRoute(e); err != nil {
		t.Fatalf("expected ok, got: %v", err)
	}
}

func TestValidateCommonRoute_IP_BadAddress(t *testing.T) {
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.999", Mask: "255.255.0.0"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on bad address")
	}
}

func TestValidateCommonRoute_IP_BadMask(t *testing.T) {
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "not-a-mask"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on bad mask")
	}
}

func TestValidateCommonRoute_IP_DomainFieldNotEmpty(t *testing.T) {
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.0.0", Domain: "leak"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error when domain set for kind=ip")
	}
}

func TestValidateCommonRoute_Domain_OK(t *testing.T) {
	e := CommonRouteEntry{Kind: "domain", Domain: "youtube.com"}
	if err := validateCommonRoute(e); err != nil {
		t.Fatalf("expected ok, got: %v", err)
	}
}

func TestValidateCommonRoute_Domain_BadDomain(t *testing.T) {
	cases := []string{"", "no_underscore_allowed.com", "-leading-dash.com", "trailing-.com", "single"}
	for _, d := range cases {
		e := CommonRouteEntry{Kind: "domain", Domain: d}
		if err := validateCommonRoute(e); err == nil {
			t.Errorf("expected error for domain %q", d)
		}
	}
}

func TestValidateCommonRoute_Domain_IPFieldNotEmpty(t *testing.T) {
	e := CommonRouteEntry{Kind: "domain", Domain: "youtube.com", Address: "1.1.1.1"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error when address set for kind=domain")
	}
}

func TestValidateCommonRoute_BadKind(t *testing.T) {
	e := CommonRouteEntry{Kind: "weird"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on bad kind")
	}
}

func TestValidateCommonRoute_DescriptionTooLong(t *testing.T) {
	long := make([]byte, 201)
	for i := range long {
		long[i] = 'x'
	}
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.0.0", Description: string(long)}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on description > 200")
	}
}
```

- [ ] **Step 2: Прогнать тесты — должны не компилироваться (RED)**

Run: `go test -run TestValidateCommonRoute -v ./...`
Expected: ошибка компиляции `undefined: CommonRouteEntry` / `undefined: validateCommonRoute`.

- [ ] **Step 3: Создать `common_routes.go` с типами и валидацией**

```go
package main

import (
	"fmt"
	"regexp"
	"net"
	"sync"
)

type CommonRouteEntry struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"` // "ip" | "domain"
	Address        string   `json:"address,omitempty"`
	Mask           string   `json:"mask,omitempty"`
	Domain         string   `json:"domain,omitempty"`
	Description    string   `json:"description"`
	ResolvedIPs    []string `json:"resolved_ips,omitempty"`
	LastResolveAt  string   `json:"last_resolve_at,omitempty"`
	LastResolveErr string   `json:"last_resolve_err,omitempty"`
}

type CommonRoutesConfig struct {
	Routes []CommonRouteEntry `json:"routes"`
}

type ccdCommonRoute struct {
	Address     string
	Mask        string
	Tag         string
	Description string
}

var domainRegexp = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

func validateCommonRoute(e CommonRouteEntry) error {
	if len(e.Description) > 200 {
		return fmt.Errorf("description too long (max 200)")
	}
	switch e.Kind {
	case "ip":
		if e.Domain != "" {
			return fmt.Errorf("domain must be empty for kind=ip")
		}
		if net.ParseIP(e.Address) == nil {
			return fmt.Errorf("address %q is not a valid IP", e.Address)
		}
		if net.ParseIP(e.Mask) == nil {
			return fmt.Errorf("mask %q is not a valid IP-format netmask", e.Mask)
		}
		return nil
	case "domain":
		if e.Address != "" || e.Mask != "" {
			return fmt.Errorf("address/mask must be empty for kind=domain")
		}
		if !domainRegexp.MatchString(e.Domain) {
			return fmt.Errorf("domain %q is not a valid RFC1035 hostname", e.Domain)
		}
		return nil
	default:
		return fmt.Errorf("unknown kind %q (expected ip|domain)", e.Kind)
	}
}

// Concurrency primitives — будут использоваться в следующих задачах.
type commonRoutesStore struct {
	mu  sync.RWMutex
	cfg CommonRoutesConfig
}

// File-level lock на запись CCD-файлов (используется в задаче с rerenderAllCcds).
var ccdMu sync.Mutex
```

- [ ] **Step 4: Прогнать тесты — должны проходить (GREEN)**

Run: `go test -run TestValidateCommonRoute -v ./...`
Expected: все `TestValidateCommonRoute_*` — PASS.

- [ ] **Step 5: Коммит**

```bash
git add common_routes.go common_routes_test.go
git commit -m "feat(common-routes): add types and validation"
```

---

## Task 2: Хранилище — filesystem backend

**Files:**
- Modify: `common_routes.go`
- Modify: `common_routes_test.go`

- [ ] **Step 1: Добавить тесты сохранения/загрузки на файловой системе (RED)**

Добавить в `common_routes_test.go`:

```go
import (
	"os"
	"path/filepath"
	"testing"
)

func TestCommonRoutesFileStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "_common_routes.json")

	original := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "abc", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0", Description: "lan"},
		{ID: "def", Kind: "domain", Domain: "x.io", ResolvedIPs: []string{"1.2.3.4"}},
	}}

	if err := saveCommonRoutesToFile(path, original); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := loadCommonRoutesFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(loaded.Routes))
	}
	if loaded.Routes[1].Domain != "x.io" || loaded.Routes[1].ResolvedIPs[0] != "1.2.3.4" {
		t.Fatalf("data mismatch: %+v", loaded.Routes[1])
	}
}

func TestCommonRoutesFileStore_LoadMissingReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.json")

	cfg, err := loadCommonRoutesFromFile(path)
	if err != nil {
		t.Fatalf("expected no error on missing, got: %v", err)
	}
	if len(cfg.Routes) != 0 {
		t.Fatalf("expected empty routes, got: %+v", cfg.Routes)
	}
}

func TestCommonRoutesFileStore_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "_common_routes.json")

	// Первая запись
	if err := saveCommonRoutesToFile(path, CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "1"}}}); err != nil {
		t.Fatal(err)
	}
	// Вторая запись
	if err := saveCommonRoutesToFile(path, CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "2"}}}); err != nil {
		t.Fatal(err)
	}
	// .tmp файла быть не должно после успеха
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file not cleaned: %v", err)
	}
}
```

- [ ] **Step 2: Прогнать — должно фейлиться по unresolved (RED)**

Run: `go test -run TestCommonRoutesFileStore -v ./...`
Expected: ошибка компиляции `undefined: saveCommonRoutesToFile` / `loadCommonRoutesFromFile`.

- [ ] **Step 3: Имплементация filesystem-стора**

Добавить в `common_routes.go`:

```go
import (
	"encoding/json"
	"os"
)

func loadCommonRoutesFromFile(path string) (CommonRoutesConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return CommonRoutesConfig{Routes: []CommonRouteEntry{}}, nil
		}
		return CommonRoutesConfig{}, err
	}
	var cfg CommonRoutesConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return CommonRoutesConfig{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Routes == nil {
		cfg.Routes = []CommonRouteEntry{}
	}
	return cfg, nil
}

func saveCommonRoutesToFile(path string, cfg CommonRoutesConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
```

- [ ] **Step 4: Прогнать — должны проходить (GREEN)**

Run: `go test -run TestCommonRoutesFileStore -v ./...`
Expected: 3 PASS.

- [ ] **Step 5: Коммит**

```bash
git add common_routes.go common_routes_test.go
git commit -m "feat(common-routes): add filesystem storage backend"
```

---

## Task 3: Хранилище — kubernetes.secrets backend

**Files:**
- Modify: `common_routes.go`
- Modify: `kubernetes.go` (если потребуется добавить helper — проверь существующие `secretGetByName` / `secretUpdate`)

Этот таск — обёртка над существующей k8s-инфрой. Тесты против реального k8s API не пишем (для этого нужен envtest); ограничиваемся unit-тестами для конструктора секрета и интеграционной проверкой в smoke-этапе.

- [ ] **Step 1: Прочитать существующие helpers `secretGetByName` / `secretUpdate` / `secretCreate`**

Read: `kubernetes.go:680-758` (`secretGetCcd`, `secretUpdateCcd`, `secretUpdate`).

Цель — повторить тот же паттерн: один secret с фиксированным именем `ovpn-admin-common-routes`, ключ `data` хранит JSON.

- [ ] **Step 2: Тест для конструктора имени и сериализации**

Добавить в `common_routes_test.go`:

```go
func TestCommonRoutesSecret_KeyName(t *testing.T) {
	if commonRoutesSecretName != "ovpn-admin-common-routes" {
		t.Fatalf("unexpected secret name: %s", commonRoutesSecretName)
	}
}

func TestCommonRoutesSerialize(t *testing.T) {
	cfg := CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "x", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"}}}
	data, err := serializeCommonRoutes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := deserializeCommonRoutes(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Routes[0].ID != "x" {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestCommonRoutesDeserialize_EmptyInput(t *testing.T) {
	cfg, err := deserializeCommonRoutes(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 0 {
		t.Fatalf("expected empty, got %+v", cfg)
	}
}
```

- [ ] **Step 3: Прогнать — RED**

Run: `go test -run "TestCommonRoutesSecret|TestCommonRoutesSerialize|TestCommonRoutesDeserialize" -v ./...`
Expected: ошибки компиляции на отсутствие констант/функций.

- [ ] **Step 4: Имплементация k8s-обёрток**

Добавить в `common_routes.go`:

```go
const commonRoutesSecretName = "ovpn-admin-common-routes"
const commonRoutesSecretDataKey = "data"

func serializeCommonRoutes(cfg CommonRoutesConfig) ([]byte, error) {
	if cfg.Routes == nil {
		cfg.Routes = []CommonRouteEntry{}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func deserializeCommonRoutes(data []byte) (CommonRoutesConfig, error) {
	if len(data) == 0 {
		return CommonRoutesConfig{Routes: []CommonRouteEntry{}}, nil
	}
	var cfg CommonRoutesConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return CommonRoutesConfig{}, err
	}
	if cfg.Routes == nil {
		cfg.Routes = []CommonRouteEntry{}
	}
	return cfg, nil
}
```

В `kubernetes.go` (рядом с `secretGetCcd` / `secretUpdateCcd`, около `kubernetes.go:680`) добавить:

```go
func (openVPNPKI *OpenVPNPKI) secretGetCommonRoutes() ([]byte, error) {
	secret, err := openVPNPKI.secretGetByName(commonRoutesSecretName)
	if err != nil {
		// если secret отсутствует — возвращаем nil, nil (deserializeCommonRoutes отдаст пустой config)
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, err
	}
	return secret.Data[commonRoutesSecretDataKey], nil
}

func (openVPNPKI *OpenVPNPKI) secretUpdateCommonRoutes(data []byte) error {
	secret, err := openVPNPKI.secretGetByName(commonRoutesSecretName)
	if err != nil && strings.Contains(err.Error(), "not found") {
		// create
		objectMeta := metav1.ObjectMeta{
			Name: commonRoutesSecretName,
			Labels: map[string]string{
				labelKeyType:      "common-routes",
				labelKeyManagedBy: labelValueManagedByApp,
			},
		}
		return openVPNPKI.secretCreate(objectMeta, map[string][]byte{commonRoutesSecretDataKey: data}, v1.SecretTypeOpaque)
	}
	if err != nil {
		return err
	}
	secret.Data[commonRoutesSecretDataKey] = data
	return openVPNPKI.secretUpdate(secret.ObjectMeta, secret.Data, v1.SecretTypeOpaque)
}
```

> **Note:** Если в `kubernetes.go` нет `secretCreate`, посмотри как создаются другие secrets (поиск `Create(.*Secret`) и используй тот же подход. Если есть только `secretUpdate` через upsert — можно вызывать его напрямую с пустым `ObjectMeta.ResourceVersion`.

- [ ] **Step 5: Сборка и unit-тесты — GREEN**

Run: `go build ./... && go test -run "TestCommonRoutesSecret|TestCommonRoutesSerialize|TestCommonRoutesDeserialize" -v ./...`
Expected: build OK, 3 PASS.

- [ ] **Step 6: Коммит**

```bash
git add common_routes.go kubernetes.go common_routes_test.go
git commit -m "feat(common-routes): add kubernetes.secrets storage backend"
```

---

## Task 4: Унифицированный store с RWMutex и dispatch'ем на backend

**Files:**
- Modify: `common_routes.go`
- Modify: `common_routes_test.go`

- [ ] **Step 1: Тесты concurrent доступа**

Добавить:

```go
import (
	"sync"
	"testing"
)

func TestCommonRoutesStore_ConcurrentReadWrite(t *testing.T) {
	store := newCommonRoutesStoreForTesting()
	store.replace(CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "a", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"}}})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = store.snapshot()
		}()
		go func() {
			defer wg.Done()
			store.replace(CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "b", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"}}})
		}()
	}
	wg.Wait()
}

func TestCommonRoutesStore_SnapshotIsCopy(t *testing.T) {
	store := newCommonRoutesStoreForTesting()
	store.replace(CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "a", Kind: "domain", Domain: "x.io", ResolvedIPs: []string{"1.1.1.1"}}}})

	snap := store.snapshot()
	snap.Routes[0].ResolvedIPs[0] = "9.9.9.9"

	again := store.snapshot()
	if again.Routes[0].ResolvedIPs[0] == "9.9.9.9" {
		t.Fatal("snapshot must not share underlying slice")
	}
}
```

- [ ] **Step 2: Запустить — RED**

Run: `go test -run TestCommonRoutesStore -v ./...`
Expected: `undefined: newCommonRoutesStoreForTesting`.

- [ ] **Step 3: Имплементация store**

В `common_routes.go` заменить ранее объявленную пустую `commonRoutesStore` на:

```go
type commonRoutesStore struct {
	mu sync.RWMutex
	cfg CommonRoutesConfig
}

// snapshot возвращает deep-copy конфига, безопасную для чтения без блокировки.
func (s *commonRoutesStore) snapshot() CommonRoutesConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := CommonRoutesConfig{Routes: make([]CommonRouteEntry, len(s.cfg.Routes))}
	for i, r := range s.cfg.Routes {
		c := r
		if r.ResolvedIPs != nil {
			c.ResolvedIPs = append([]string(nil), r.ResolvedIPs...)
		}
		out.Routes[i] = c
	}
	return out
}

// replace заменяет конфиг целиком под write-lock'ом.
func (s *commonRoutesStore) replace(cfg CommonRoutesConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.Routes == nil {
		cfg.Routes = []CommonRouteEntry{}
	}
	s.cfg = cfg
}

// withWrite берёт write-lock, передаёт указатель на cfg в callback (внутри — модификации).
// Возвращает копию изменённого конфига, чтобы можно было сохранить наружу без удержания lock'а.
func (s *commonRoutesStore) withWrite(fn func(cfg *CommonRoutesConfig) error) (CommonRoutesConfig, error) {
	s.mu.Lock()
	if err := fn(&s.cfg); err != nil {
		s.mu.Unlock()
		return CommonRoutesConfig{}, err
	}
	cfgCopy := s.cfg
	s.mu.Unlock()
	return cfgCopy, nil
}

// newCommonRoutesStoreForTesting — конструктор для тестов; в проде создаётся в main.go.
func newCommonRoutesStoreForTesting() *commonRoutesStore {
	return &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}
}
```

- [ ] **Step 4: Прогнать тесты + `-race`**

Run: `go test -race -run TestCommonRoutesStore -v ./...`
Expected: PASS, без race-warnings.

- [ ] **Step 5: Коммит**

```bash
git add common_routes.go common_routes_test.go
git commit -m "feat(common-routes): add in-memory store with RWMutex"
```

---

## Task 5: `expandCommonRoutes` — преобразование конфига в render-структуры

**Files:**
- Modify: `common_routes.go`
- Modify: `common_routes_test.go`

- [ ] **Step 1: Тесты expand**

```go
func TestExpandCommonRoutes_IP(t *testing.T) {
	cfg := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "a", Kind: "ip", Address: "10.0.0.0", Mask: "255.255.0.0", Description: "lan"},
	}}
	out := expandCommonRoutes(cfg)
	if len(out) != 1 {
		t.Fatalf("want 1, got %d", len(out))
	}
	if out[0].Address != "10.0.0.0" || out[0].Mask != "255.255.0.0" || out[0].Tag != "static" {
		t.Fatalf("got %+v", out[0])
	}
}

func TestExpandCommonRoutes_Domain_MultipleIPs(t *testing.T) {
	cfg := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "b", Kind: "domain", Domain: "yt.com", ResolvedIPs: []string{"1.1.1.1", "2.2.2.2"}, Description: "youtube"},
	}}
	out := expandCommonRoutes(cfg)
	if len(out) != 2 {
		t.Fatalf("want 2, got %d", len(out))
	}
	for _, r := range out {
		if r.Mask != "255.255.255.255" {
			t.Errorf("expected /32 mask, got %s", r.Mask)
		}
		if r.Tag != "yt.com" {
			t.Errorf("expected tag=yt.com, got %s", r.Tag)
		}
	}
}

func TestExpandCommonRoutes_Domain_EmptyResolved(t *testing.T) {
	cfg := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "c", Kind: "domain", Domain: "fail.com", ResolvedIPs: nil},
	}}
	out := expandCommonRoutes(cfg)
	if len(out) != 0 {
		t.Fatalf("expected nothing for unresolved domain, got %d", len(out))
	}
}

func TestExpandCommonRoutes_Mixed(t *testing.T) {
	cfg := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"},
		{Kind: "domain", Domain: "yt.com", ResolvedIPs: []string{"1.1.1.1"}},
		{Kind: "domain", Domain: "unresolved.com"},
	}}
	out := expandCommonRoutes(cfg)
	if len(out) != 2 {
		t.Fatalf("want 2, got %d", len(out))
	}
}
```

- [ ] **Step 2: Прогнать — RED**

Run: `go test -run TestExpandCommonRoutes -v ./...`
Expected: `undefined: expandCommonRoutes`.

- [ ] **Step 3: Имплементация**

В `common_routes.go`:

```go
func expandCommonRoutes(cfg CommonRoutesConfig) []ccdCommonRoute {
	out := make([]ccdCommonRoute, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		switch r.Kind {
		case "ip":
			out = append(out, ccdCommonRoute{
				Address:     r.Address,
				Mask:        r.Mask,
				Tag:         "static",
				Description: r.Description,
			})
		case "domain":
			for _, ip := range r.ResolvedIPs {
				out = append(out, ccdCommonRoute{
					Address:     ip,
					Mask:        "255.255.255.255",
					Tag:         r.Domain,
					Description: r.Description,
				})
			}
		}
	}
	return out
}
```

- [ ] **Step 4: Прогнать — GREEN**

Run: `go test -run TestExpandCommonRoutes -v ./...`
Expected: 4 PASS.

- [ ] **Step 5: Коммит**

```bash
git add common_routes.go common_routes_test.go
git commit -m "feat(common-routes): add expandCommonRoutes"
```

---

## Task 6: Обновить `ccd.tpl` шаблон и `parseCcd` (фильтр `__common__`)

**Files:**
- Modify: `templates/ccd.tpl`
- Modify: `main.go` (функция `parseCcd`, `~main.go:765-793`; добавить поле `CommonRoutes` в struct `Ccd`)
- Modify: `common_routes_test.go`

- [ ] **Step 1: Тесты для `parseCcd`-фильтра**

Добавить в `common_routes_test.go`:

```go
func TestParseCcd_FiltersCommonMarker(t *testing.T) {
	dir := t.TempDir()
	username := "alice"
	path := dir + "/" + username
	content := `ifconfig-push 10.0.0.5 255.255.255.0
push "route 192.168.1.0 255.255.255.0" # corp
push "route 142.250.1.1 255.255.255.255" # __common__:yt.com youtube
push "route 142.250.1.2 255.255.255.255" # __common__:yt.com youtube
push "route 8.8.8.8 255.255.255.255" # dns
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// parseCcd читает по абсолютному пути <ccdDir>/<username>. Сэмулируем флаг.
	original := *ccdDir
	tmp := dir
	ccdDir = &tmp
	defer func() { ccdDir = &original }()

	oAdmin := &OvpnAdmin{}
	ccd := oAdmin.parseCcd(username)
	if ccd.ClientAddress != "10.0.0.5" {
		t.Errorf("ClientAddress: got %s", ccd.ClientAddress)
	}
	if len(ccd.CustomRoutes) != 2 {
		t.Fatalf("expected 2 user routes (192.168.x and 8.8.8.8), got %d: %+v", len(ccd.CustomRoutes), ccd.CustomRoutes)
	}
	for _, r := range ccd.CustomRoutes {
		if r.Address == "142.250.1.1" || r.Address == "142.250.1.2" {
			t.Errorf("__common__ route leaked into user routes: %+v", r)
		}
	}
}
```

- [ ] **Step 2: Прогнать — RED**

Run: `go test -run TestParseCcd_FiltersCommonMarker -v ./...`
Expected: test FAIL (текущий `parseCcd` не фильтрует маркер) — `expected 2 user routes, got 4`.

- [ ] **Step 3: Обновить `templates/ccd.tpl`**

Текущее содержимое заменить на:

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

- [ ] **Step 4: Добавить `CommonRoutes` поле в struct `Ccd` (`main.go:233-237`)**

```go
type Ccd struct {
	User          string           `json:"User"`
	ClientAddress string           `json:"ClientAddress"`
	CustomRoutes  []ccdRoute       `json:"CustomRoutes"`
	CommonRoutes  []ccdCommonRoute `json:"-"` // не сериализуется в API, только для рендера
}
```

- [ ] **Step 5: Обновить `parseCcd` (`main.go:780-790`) для фильтрации `__common__`**

Заменить блок:

```go
for _, v := range txtLinesArray {
    str := strings.Fields(v)
    if len(str) > 0 {
        switch {
        case strings.HasPrefix(str[0], "ifconfig-push"):
            ccd.ClientAddress = str[1]
        case strings.HasPrefix(str[0], "push"):
            ccd.CustomRoutes = append(ccd.CustomRoutes, ccdRoute{Address: strings.Trim(str[2], "\""), Mask: strings.Trim(str[3], "\""), Description: strings.Trim(strings.Join(str[4:], ""), "#")})
        }
    }
}
```

на:

```go
for _, v := range txtLinesArray {
    str := strings.Fields(v)
    if len(str) == 0 {
        continue
    }
    switch {
    case strings.HasPrefix(str[0], "ifconfig-push"):
        ccd.ClientAddress = str[1]
    case strings.HasPrefix(str[0], "push"):
        if strings.Contains(v, "# __common__:") {
            continue // строка добавлена common-routes — пропускаем
        }
        ccd.CustomRoutes = append(ccd.CustomRoutes, ccdRoute{
            Address:     strings.Trim(str[2], "\""),
            Mask:        strings.Trim(str[3], "\""),
            Description: strings.Trim(strings.Join(str[4:], ""), "#"),
        })
    }
}
```

- [ ] **Step 6: Прогнать тест — GREEN**

Run: `go test -run TestParseCcd_FiltersCommonMarker -v ./...`
Expected: PASS.

- [ ] **Step 7: Прогнать всю Go-сборку**

Run: `go build ./...`
Expected: успешная сборка (struct `Ccd` изменилась — убедиться что весь использующий её код компилируется).

- [ ] **Step 8: Коммит**

```bash
git add templates/ccd.tpl main.go common_routes_test.go
git commit -m "feat(common-routes): extend ccd.tpl and filter __common__ in parseCcd"
```

---

## Task 7: Рефакторинг `modifyCcd` — принимает `commonExpanded`

**Files:**
- Modify: `main.go` (функция `modifyCcd` `~main.go:795-821`, и **все** её call-sites: `userApplyCcdHandler` `~main.go:422`)
- Modify: `common_routes_test.go`

- [ ] **Step 1: Тест что modifyCcd рендерит общие маршруты**

```go
func TestModifyCcd_RendersCommonRoutes(t *testing.T) {
	dir := t.TempDir()
	original := *ccdDir
	ccdDir = &dir
	defer func() { ccdDir = &original }()

	// Подготовим templates packr — но для теста проще: вызываем напрямую template-функцию через тестовый шаблон,
	// либо проверим выходной файл после modifyCcd, прочитав его и распарсив.
	// Используем packr-box из ./templates.
	app := &OvpnAdmin{}
	app.templates = packr.New("template", "./templates")

	ccd := Ccd{
		User:          "bob",
		ClientAddress: "dynamic",
		CustomRoutes:  []ccdRoute{{Address: "10.0.0.0", Mask: "255.255.255.0", Description: "lan"}},
	}
	common := []ccdCommonRoute{
		{Address: "1.1.1.1", Mask: "255.255.255.255", Tag: "yt.com", Description: "youtube"},
	}

	storageOriginal := *storageBackend
	fs := "filesystem"
	storageBackend = &fs
	defer func() { storageBackend = &storageOriginal }()

	ok, msg := app.modifyCcd(ccd, common)
	if !ok {
		t.Fatalf("modifyCcd failed: %s", msg)
	}

	data, err := os.ReadFile(dir + "/bob")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, `push "route 10.0.0.0 255.255.255.0"`) {
		t.Errorf("user route missing:\n%s", content)
	}
	if !strings.Contains(content, `push "route 1.1.1.1 255.255.255.255" # __common__:yt.com`) {
		t.Errorf("common route missing:\n%s", content)
	}
}
```

(Если packr-box не находится в тесте — переключиться на `template.New(...).Parse(...)` с inline шаблоном, либо использовать `t.Skip` если запускается без packr. Альтернатива: вынести `getCcdTemplate` так, чтобы он принимал источник.)

- [ ] **Step 2: Прогнать — RED**

Run: `go test -run TestModifyCcd_RendersCommonRoutes -v ./...`
Expected: compile error (сигнатура `modifyCcd` пока не принимает второй аргумент).

- [ ] **Step 3: Изменить сигнатуру `modifyCcd`**

В `main.go` функцию `modifyCcd` (`~main.go:795`) переписать:

```go
func (oAdmin *OvpnAdmin) modifyCcd(ccd Ccd, commonExpanded []ccdCommonRoute) (bool, string) {
    ccdValid, err := validateCcd(ccd)
    if err != "" {
        return false, err
    }
    if !ccdValid {
        return false, "something goes wrong"
    }

    ccd.CommonRoutes = commonExpanded

    t := oAdmin.getCcdTemplate()
    var tmp bytes.Buffer
    if err := t.Execute(&tmp, ccd); err != nil {
        log.Error(err)
        return false, "template render failed"
    }

    if *storageBackend == "kubernetes.secrets" {
        app.secretUpdateCcd(ccd.User, tmp.Bytes())
    } else {
        if err := fWrite(*ccdDir+"/"+ccd.User, tmp.String()); err != nil {
            log.Errorf("modifyCcd: fWrite(): %v", err)
            return false, "write failed"
        }
    }
    return true, "ccd updated successfully"
}
```

- [ ] **Step 4: Обновить `userApplyCcdHandler` (`main.go:422`)**

Было: `ccdApplied, applyStatus := oAdmin.modifyCcd(ccd)`

Стало:

```go
expanded := expandCommonRoutes(oAdmin.commonRoutes.snapshot())
ccdApplied, applyStatus := oAdmin.modifyCcd(ccd, expanded)
```

> **Зависимость:** в `OvpnAdmin` ещё нет поля `commonRoutes` — добавим в Task 9. Пока эта строка скомпилируется, если в задаче 9 поле будет того же типа. Чтобы не разрывать flow, **сразу же** перейти к Task 9 после этой задачи, или временно положить compile-time stub: добавить пустое поле `commonRoutes *commonRoutesStore` в `OvpnAdmin` (Task 9 его заполнит).

Чтобы избежать broken-build между задачами, в **этом** же таске добавить поле:

```go
type OvpnAdmin struct {
    // ... существующие поля ...
    commonRoutes *commonRoutesStore
}
```

И в `main()` инициализировать минимально:

```go
ovpnAdmin.commonRoutes = &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}
```

(полная инициализация с загрузкой — в Task 9).

- [ ] **Step 5: Прогнать тесты и build**

Run: `go build ./... && go test -run TestModifyCcd -v ./...`
Expected: build OK, тест PASS (если packr нашёл шаблоны — что должно быть из рабочей директории корня репо).

- [ ] **Step 6: Коммит**

```bash
git add main.go common_routes_test.go
git commit -m "refactor(ccd): modifyCcd takes commonExpanded snapshot"
```

---

## Task 8: `rerenderAllCcds`

**Files:**
- Modify: `main.go` (добавить метод `rerenderAllCcds`)
- Modify: `common_routes.go` (либо `main.go` — выбор по эстетике; ccdMu уже в `common_routes.go` из Task 1)

- [ ] **Step 1: Тест — добавление common-route должно перерендерить CCD активного юзера**

Этот тест в полном виде потребует docker-compose; для unit-варианта проверяем только логику итерации. Если writing-test слишком тяжёл — можно его опустить и валидировать в smoke-тесте (Task 14). Минимально:

```go
func TestRerenderAllCcds_SkipsRevoked(t *testing.T) {
	app := &OvpnAdmin{
		clients: []OpenvpnClient{
			{Identity: "alice", AccountStatus: "Active"},
			{Identity: "bob", AccountStatus: "Revoked"},
		},
	}
	app.commonRoutes = &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}

	var rendered []string
	// monkey-patch недоступен в Go; используем seam: внутреннюю функцию forEachActiveUser, которую можно тестировать.
	rendered = collectActiveUsernames(app)
	if len(rendered) != 1 || rendered[0] != "alice" {
		t.Fatalf("expected only alice, got %v", rendered)
	}
}

// helper для теста:
func collectActiveUsernames(oAdmin *OvpnAdmin) []string {
	var out []string
	for _, u := range oAdmin.clients {
		if u.AccountStatus == "Active" {
			out = append(out, u.Identity)
		}
	}
	return out
}
```

> **Note:** Если эта seam-функция показалась искусственной — оставить только smoke-тест в Task 14, удалить unit-тест Step 1.

- [ ] **Step 2: Имплементация `rerenderAllCcds`**

В `main.go` добавить:

```go
func (oAdmin *OvpnAdmin) rerenderAllCcds(commonExpanded []ccdCommonRoute) {
    ccdMu.Lock()
    defer ccdMu.Unlock()

    start := time.Now()
    count := 0
    for _, u := range oAdmin.clients {
        if u.AccountStatus != "Active" {
            continue
        }
        ccd := oAdmin.getCcd(u.Identity)
        ok, msg := oAdmin.modifyCcd(ccd, commonExpanded)
        if !ok {
            log.Warnf("rerenderAllCcds: %s: %s", u.Identity, msg)
            continue
        }
        count++
    }
    log.Infof("rerenderAllCcds: rerendered %d CCDs in %s", count, time.Since(start))
}
```

> **Field name reality check:** `OpenvpnClient.Identity` — поле из `main.go:219`. Проверь актуальное имя поля при правке.

- [ ] **Step 3: Build OK, опциональные тесты**

Run: `go build ./...`
Expected: успешная сборка.

- [ ] **Step 4: Коммит**

```bash
git add main.go common_routes_test.go
git commit -m "feat(common-routes): add rerenderAllCcds"
```

---

## Task 9: DNS-резолвер

**Files:**
- Modify: `common_routes.go`
- Modify: `common_routes_test.go`

- [ ] **Step 1: Тесты для compare/sort**

```go
func TestSameIPSet(t *testing.T) {
	if !sameIPSet([]string{"1.1.1.1", "2.2.2.2"}, []string{"2.2.2.2", "1.1.1.1"}) {
		t.Fatal("set equality must ignore order")
	}
	if sameIPSet([]string{"1.1.1.1"}, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Fatal("different lengths must differ")
	}
	if sameIPSet([]string{"1.1.1.1"}, []string{"2.2.2.2"}) {
		t.Fatal("different values must differ")
	}
}

func TestSortedIPv4Strings(t *testing.T) {
	out := sortedIPv4Strings([]string{"10.0.0.1", "1.1.1.1", "192.168.1.1"})
	want := []string{"1.1.1.1", "10.0.0.1", "192.168.1.1"} // лексикографически
	for i := range out {
		if out[i] != want[i] {
			t.Fatalf("got %v, want %v", out, want)
		}
	}
}
```

- [ ] **Step 2: Прогнать — RED**

Run: `go test -run "TestSameIPSet|TestSortedIPv4Strings" -v ./...`
Expected: unresolved.

- [ ] **Step 3: Имплементация helpers и резолвера**

В `common_routes.go`:

```go
import (
	"context"
	"net"
	"sort"
	"time"
)

func sortedIPv4Strings(ips []string) []string {
	out := append([]string(nil), ips...)
	sort.Strings(out)
	return out
}

func sameIPSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := sortedIPv4Strings(a)
	bc := sortedIPv4Strings(b)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

// resolveOneDomain выполняет один LookupIP с таймаутом и возвращает только IPv4.
func resolveOneDomain(ctx context.Context, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no A records")
	}
	out := make([]string, 0, len(addrs))
	for _, ip := range addrs {
		out = append(out, ip.String())
	}
	return sortedIPv4Strings(out), nil
}

// refreshAllDomains итерирует cfg, резолвит каждый kind=domain.
// Возвращает: (новый cfg, changed?, resolvedCount, failedCount).
// cfg.Routes мутируется (LastResolveAt/Err/ResolvedIPs).
func refreshAllDomains(ctx context.Context, cfg CommonRoutesConfig, now time.Time) (CommonRoutesConfig, bool, int, int) {
	changed := false
	resolved, failed := 0, 0
	for i, r := range cfg.Routes {
		if r.Kind != "domain" {
			continue
		}
		ips, err := resolveOneDomain(ctx, r.Domain)
		cfg.Routes[i].LastResolveAt = now.UTC().Format(time.RFC3339)
		if err != nil {
			cfg.Routes[i].LastResolveErr = err.Error()
			failed++
			continue
		}
		cfg.Routes[i].LastResolveErr = ""
		if !sameIPSet(r.ResolvedIPs, ips) {
			cfg.Routes[i].ResolvedIPs = ips
			changed = true
		}
		resolved++
	}
	return cfg, changed, resolved, failed
}
```

- [ ] **Step 4: Тесты helpers — GREEN**

Run: `go test -race -run "TestSameIPSet|TestSortedIPv4Strings" -v ./...`
Expected: PASS.

- [ ] **Step 5: Тест `refreshAllDomains` с моком резолвера**

Чтобы протестировать без реальной сети, добавим переменную-резолвер, чтобы можно было подменить:

```go
var domainResolver = resolveOneDomain // can be overridden in tests
```

И поменять вызов внутри `refreshAllDomains` на `domainResolver(ctx, r.Domain)`. Тогда тест:

```go
func TestRefreshAllDomains_MarksChangedAndStatus(t *testing.T) {
	original := domainResolver
	defer func() { domainResolver = original }()

	calls := 0
	domainResolver = func(ctx context.Context, d string) ([]string, error) {
		calls++
		switch d {
		case "good.com":
			return []string{"1.1.1.1"}, nil
		case "fail.com":
			return nil, fmt.Errorf("dns timeout")
		}
		return nil, fmt.Errorf("unexpected domain %s", d)
	}

	cfg := CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "a", Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"},
		{ID: "b", Kind: "domain", Domain: "good.com", ResolvedIPs: []string{"9.9.9.9"}},
		{ID: "c", Kind: "domain", Domain: "fail.com", ResolvedIPs: []string{"7.7.7.7"}},
	}}

	out, changed, ok, failed := refreshAllDomains(context.Background(), cfg, time.Now())
	if !changed {
		t.Errorf("expected changed=true (good.com IPs changed)")
	}
	if ok != 1 || failed != 1 {
		t.Errorf("counters wrong: ok=%d failed=%d", ok, failed)
	}
	if out.Routes[1].ResolvedIPs[0] != "1.1.1.1" {
		t.Errorf("good.com IP not updated")
	}
	if out.Routes[2].ResolvedIPs[0] != "7.7.7.7" {
		t.Errorf("fail.com IPs should be preserved on error")
	}
	if out.Routes[2].LastResolveErr == "" {
		t.Errorf("fail.com LastResolveErr should be set")
	}
}
```

- [ ] **Step 6: Прогнать**

Run: `go test -race -run TestRefreshAllDomains -v ./...`
Expected: PASS.

- [ ] **Step 7: Коммит**

```bash
git add common_routes.go common_routes_test.go
git commit -m "feat(common-routes): add DNS resolver"
```

---

## Task 10: HTTP-хендлеры

**Files:**
- Modify: `common_routes.go` (хендлеры) или новый `common_routes_http.go`. Идём по `common_routes.go` пока укладывается.
- Modify: `common_routes_test.go`

- [ ] **Step 1: Тесты хендлеров через `httptest`**

```go
import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestAdmin(t *testing.T) *OvpnAdmin {
	t.Helper()
	app := &OvpnAdmin{
		role: "master",
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}},
	}
	// Чтобы хендлеры могли сохранять — переключаемся на filesystem с временным dir
	dir := t.TempDir()
	tmp := dir
	ccdDir = &tmp
	storage := "filesystem"
	storageBackend = &storage
	commonRoutesFile := dir + "/_common_routes.json"
	app.commonRoutesPath = commonRoutesFile  // см. Step 2 — добавим поле
	return app
}

func TestCommonRoutesHandler_GET_Empty(t *testing.T) {
	app := newTestAdmin(t)
	req := httptest.NewRequest(http.MethodGet, "/api/common-routes", nil)
	rec := httptest.NewRecorder()
	app.commonRoutesHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	var got struct {
		Routes []CommonRouteEntry `json:"routes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Routes == nil {
		t.Fatal("routes must be non-nil slice (even if empty) for JSON consumers")
	}
}

func TestCommonRoutesHandler_POST_CreatesEntry(t *testing.T) {
	app := newTestAdmin(t)
	body := []byte(`{"kind":"ip","address":"10.0.0.0","mask":"255.255.0.0","description":"lan"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/common-routes", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.commonRoutesHandler(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
	}
	snap := app.commonRoutes.snapshot()
	if len(snap.Routes) != 1 || snap.Routes[0].ID == "" {
		t.Fatalf("entry not stored: %+v", snap)
	}
}

func TestCommonRoutesHandler_POST_RejectsDuplicate(t *testing.T) {
	app := newTestAdmin(t)
	body := []byte(`{"kind":"ip","address":"10.0.0.0","mask":"255.255.0.0"}`)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/common-routes", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		app.commonRoutesHandler(rec, req)
		if i == 1 && rec.Code != http.StatusConflict {
			t.Fatalf("expected 409 on duplicate, got %d", rec.Code)
		}
	}
}

func TestCommonRoutesHandler_Slave_Locked(t *testing.T) {
	app := newTestAdmin(t)
	app.role = "slave"
	body := []byte(`{"kind":"ip","address":"10.0.0.0","mask":"255.0.0.0"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/common-routes", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.commonRoutesHandler(rec, req)
	if rec.Code != http.StatusLocked {
		t.Fatalf("expected 423, got %d", rec.Code)
	}
}

func TestCommonRoutesItemHandler_DELETE(t *testing.T) {
	app := newTestAdmin(t)
	// pre-seed
	id := "test-uuid"
	app.commonRoutes.replace(CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: id, Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0"}}})

	req := httptest.NewRequest(http.MethodDelete, "/api/common-routes/"+id, nil)
	rec := httptest.NewRecorder()
	app.commonRoutesItemHandler(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if len(app.commonRoutes.snapshot().Routes) != 0 {
		t.Fatal("entry not deleted")
	}
}

func TestCommonRoutesItemHandler_PUT(t *testing.T) {
	app := newTestAdmin(t)
	id := "test-uuid"
	app.commonRoutes.replace(CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: id, Kind: "ip", Address: "10.0.0.0", Mask: "255.0.0.0", Description: "old"}}})

	body := []byte(`{"kind":"ip","address":"10.0.0.0","mask":"255.255.0.0","description":"new"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/common-routes/"+id, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.commonRoutesItemHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	snap := app.commonRoutes.snapshot()
	if snap.Routes[0].Description != "new" || snap.Routes[0].Mask != "255.255.0.0" {
		t.Fatalf("update not applied: %+v", snap.Routes[0])
	}
}
```

- [ ] **Step 2: Имплементация хендлеров**

В `common_routes.go` добавить:

```go
import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// (поле commonRoutesPath добавляется в OvpnAdmin в Task 11 main-wiring; здесь полагаемся на него)

const commonRoutesRefreshIntervalHours = 24

func (oAdmin *OvpnAdmin) commonRoutesHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	switch r.Method {
	case http.MethodGet:
		snap := oAdmin.commonRoutes.snapshot()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"routes":               snap.Routes,
			"refreshIntervalHours": commonRoutesRefreshIntervalHours,
		})
	case http.MethodPost:
		if oAdmin.role == "slave" {
			http.Error(w, `{"status":"error","message":"slave is read-only"}`, http.StatusLocked)
			return
		}
		oAdmin.handleCreateCommonRoute(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (oAdmin *OvpnAdmin) commonRoutesItemHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	// /api/common-routes/<id> — извлекаем id
	id := strings.TrimPrefix(r.URL.Path, "/api/common-routes/")
	// учесть listenBaseUrl если он отличается от "/" — приложение монтируется на base url, request.URL.Path уже относительный
	if idx := strings.Index(id, "/"); idx != -1 {
		id = id[:idx]
	}
	if id == "" || id == "refresh" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error","message":"slave is read-only"}`, http.StatusLocked)
		return
	}

	switch r.Method {
	case http.MethodPut:
		oAdmin.handleUpdateCommonRoute(w, r, id)
	case http.MethodDelete:
		oAdmin.handleDeleteCommonRoute(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (oAdmin *OvpnAdmin) commonRoutesRefreshHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error","message":"slave is read-only"}`, http.StatusLocked)
		return
	}

	current := oAdmin.commonRoutes.snapshot()
	updated, changed, ok, failed := refreshAllDomains(r.Context(), current, time.Now())

	oAdmin.commonRoutes.replace(updated)
	if err := oAdmin.persistCommonRoutes(updated); err != nil {
		log.Errorf("persistCommonRoutes: %v", err)
	}

	if changed {
		expanded := expandCommonRoutes(updated)
		go oAdmin.rerenderAllCcds(expanded)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"resolved": ok,
		"failed":   failed,
		"changed":  changed,
	})
}

func (oAdmin *OvpnAdmin) handleCreateCommonRoute(w http.ResponseWriter, r *http.Request) {
	var in CommonRouteEntry
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	in.ID = uuid.New().String()
	if err := validateCommonRoute(in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	current := oAdmin.commonRoutes.snapshot()
	if isDuplicateCommonRoute(current, in) {
		http.Error(w, "duplicate entry", http.StatusConflict)
		return
	}

	// Если kind=domain — пробуем синхронный резолв (best-effort)
	if in.Kind == "domain" {
		ips, err := resolveOneDomain(r.Context(), in.Domain)
		in.LastResolveAt = time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			in.LastResolveErr = err.Error()
		} else {
			in.ResolvedIPs = ips
			in.LastResolveErr = ""
		}
	}

	current.Routes = append(current.Routes, in)
	oAdmin.commonRoutes.replace(current)
	if err := oAdmin.persistCommonRoutes(current); err != nil {
		log.Errorf("persist: %v", err)
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}

	expanded := expandCommonRoutes(current)
	go oAdmin.rerenderAllCcds(expanded)

	writeJSON(w, http.StatusCreated, map[string]interface{}{"route": in})
}

func (oAdmin *OvpnAdmin) handleUpdateCommonRoute(w http.ResponseWriter, r *http.Request, id string) {
	var in CommonRouteEntry
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	in.ID = id
	if err := validateCommonRoute(in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	current := oAdmin.commonRoutes.snapshot()
	idx := -1
	for i, r := range current.Routes {
		if r.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Сохраняем ResolvedIPs если ключ домена тот же
	if in.Kind == "domain" && current.Routes[idx].Kind == "domain" && current.Routes[idx].Domain == in.Domain {
		in.ResolvedIPs = current.Routes[idx].ResolvedIPs
		in.LastResolveAt = current.Routes[idx].LastResolveAt
		in.LastResolveErr = current.Routes[idx].LastResolveErr
	} else if in.Kind == "domain" {
		// домен поменялся — резолвим
		ips, err := resolveOneDomain(r.Context(), in.Domain)
		in.LastResolveAt = time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			in.LastResolveErr = err.Error()
		} else {
			in.ResolvedIPs = ips
		}
	}

	current.Routes[idx] = in
	if isDuplicateCommonRoute(removeAt(current, idx), in) {
		http.Error(w, "duplicate entry", http.StatusConflict)
		return
	}

	oAdmin.commonRoutes.replace(current)
	if err := oAdmin.persistCommonRoutes(current); err != nil {
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}

	expanded := expandCommonRoutes(current)
	go oAdmin.rerenderAllCcds(expanded)

	writeJSON(w, http.StatusOK, map[string]interface{}{"route": in})
}

func (oAdmin *OvpnAdmin) handleDeleteCommonRoute(w http.ResponseWriter, r *http.Request, id string) {
	current := oAdmin.commonRoutes.snapshot()
	idx := -1
	for i, rt := range current.Routes {
		if rt.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	current.Routes = append(current.Routes[:idx], current.Routes[idx+1:]...)
	oAdmin.commonRoutes.replace(current)
	if err := oAdmin.persistCommonRoutes(current); err != nil {
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}

	expanded := expandCommonRoutes(current)
	go oAdmin.rerenderAllCcds(expanded)

	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func isDuplicateCommonRoute(cfg CommonRoutesConfig, e CommonRouteEntry) bool {
	for _, r := range cfg.Routes {
		if r.ID == e.ID {
			continue // self
		}
		switch e.Kind {
		case "ip":
			if r.Kind == "ip" && r.Address == e.Address && r.Mask == e.Mask {
				return true
			}
		case "domain":
			if r.Kind == "domain" && r.Domain == e.Domain {
				return true
			}
		}
	}
	return false
}

func removeAt(cfg CommonRoutesConfig, idx int) CommonRoutesConfig {
	out := CommonRoutesConfig{Routes: make([]CommonRouteEntry, 0, len(cfg.Routes)-1)}
	for i, r := range cfg.Routes {
		if i == idx {
			continue
		}
		out.Routes = append(out.Routes, r)
	}
	return out
}

// persistCommonRoutes сохраняет конфиг в выбранный backend.
// Поле commonRoutesPath инициализируется в main() (Task 11).
func (oAdmin *OvpnAdmin) persistCommonRoutes(cfg CommonRoutesConfig) error {
	if *storageBackend == "kubernetes.secrets" {
		data, err := serializeCommonRoutes(cfg)
		if err != nil {
			return err
		}
		return app.secretUpdateCommonRoutes(data)
	}
	return saveCommonRoutesToFile(oAdmin.commonRoutesPath, cfg)
}
```

И добавить поле в `OvpnAdmin`:

```go
type OvpnAdmin struct {
    // ...
    commonRoutes     *commonRoutesStore
    commonRoutesPath string // путь для filesystem backend
}
```

- [ ] **Step 3: Прогнать тесты — GREEN**

Run: `go test -race -run TestCommonRoutesHandler -v ./...`
Expected: 5 PASS.

```bash
go test -race -run TestCommonRoutesItemHandler -v ./...
```
Expected: 2 PASS.

- [ ] **Step 4: Коммит**

```bash
git add common_routes.go common_routes_test.go main.go
git commit -m "feat(common-routes): add HTTP handlers (CRUD + refresh)"
```

---

## Task 11: Wiring в `main.go` — флаг, инициализация, регистрация роутов, горутина

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Добавить флаги (после строки `~main.go:87`)**

```go
commonRoutesEnabled = kingpin.Flag("common-routes", "enable common routes feature").Default("true").Envar("OVPN_COMMON_ROUTES").Bool()
```

- [ ] **Step 2: В `main()` после `ccdEnabled` блока (`~main.go:563-565`) добавить:**

```go
if *commonRoutesEnabled {
    ovpnAdmin.modules = append(ovpnAdmin.modules, "common-routes")

    // Инициализация store + загрузка
    ovpnAdmin.commonRoutes = &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}
    ovpnAdmin.commonRoutesPath = *ccdDir + "/_common_routes.json"

    var initial CommonRoutesConfig
    if *storageBackend == "kubernetes.secrets" {
        data, err := app.secretGetCommonRoutes()
        if err != nil {
            log.Warnf("loading common routes from secret: %v (starting with empty)", err)
        }
        if c, err := deserializeCommonRoutes(data); err != nil {
            log.Warnf("deserializing common routes: %v (starting with empty)", err)
        } else {
            initial = c
        }
    } else {
        if c, err := loadCommonRoutesFromFile(ovpnAdmin.commonRoutesPath); err != nil {
            log.Warnf("loading common routes from %s: %v (starting with empty)", ovpnAdmin.commonRoutesPath, err)
        } else {
            initial = c
        }
    }
    ovpnAdmin.commonRoutes.replace(initial)

    // Запуск DNS-резолвера в фоне
    go ovpnAdmin.runCommonRoutesScheduler()
}
```

- [ ] **Step 3: Добавить метод `runCommonRoutesScheduler` (рядом с другими методами `OvpnAdmin`)**

```go
func (oAdmin *OvpnAdmin) runCommonRoutesScheduler() {
    ctx := context.Background()

    runOnce := func() {
        current := oAdmin.commonRoutes.snapshot()
        // skip если нет ни одного домена
        hasDomain := false
        for _, r := range current.Routes {
            if r.Kind == "domain" {
                hasDomain = true
                break
            }
        }
        if !hasDomain {
            return
        }
        updated, changed, ok, failed := refreshAllDomains(ctx, current, time.Now())
        oAdmin.commonRoutes.replace(updated)
        if err := oAdmin.persistCommonRoutes(updated); err != nil {
            log.Errorf("scheduler persist: %v", err)
        }
        log.Infof("common-routes scheduler: resolved=%d failed=%d changed=%v", ok, failed, changed)
        if changed {
            oAdmin.rerenderAllCcds(expandCommonRoutes(updated))
        }
    }

    // первый запуск сразу
    runOnce()

    ticker := time.NewTicker(24 * time.Hour)
    defer ticker.Stop()
    for range ticker.C {
        runOnce()
    }
}
```

- [ ] **Step 4: Зарегистрировать HTTP-роуты в `main()` (рядом с `api/user/ccd*`, `~main.go:596-597`)**

```go
http.HandleFunc(*listenBaseUrl+"api/common-routes", ovpnAdmin.requireAuth(ovpnAdmin.commonRoutesHandler))
http.HandleFunc(*listenBaseUrl+"api/common-routes/refresh", ovpnAdmin.requireAuth(ovpnAdmin.commonRoutesRefreshHandler))
http.HandleFunc(*listenBaseUrl+"api/common-routes/", ovpnAdmin.requireAuth(ovpnAdmin.commonRoutesItemHandler))
```

- [ ] **Step 5: Build и smoke unit-suite**

Run: `go build ./... && go test -race ./...`
Expected: build OK, все тесты PASS.

- [ ] **Step 6: Коммит**

```bash
git add main.go
git commit -m "feat(common-routes): wire up storage, scheduler, and HTTP routes"
```

---

## Task 12: Frontend — функции API

**Files:**
- Modify: `frontend/src/api.js`

- [ ] **Step 1: Добавить в `frontend/src/api.js` в конец файла**

```js
export async function fetchCommonRoutes() {
  const { data } = await axios.get('api/common-routes')
  return data // { routes: [...], refreshIntervalHours: 24 }
}

export async function createCommonRoute(payload) {
  const { data } = await axios.post('api/common-routes', JSON.stringify(payload), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data.route
}

export async function updateCommonRoute(id, payload) {
  const { data } = await axios.put(`api/common-routes/${id}`, JSON.stringify(payload), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data.route
}

export async function deleteCommonRoute(id) {
  await axios.delete(`api/common-routes/${id}`)
}

export async function refreshCommonRoutesDns() {
  const { data } = await axios.post('api/common-routes/refresh')
  return data // { resolved, failed, changed }
}
```

- [ ] **Step 2: Прогнать `npm run build`**

```bash
cd frontend && npm run build && cd ..
```
Expected: build OK.

- [ ] **Step 3: Коммит**

```bash
git add frontend/src/api.js
git commit -m "feat(common-routes): add frontend API functions"
```

---

## Task 13: Компонент `TabBar`

**Files:**
- Create: `frontend/src/components/TabBar.vue`

- [ ] **Step 1: Создать `frontend/src/components/TabBar.vue`**

```vue
<!-- frontend/src/components/TabBar.vue -->
<script setup>
defineProps({
  modelValue: { type: String, required: true },
  tabs: { type: Array, required: true }, // [{ key: 'users', label: 'Пользователи' }, ...]
})
defineEmits(['update:modelValue'])
</script>

<template>
  <nav class="max-w-7xl mx-auto px-6 pt-4">
    <div class="flex gap-1 border-b border-border">
      <button
        v-for="tab in tabs"
        :key="tab.key"
        type="button"
        class="px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors"
        :class="modelValue === tab.key
          ? 'border-primary text-foreground'
          : 'border-transparent text-muted-foreground hover:text-foreground'"
        @click="$emit('update:modelValue', tab.key)"
      >
        {{ tab.label }}
      </button>
    </div>
  </nav>
</template>
```

- [ ] **Step 2: Build**

```bash
cd frontend && npm run build && cd ..
```
Expected: build OK.

- [ ] **Step 3: Коммит**

```bash
git add frontend/src/components/TabBar.vue
git commit -m "feat(common-routes): add TabBar component"
```

---

## Task 14: Компонент `CommonRoutesView` + модал

**Files:**
- Create: `frontend/src/components/CommonRoutesView.vue`
- Create: `frontend/src/components/modals/CommonRouteModal.vue`

- [ ] **Step 1: `CommonRoutesView.vue`**

Создать `frontend/src/components/CommonRoutesView.vue`:

```vue
<!-- frontend/src/components/CommonRoutesView.vue -->
<script setup>
import { ref, onMounted, computed } from 'vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'
import Badge from '@/components/ui/Badge.vue'
import CommonRouteModal from '@/components/modals/CommonRouteModal.vue'
import { useToast } from '@/composables/useToast'
import {
  fetchCommonRoutes, createCommonRoute, updateCommonRoute,
  deleteCommonRoute, refreshCommonRoutesDns,
} from '@/api.js'

const props = defineProps({
  serverRole: { type: String, default: 'master' },
})

const routes = ref([])
const refreshIntervalHours = ref(24)
const loading = ref(false)
const refreshing = ref(false)

const newKind = ref('ip')
const newRoute = ref({ address: '', mask: '', domain: '', description: '' })
const formError = ref('')

const editing = ref(null) // route obj or null

const { toast: _toast } = useToast()
function notify(title, variant = 'default') {
  _toast({ title, variant })
}

const isMaster = computed(() => props.serverRole === 'master')

const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/
const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/

function isValidIp(v) { return ipPattern.test(v) }
function isValidDomain(v) { return domainPattern.test(v) }

async function reload() {
  loading.value = true
  try {
    const data = await fetchCommonRoutes()
    routes.value = data.routes || []
    refreshIntervalHours.value = data.refreshIntervalHours || 24
  } finally {
    loading.value = false
  }
}

function resetForm() {
  newRoute.value = { address: '', mask: '', domain: '', description: '' }
  formError.value = ''
}

async function addRoute() {
  formError.value = ''
  const payload = { kind: newKind.value, description: newRoute.value.description || '' }
  if (newKind.value === 'ip') {
    if (!isValidIp(newRoute.value.address)) { formError.value = `Неверный формат IP: "${newRoute.value.address}"`; return }
    if (!isValidIp(newRoute.value.mask)) { formError.value = `Неверный формат маски: "${newRoute.value.mask}"`; return }
    payload.address = newRoute.value.address
    payload.mask = newRoute.value.mask
  } else {
    if (!isValidDomain(newRoute.value.domain)) { formError.value = `Неверный домен: "${newRoute.value.domain}"`; return }
    payload.domain = newRoute.value.domain
  }
  try {
    const created = await createCommonRoute(payload)
    routes.value.push(created)
    notify('Маршрут добавлен', 'success')
    if (created.last_resolve_err) {
      notify(`Резолв ${created.domain} не удался: ${created.last_resolve_err}`, 'destructive')
    }
    resetForm()
  } catch (e) {
    formError.value = e.response?.data || e.message
  }
}

async function removeRoute(id) {
  try {
    await deleteCommonRoute(id)
    routes.value = routes.value.filter(r => r.id !== id)
    notify('Маршрут удалён')
  } catch (e) {
    notify(`Ошибка удаления: ${e.message}`, 'destructive')
  }
}

async function refreshDns() {
  refreshing.value = true
  try {
    const r = await refreshCommonRoutesDns()
    notify(`DNS обновлён: резолвлено ${r.resolved}, ошибок ${r.failed}`, r.failed > 0 ? 'destructive' : 'success')
    await reload()
  } catch (e) {
    notify(`Ошибка обновления DNS: ${e.message}`, 'destructive')
  } finally {
    refreshing.value = false
  }
}

function openEdit(route) { editing.value = { ...route } }
function closeEdit() { editing.value = null }
async function submitEdit(payload) {
  try {
    const updated = await updateCommonRoute(payload.id, payload)
    const idx = routes.value.findIndex(r => r.id === updated.id)
    if (idx !== -1) routes.value[idx] = updated
    notify('Маршрут обновлён', 'success')
    closeEdit()
  } catch (e) {
    notify(`Ошибка: ${e.response?.data || e.message}`, 'destructive')
  }
}

function formatRelativeTime(iso) {
  if (!iso) return ''
  const diffMs = Date.now() - new Date(iso).getTime()
  const h = Math.floor(diffMs / 3600000)
  if (h < 1) return 'менее часа назад'
  if (h < 24) return `${h} ч назад`
  return `${Math.floor(h / 24)} дн назад`
}

onMounted(reload)
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <p class="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1">Общие маршруты</p>
        <p class="text-xs text-muted-foreground">Применяются ко всем активным пользователям. Изменения вступают в силу после переподключения клиента.</p>
      </div>
      <Button v-if="isMaster" :disabled="refreshing" @click="refreshDns">
        {{ refreshing ? 'Обновляем…' : 'Обновить DNS' }}
      </Button>
    </div>

    <!-- Форма добавления -->
    <div v-if="isMaster" class="rounded-md border border-border p-3 space-y-2 bg-card">
      <div class="flex items-center gap-2">
        <label class="text-sm">
          <input type="radio" value="ip" v-model="newKind" /> IP / маска
        </label>
        <label class="text-sm">
          <input type="radio" value="domain" v-model="newKind" /> Домен
        </label>
      </div>
      <div class="flex gap-2 flex-wrap">
        <template v-if="newKind === 'ip'">
          <Input v-model="newRoute.address" placeholder="10.0.0.0" class="w-40" />
          <Input v-model="newRoute.mask" placeholder="255.255.255.0" class="w-40" />
        </template>
        <Input v-else v-model="newRoute.domain" placeholder="youtube.com" class="w-60" />
        <Input v-model="newRoute.description" placeholder="Описание (опционально)" class="flex-1 min-w-[200px]" />
        <Button variant="success" @click="addRoute">+ Добавить</Button>
      </div>
      <div v-if="formError" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
        {{ formError }}
      </div>
    </div>

    <!-- Таблица -->
    <div class="rounded-md border border-border overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-muted/50">
          <tr>
            <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground w-20">Тип</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground">Значение</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground">Описание</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground w-48">DNS</th>
            <th v-if="isMaster" class="px-3 py-2 w-28" />
          </tr>
        </thead>
        <tbody>
          <tr v-if="loading">
            <td colspan="5" class="px-3 py-4 text-center text-muted-foreground">Загрузка…</td>
          </tr>
          <tr v-else-if="routes.length === 0">
            <td colspan="5" class="px-3 py-4 text-center text-muted-foreground">Нет общих маршрутов. Добавьте первый.</td>
          </tr>
          <tr v-for="r in routes" :key="r.id" class="border-t border-border align-top">
            <td class="px-3 py-2">
              <Badge :variant="r.kind === 'ip' ? 'secondary' : 'default'">{{ r.kind === 'ip' ? 'IP' : '🌐 Domain' }}</Badge>
            </td>
            <td class="px-3 py-2 font-mono text-xs">
              <template v-if="r.kind === 'ip'">{{ r.address }} / {{ r.mask }}</template>
              <template v-else>
                <div>{{ r.domain }}</div>
                <div v-if="r.resolved_ips && r.resolved_ips.length" class="text-muted-foreground mt-1">
                  → {{ r.resolved_ips.join(', ') }}
                </div>
              </template>
            </td>
            <td class="px-3 py-2">{{ r.description }}</td>
            <td class="px-3 py-2 text-xs">
              <template v-if="r.kind === 'domain'">
                <span v-if="r.last_resolve_err" class="text-yellow-500" :title="r.last_resolve_err">
                  ⚠ DNS error · {{ formatRelativeTime(r.last_resolve_at) }}
                </span>
                <span v-else class="text-green-600">OK · {{ formatRelativeTime(r.last_resolve_at) }}</span>
              </template>
              <span v-else class="text-muted-foreground">—</span>
            </td>
            <td v-if="isMaster" class="px-3 py-2 text-right">
              <Button size="sm" variant="ghost" @click="openEdit(r)">✏</Button>
              <Button size="sm" variant="destructive" @click="removeRoute(r.id)">✕</Button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <CommonRouteModal
      v-if="editing"
      :open="!!editing"
      :route="editing"
      @close="closeEdit"
      @submit="submitEdit"
    />
  </div>
</template>
```

- [ ] **Step 2: `CommonRouteModal.vue`**

Создать `frontend/src/components/modals/CommonRouteModal.vue`:

```vue
<!-- frontend/src/components/modals/CommonRouteModal.vue -->
<script setup>
import { ref, watch } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps({
  open: Boolean,
  route: { type: Object, required: true },
})
const emit = defineEmits(['close', 'submit'])

const local = ref({ ...props.route })
const error = ref('')

watch(() => props.route, (v) => { local.value = { ...v }; error.value = '' }, { deep: true })

const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/
const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/

function submit() {
  error.value = ''
  if (local.value.kind === 'ip') {
    if (!ipPattern.test(local.value.address)) { error.value = 'Неверный IP'; return }
    if (!ipPattern.test(local.value.mask)) { error.value = 'Неверная маска'; return }
  } else {
    if (!domainPattern.test(local.value.domain)) { error.value = 'Неверный домен'; return }
  }
  emit('submit', {
    id: local.value.id,
    kind: local.value.kind,
    address: local.value.kind === 'ip' ? local.value.address : '',
    mask: local.value.kind === 'ip' ? local.value.mask : '',
    domain: local.value.kind === 'domain' ? local.value.domain : '',
    description: local.value.description || '',
  })
}
</script>

<template>
  <Dialog :open="open" :title="`Редактирование маршрута`" @close="emit('close')">
    <div class="space-y-3">
      <div class="text-xs text-muted-foreground">Тип: {{ local.kind === 'ip' ? 'IP / маска' : 'Домен' }}</div>
      <div v-if="local.kind === 'ip'" class="flex gap-2">
        <Input v-model="local.address" placeholder="10.0.0.0" class="w-40" />
        <Input v-model="local.mask" placeholder="255.255.255.0" class="w-40" />
      </div>
      <Input v-else v-model="local.domain" placeholder="youtube.com" />
      <Input v-model="local.description" placeholder="Описание" />
      <div v-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">{{ error }}</div>
    </div>
    <template #footer>
      <Button variant="ghost" @click="emit('close')">Отмена</Button>
      <Button @click="submit">Сохранить</Button>
    </template>
  </Dialog>
</template>
```

- [ ] **Step 3: Build**

```bash
cd frontend && npm run build && cd ..
```
Expected: build OK, без ошибок Vue/Vite.

- [ ] **Step 4: Коммит**

```bash
git add frontend/src/components/CommonRoutesView.vue frontend/src/components/modals/CommonRouteModal.vue
git commit -m "feat(common-routes): add CommonRoutesView and modal components"
```

---

## Task 15: Интеграция в `App.vue`

**Files:**
- Modify: `frontend/src/App.vue`

- [ ] **Step 1: Добавить импорт и состояние**

В `<script setup>` блок:

```js
import TabBar from '@/components/TabBar.vue'
import CommonRoutesView from '@/components/CommonRoutesView.vue'

const activeTab = ref('users')

const visibleTabs = computed(() => {
  const tabs = [{ key: 'users', label: 'Пользователи' }]
  if (modulesEnabled.value.includes('common-routes')) {
    tabs.push({ key: 'common-routes', label: 'Общие маршруты' })
  }
  return tabs
})
```

Не забыть импорт `computed`:
```js
import { ref, onMounted, computed } from 'vue'
```

- [ ] **Step 2: Обновить `<template>`**

Между `<AppHeader>` и существующим `<main>` вставить:

```vue
<TabBar v-model="activeTab" :tabs="visibleTabs" />

<main class="max-w-7xl mx-auto px-6 py-6 space-y-6">
  <template v-if="activeTab === 'users'">
    <div>
      <p class="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Обзор</p>
      <StatCards :users="users" />
    </div>
    <div>
      <p class="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Пользователи</p>
      <UsersTable ... <!-- существующее, без изменений --> />
    </div>
  </template>
  <template v-else-if="activeTab === 'common-routes'">
    <CommonRoutesView :server-role="serverRole" />
  </template>
</main>
```

(аккуратно: сохранить существующие props/events на `UsersTable`, не удалять модалы — они остаются за пределами `<main>`).

- [ ] **Step 3: Build**

```bash
cd frontend && npm run build && cd ..
```
Expected: build OK.

- [ ] **Step 4: Коммит**

```bash
git add frontend/src/App.vue
git commit -m "feat(common-routes): integrate TabBar and CommonRoutesView into App"
```

---

## Task 16: Smoke-тест через docker-compose

**Files:**
- (опционально) Modify: `docker-compose.test.yml` — если нужно увидеть `--common-routes`, флаг по умолчанию `true`, передавать не обязательно.

- [ ] **Step 1: Полная пересборка**

```bash
docker compose -f docker-compose.test.yml down -v
docker compose -f docker-compose.test.yml build --no-cache
docker compose -f docker-compose.test.yml up -d
```

(Помнить правило CLAUDE.md: всегда `build --no-cache`.)

- [ ] **Step 2: Открыть UI**

В браузере: `http://localhost:8080` (или порт из compose). Залогиниться (см. логи `docker compose -f docker-compose.test.yml logs ovpn-admin | grep "Временный пароль"`).

Проверить:
- Появилась вкладка «Общие маршруты»
- Список пуст, форма работает

- [ ] **Step 3: Добавить IP-маршрут**

В UI: Kind=IP, Address=`192.0.2.0`, Mask=`255.255.255.0`, Description=`smoke-ip`.
Затем проверить:

```bash
docker compose -f docker-compose.test.yml exec ovpn-admin cat /etc/openvpn/ccd/<имя_тестового_юзера>
```

Ожидаемо: появилась строка `push "route 192.0.2.0 255.255.255.0" # __common__:static smoke-ip`.

- [ ] **Step 4: Добавить домен**

В UI: Kind=Domain, Domain=`example.com`. Кликнуть «Обновить DNS». Проверить:
- В UI отображаются резолвленные IP
- В CCD-файле появились `push "route <IP> 255.255.255.255" # __common__:example.com`

- [ ] **Step 5: Подключить тестового клиента (если в compose есть openvpn-client) и убедиться что route виден**

```bash
docker compose -f docker-compose.test.yml exec openvpn-client ip route
```

Ожидаемо: 192.0.2.0/24 присутствует.

- [ ] **Step 6: Проверить юзерский CCD-модал не «съел» общие маршруты**

В UI: открыть существующего юзера → Маршруты. В списке должны быть только его персональные, без `__common__`.

- [ ] **Step 7: Удалить запись через UI и убедиться что CCD очищены**

```bash
docker compose -f docker-compose.test.yml exec ovpn-admin cat /etc/openvpn/ccd/<имя_юзера>
```
Ожидаемо: строки с `__common__:` исчезли.

- [ ] **Step 8: Перезапустить контейнер — кэшированные IP должны остаться**

```bash
docker compose -f docker-compose.test.yml restart ovpn-admin
```

Через 5 секунд: в UI домен по-прежнему виден с теми же IP, без принудительного refresh.

- [ ] **Step 9: Коммит (если потребовались изменения compose-файла)**

Если ничего не менялось — коммита нет.

---

## Self-Review (пройдено при написании плана)

**Spec coverage:**

| Spec секция | Покрытие в плане |
|-------------|------------------|
| Модель данных `CommonRouteEntry` / `CommonRoutesConfig` | Task 1 |
| Хранилище filesystem (atomic write) | Task 2 |
| Хранилище kubernetes.secrets | Task 3 |
| Сериализация / десериализация | Task 3 |
| `commonRoutesStore` с RWMutex + snapshot copy | Task 4 |
| `expandCommonRoutes` | Task 5 |
| Шаблон ccd.tpl + маркер `__common__` | Task 6 |
| `parseCcd` фильтр | Task 6 |
| `modifyCcd` принимает snapshot | Task 7 |
| `rerenderAllCcds` + ccdMu | Task 8 |
| DNS-резолвер `resolveOneDomain` + `refreshAllDomains` | Task 9 |
| API `/api/common-routes` (GET/POST/PUT/DELETE/refresh) | Task 10 |
| Валидация на бэке + дубли (409) | Task 10 (через `validateCommonRoute` + `isDuplicateCommonRoute`) |
| Slave 423 | Task 10 |
| Sync-резолв при POST/PUT для kind=domain | Task 10 |
| Флаг `--common-routes`, добавление в `modules` | Task 11 |
| Загрузка конфига на старте | Task 11 |
| Запуск фонового тикера | Task 11 |
| Регистрация HTTP-роутов | Task 11 |
| Frontend `api.js` | Task 12 |
| TabBar | Task 13 |
| CommonRoutesView + Modal | Task 14 |
| Интеграция в App.vue | Task 15 |
| Smoke-тест | Task 16 |

**Placeholder scan:** ОК — все шаги содержат конкретный код/команды. В Task 8 указано «или удалить unit-тест если seam искусственный» — это явный выбор, не заглушка.

**Type consistency:** проверено — `CommonRouteEntry` поля совпадают везде; `ccdCommonRoute` использовано одинаково; сигнатура `modifyCcd(ccd Ccd, commonExpanded []ccdCommonRoute)` синхронна в Tasks 7, 8, 10. Имя поля `OpenvpnClient.Identity` подтверждено по `main.go:219`.

**Известные неточности, требующие внимания при имплементации:**
- В Task 3 предполагается наличие `openVPNPKI.secretCreate`. Перед написанием — проверить актуальное API в `kubernetes.go`. Если такого метода нет, использовать `clientset.CoreV1().Secrets(ns).Create(ctx, &secret, ...)` по тому же паттерну, что для других секретов проекта.
- В Task 7 unit-тест `TestModifyCcd_RendersCommonRoutes` использует packr-box. Если в test-runner'е packr не находит файлы (`./templates`) — переписать тест на in-memory шаблон через `template.New().Parse()`.
- В Task 11 `runCommonRoutesScheduler` использует `context.Background()` — graceful shutdown через сигнал в этом проекте сейчас не реализован для других горутин (`updateState`, `syncWithMaster` тоже без отмены). Следуем существующему паттерну.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-20-common-routes.md`. Two execution options:

**1. Subagent-Driven (recommended)** — я диспатчу свежего сабагента на каждую задачу, ревью между задачами, быстрая итерация. Каждый сабагент стартует с чистым контекстом и фокусируется на одной задаче.

**2. Inline Execution** — выполнение задач в этой же сессии через executing-plans, батчами с чекпоинтами.

Which approach?

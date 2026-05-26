# Pragmatic Refactor: Store Interface + File Extraction

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the God Object pattern, replace 18 scattered `if *storageBackend` blocks with a Store interface, extract files from main.go, fix tests for t.Parallel(), unify HTTP API to JSON.

**Architecture:** Pragmatic — `internal/storage` for the Store interface (single sub-package), everything else stays `package main` with file extraction. CcdReader interface for firewall isolation. No Module lifecycle interface.

**Tech Stack:** Go 1.25, packr2, kingpin, Kubernetes client-go, prometheus

---

### Task 1: Create Store interface

**Files:**
- Create: `internal/storage/store.go`

- [ ] **Step 1: Define the Store interface**

```go
package storage

type Store interface {
	// PKI / certificate operations
	BuildClient(commonName string) error
	RevokeClient(commonName string) error
	UnrevokeClient(commonName string) error
	RotateClient(commonName, newPassword string) error
	DeleteClient(commonName string) error
	GetClientCert(commonName string) (cert, key string)
	UpdateIndexTxtOnDisk() error

	// CCD (Client Config Directory)
	GetCcd(commonName string) string
	SaveCcd(commonName string, data []byte) error
	// ListCcdSecrets returns CCD content for all clients — used by checkStaticAddressIsFree
	ListCcdSecrets() ([]CcdSecret, error)

	// Config blobs (common-routes, server-config)
	LoadCommonRoutes() ([]byte, error)
	SaveCommonRoutes(data []byte) error
	LoadServerConfig() ([]byte, error)
	SaveServerConfig(data []byte) error

	// Bootstrap — called once at startup for k8s backend; no-op for filesystem
	Bootstrap() error
}

type CcdSecret struct {
	CommonName string
	CcdContent string
}
```

- [ ] **Step 2: Run `go build ./internal/storage/...`**

Expected: compiles clean.

- [ ] **Step 3: Commit**
```bash
git add internal/storage/store.go
git commit -m "refactor: define Store interface in internal/storage"
```

---

### Task 2: Implement filesystemStore

**Files:**
- Create: `internal/storage/filesystem.go`
- Read: `main.go` (lines with `else` branches after `if *storageBackend == "kubernetes.secrets"`)
- Read: `helpers.go` (fRead, fWrite, runBash)

The filesystem store wraps existing file I/O and easyrsa shell calls. Each method maps 1:1 to an existing `else` branch in the current codebase. Constructor receives paths as config, not as globals.

- [ ] **Step 1: Create FilesystemParams and filesystemStore**

```go
package storage

type FilesystemParams struct {
	EasyrsaDirPath string
	EasyrsaBinPath string
	CcdDir         string
	IndexTxtPath   string
}

type filesystemStore struct {
	p FilesystemParams
}

func NewFilesystem(p FilesystemParams) Store {
	return &filesystemStore{p: p}
}
```

- [ ] **Step 2: Implement each method**

Each method body is extracted from the corresponding `else` branch of the if/else in main.go. Key mappings:
- `BuildClient` → `runBash(fmt.Sprintf("cd %s && easyrsa build-client-full %s nopass", p.EasyrsaDirPath, cn))`
- `RevokeClient` → `runBash(fmt.Sprintf("cd %s && echo yes | easyrsa revoke %s && easyrsa gen-crl", p.EasyrsaDirPath, cn))`
- `UnrevokeClient` → rewrite index.txt line, then gen-crl
- `RotateClient` → revoke + build-client-full
- `DeleteClient` → revoke + rm files
- `GetClientCert` → `fRead(p.EasyrsaDirPath + "/pki/issued/" + cn + ".crt")` etc.
- `UpdateIndexTxtOnDisk` → no-op for filesystem (index.txt is already on disk)
- `GetCcd` → `fRead(p.CcdDir + "/" + cn)`
- `SaveCcd` → `fWrite(p.CcdDir + "/" + cn, data)`
- `ListCcdSecrets` → list CCD dir, read each file
- `Load/SaveCommonRoutes` → `loadCommonRoutesFromFile` / `saveCommonRoutesToFile` equivalents
- `Load/SaveServerConfig` → `loadServerConfigFromFile` / `saveServerConfigToFile` equivalents
- `Bootstrap` → no-op

IMPORTANT: The filesystem store needs access to helper functions (`fRead`, `fWrite`, `fExist`, `runBash`). Since these are in `package main` and the store is in `internal/storage`, we need to either:
a) Duplicate the simple helpers (fRead/fWrite are ~5 lines each) in the storage package
b) Move helpers to a shared internal/fsutil package
c) Pass helper functions as constructor parameters

Option (a) is simplest for now — duplicate the 4 small helpers.

- [ ] **Step 3: Verify it compiles**
```bash
go build ./internal/storage/...
```

- [ ] **Step 4: Commit**
```bash
git add internal/storage/filesystem.go
git commit -m "refactor: implement filesystemStore for Store interface"
```

---

### Task 3: Implement kubernetesStore

**Files:**
- Create: `internal/storage/kubernetes.go`
- Read: top-level `kubernetes.go` (all methods)
- Read: `certificates.go` (used by k8s PKI)

The kubernetes store wraps the existing `OpenVPNPKI` struct. Initially it is a thin wrapper — the actual k8s logic stays in `OpenVPNPKI` methods that are moved into this package.

- [ ] **Step 1: Move OpenVPNPKI to internal/storage**

Copy `kubernetes.go` content to `internal/storage/kubernetes.go`. Change `package main` → `package storage`. The `OpenVPNPKI` struct and all its methods land here. Also move `certificates.go` (pure crypto) as it is only used by k8s backend.

- [ ] **Step 2: Implement Store interface methods on kubernetesStore**

Create a thin `kubernetesStore` wrapper that delegates to `OpenVPNPKI` methods:

```go
type kubernetesStore struct {
	pki *OpenVPNPKI
}

func NewKubernetes() (Store, error) {
	pki := &OpenVPNPKI{}
	if err := pki.run(); err != nil {
		return nil, err
	}
	return &kubernetesStore{pki: pki}, nil
}

func (s *kubernetesStore) BuildClient(cn string) error { return s.pki.easyrsaBuildClient(cn) }
func (s *kubernetesStore) GetCcd(cn string) string      { return s.pki.secretGetCcd(cn) }
// ... etc
```

- [ ] **Step 3: Handle imports**

The k8s store imports k8s.io/client-go, crypto, etc. Make sure go.mod already has these (it does).

- [ ] **Step 4: Compile and test**
```bash
go build ./internal/storage/...
```

- [ ] **Step 5: Commit**
```bash
git add internal/storage/kubernetes.go internal/storage/certificates.go
git commit -m "refactor: implement kubernetesStore for Store interface"
```

---

### Task 4: Inject Store into OvpnAdmin, eliminate global `app`

**Files:**
- Modify: `main.go` — add `store storage.Store` to OvpnAdmin, create store in main(), replace all `app.*` calls
- Modify: `common_routes.go` — replace `persistCommonRoutes` backend dispatch
- Modify: `server_config.go` — replace `serverManager.persist` backend dispatch
- Delete: top-level `kubernetes.go` (content moved to internal/storage)

This is the biggest task — touching ~18 call sites.

- [ ] **Step 1: Add `store` field to OvpnAdmin**

```go
import "ovpn-admin/internal/storage"

type OvpnAdmin struct {
	// ... existing fields ...
	store storage.Store
}
```

- [ ] **Step 2: Create store in main() instead of `app.run()`**

Replace:
```go
if *storageBackend == "kubernetes.secrets" {
    err := app.run()
    ...
}
```

With:
```go
var store storage.Store
if *storageBackend == "kubernetes.secrets" {
    var err error
    store, err = storage.NewKubernetes()
    if err != nil { log.Fatal(err) }
} else {
    store = storage.NewFilesystem(storage.FilesystemParams{
        EasyrsaDirPath: *easyrsaDirPath,
        EasyrsaBinPath: *easyrsaBinPath,
        CcdDir:         *ccdDir,
        IndexTxtPath:   *indexTxtPath,
    })
}
ovpnAdmin.store = store
```

- [ ] **Step 3: Replace all 18 call sites in main.go**

Replace `app.easyrsaBuildClient(cn)` with `oAdmin.store.BuildClient(cn)`.
Replace `app.secretGetCcd(cn)` with `oAdmin.store.GetCcd(cn)`.
...etc for all 18 sites.

- [ ] **Step 4: Replace `persistCommonRoutes` in common_routes.go**

Replace the if/else block (lines ~502-509) with `oAdmin.store.SaveCommonRoutes(data)`.

- [ ] **Step 5: Replace `serverManager.persist` in server_config.go**

Add `store storage.Store` field to `serverManager`. Replace the if/else with `m.store.SaveServerConfig(data)`. Similarly for loading.

- [ ] **Step 6: Delete global `var app OpenVPNPKI` and top-level kubernetes.go**

- [ ] **Step 7: Build and test**
```bash
go build ./...
go test -count=1 -race ./...
```

- [ ] **Step 8: Commit**
```bash
git add -A
git commit -m "refactor: inject Store into OvpnAdmin, eliminate global app"
```

---

### Task 5: Define CcdReader interface for firewall

**Files:**
- Modify: `firewall.go` — define CcdReader interface, replace `oAdmin *OvpnAdmin` backpointer
- Modify: `main.go` — update newFirewallController call

- [ ] **Step 1: Define CcdReader in firewall.go**

```go
type CcdReader interface {
	getCcd(username string) Ccd
	commonRoutesSnapshot() CommonRoutesConfig
}
```

- [ ] **Step 2: Add commonRoutesSnapshot method to OvpnAdmin**

```go
func (o *OvpnAdmin) commonRoutesSnapshot() CommonRoutesConfig {
	return o.commonRoutes.snapshot()
}
```

- [ ] **Step 3: Replace oAdmin field in firewallController**

Change `oAdmin *OvpnAdmin` → `ccdReader CcdReader`. Update `computeAllowedCIDRs` to use `fc.ccdReader.getCcd()` and `fc.ccdReader.commonRoutesSnapshot()`.

- [ ] **Step 4: Update constructor and call site**

- [ ] **Step 5: Build and test**

- [ ] **Step 6: Commit**

---

### Task 6: Extract files from main.go

**Files:**
- Create: `users.go` — user CRUD methods + handlers
- Create: `ccd.go` — CCD logic
- Create: `mgmt.go` — management interface
- Create: `sync.go` — master-slave sync
- Create: `handlers.go` — thin HTTP handler wrappers
- Create: `metrics.go` — prometheus metric declarations
- Create: `app.go` — OvpnAdmin struct, setState, updateState
- Modify: `main.go` — shrink to ~100 lines composition root

Each extraction is purely mechanical: cut functions from main.go, paste into new file, no logic changes.

- [ ] **Step 1: Extract users.go** — userCreate, userRevoke, userUnrevoke, userRotate, userDelete, usersList, userChangePassword, getUserStatistic, validateUsername, validatePassword, checkUserExist, checkStaticAddressIsFree, userListHandler, userStatisticHandler, userCreateHandler, userDeleteHandler, userRevokeHandler, userUnrevokeHandler, userRotateHandler, userChangePasswordHandler, userShowConfigHandler, userDisconnectHandler
- [ ] **Step 2: Extract ccd.go** — parseCcd, modifyCcd, getCcd, rerenderAllCcds, refreshAllUserDomains, validateCcd, getCcdTemplate, userShowCcdHandler, userApplyCcdHandler
- [ ] **Step 3: Extract mgmt.go** — mgmtRead, mgmtConnectedUsersParser, mgmtKillUserConnection, mgmtGetActiveClients, mgmtSetTimeFormat, isUserConnected
- [ ] **Step 4: Extract sync.go** — syncDataFromMaster, syncWithMaster, downloadCerts, downloadCcd, archiveCerts, archiveCcd, unArchiveCerts, unArchiveCcd, downloadCertsHandler, downloadCcdHandler, lastSyncTimeHandler, lastSuccessfulSyncTimeHandler
- [ ] **Step 5: Extract metrics.go** — all prometheus metric var declarations + registerMetrics
- [ ] **Step 6: Extract app.go** — OvpnAdmin struct, type definitions, setState, updateState, renderClientConfig, getClientConfigTemplate, indexTxtParser, renderIndexTxt, CacheControlWrapper, serverSettingsHandler
- [ ] **Step 7: Verify main.go is ~100 lines** — only main() composition root + route registration
- [ ] **Step 8: Build and test**
- [ ] **Step 9: Commit**

---

### Task 7: Fix tests for t.Parallel()

**Files:**
- Modify: `common_routes_test.go` — inject store instead of mutating globals
- Modify: `firewall_test.go` — use CcdReader interface + fakeCcdReader
- Modify: `server_config_test.go` — inject store
- Modify: `ccd_domain_test.go` — inject store, replace withTempCcdEnv

- [ ] **Step 1: Update test helpers to accept Store**

Replace `withTempCcdEnv` (global mutation) with `newTestStore(t)` that returns a `storage.NewFilesystem(...)`.

Replace `newTestAdmin` / `newTestAdminCcd` to accept `storage.Store` as parameter.

- [ ] **Step 2: Add t.Parallel() to all tests**

- [ ] **Step 3: Replace global `domainResolver` var with field on OvpnAdmin**

Move `var domainResolver = resolveOneDomain` to a field on OvpnAdmin. Tests inject mock via constructor.

- [ ] **Step 4: Run tests with -race**
```bash
go test -count=1 -race -parallel=4 ./...
```

- [ ] **Step 5: Commit**

---

### Task 8: Unify HTTP API to JSON

**Files:**
- Modify: `users.go` (handlers) — switch from r.FormValue to JSON decode
- Modify: `frontend/src/api.js` — switch from formData to JSON

- [ ] **Step 1: Create JSON request types**

```go
type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
// ... similar for rotate, changePassword, revoke, unrevoke, delete, config/show, disconnect, statistic
```

- [ ] **Step 2: Update handlers to decode JSON**

Replace `r.ParseForm(); username := r.FormValue("username")` with `json.NewDecoder(r.Body).Decode(&req)`.

- [ ] **Step 3: Update frontend api.js**

Replace `formData({username, password})` with `JSON.stringify({username, password})` and set `Content-Type: application/json`.

- [ ] **Step 4: Build frontend**
```bash
cd frontend && npm run build && cd ..
```

- [ ] **Step 5: Build and test**
```bash
go build ./...
go test -count=1 -race ./...
```

- [ ] **Step 6: Commit**

---

### Task 9: Final verification

- [ ] **Step 1: Full build**
```bash
go build ./...
go vet ./...
```

- [ ] **Step 2: Full test suite with race detector**
```bash
go test -count=1 -race ./...
```

- [ ] **Step 3: Docker compose build**
```bash
docker compose build --no-cache
```

- [ ] **Step 4: Verify main.go line count**
```bash
wc -l main.go  # should be ~100 lines
```

- [ ] **Step 5: Verify no remaining global `app` or `storageBackend` dispatch**
```bash
grep -rn "var app\|storageBackend.*kubernetes" *.go
# should return nothing outside internal/storage/
```

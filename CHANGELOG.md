# Changelog

All notable changes to ovpn-admin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- **BREAKING: master/slave replication feature** — `sync.go`, the
  `requireMaster` middleware, the `OvpnAdmin.role` / `lastSyncTime` /
  `masterSyncToken` fields, all `--role` / `--master.*` CLI flags
  (`OVPN_ROLE`, `OVPN_MASTER_HOST`, `OVPN_MASTER_USER`,
  `OVPN_MASTER_PASSWORD`, `OVPN_MASTER_SYNC_FREQUENCY`, `OVPN_MASTER_TOKEN`),
  the `/api/data/certs/download`, `/api/data/ccd/download`,
  `/api/sync/last/try`, `/api/sync/last/successful` endpoints,
  `docker-compose-slave.yaml`, `start-with-slave.sh`. The feature was dead
  code carrying real risk: the download handlers exposed the entire PKI via
  HTTP behind only `X-Sync-Token`, and the default token
  (`VerySecureToken`) was publicly known. Single-master deployments are
  unaffected. Operators who relied on this feature should migrate to
  external PKI replication (git-versioned easyrsa, rsync, K8s Secret sync).
- Frontend: `serverRole` ref / props, slave-readonly UI gating, header
  "slave · sync …" indicator, `fetchLastSync` API call.

## [2.0.4] — 2026-06-02

### Fixed

- Client `.ovpn` config template now picks `tls-crypt` vs `tls-auth`
  based on the server-side `TLSAuthMode`. Previously the template
  hardcoded `<tls-auth>` + `key-direction 1`, which broke clients when
  the server was switched to `tls-crypt` (handshake mismatch).
- Removed the legacy `cipher AES-128-CBC` line from the client
  template. Modern OpenVPN ≥2.5 clients negotiate the cipher via NCP
  using the server's `data-ciphers` list; the hardcoded value was
  misleading (the actual cipher is the first AEAD in `data-ciphers`).

## [2.0.12] — 2026-06-03

### Fixed

- **`userDelete` now actually revokes the certificate.** The previous
  flow only renamed the user's row in `index.txt` to `REVOKED-<CN>-<uuid>`
  and removed the on-disk `.crt`/`.key`/`.req` files. But the entry
  kept status `V`, so `easyrsa gen-crl` produced a CRL that did NOT
  include the cert's serial. A client holding their previously
  downloaded `.ovpn` could reconnect after deletion and the server
  happily accepted them — defeating the entire point of the operation.
  
  `DeleteClient` now runs `easyrsa --batch revoke <CN>` BEFORE the
  rename/file cleanup, so the serial lands in the CRL and OpenVPN
  rejects any reconnect attempt with `TLS Error: certificate is in
  the CRL`. Combined with the v2.0.11 mgmt-kill, deletion now ends
  both the active session AND the ability to come back.

## [2.0.11] — 2026-06-03

### Fixed

- `userDelete` now kicks the user's active VPN session via mgmt
  BEFORE wiping cert/files. Previously the deleted user kept
  tunnelling traffic until they happened to reconnect — CRL only
  takes effect at the next TLS handshake, not on already-established
  sessions. `userRevoke` already did this; bringing delete in line
  fixes "I deleted the user but they're still connected".

## [2.0.10] — 2026-06-03

### Added

- **Bulk route import** for both Common Routes and per-user CCD.
  Paste text or upload a file with one entry per line. Each line can
  be a domain (`example.com`), a CIDR (`10.0.0.0/24`), an IP +
  dotted-decimal mask (`1.2.3.4 255.255.255.0`), or a bare IP
  (treated as `/32`). Lines starting with `#` and empty lines are
  ignored.
  - Validates every line; rejects with a precise reason and 1-based
    line number, so a noisy import file can be fixed and retried.
  - Deduplicates against existing routes (per-user OR common, depending
    on the endpoint) AND within the same payload — same domain or same
    Address/Mask shows up at most once.
  - Domains are resolved synchronously at import time so the first
    PUSH_REPLY after the kick already carries the IPs.
  - Reports `{ added, skipped, errors }` so the UI can show what
    actually landed and what was dropped.
  - New endpoints: `POST /api/common-routes/import`,
    `POST /api/user/ccd/import`. Same `auth(mfa(...))` gate as every
    other mutation.
- UI: collapsible **«Импорт из файла»** block in `CcdModal` and
  **«Импорт»** toggle in `CommonRoutesView`, with a textarea, a
  file picker and an inline report of the import result.

## [2.0.9] — 2026-06-03

### Added

- **Auto-kick after route change.** When admin saves a per-user CCD
  (Save Routes), changes Common Routes, or the background scheduler
  re-resolves a domain to new IPs, ovpn-admin now sends `kill <CN>`
  to OpenVPN's mgmt for each affected client. The client auto-
  reconnects within seconds and receives the updated push directives
  in PUSH_REPLY. No more "I changed the route but my VPN session
  still routes the old IPs" — push directives only apply at connect
  time, so kicking is the only way to make in-flight sessions pick
  up the change.
- **Configurable DNS resolver** for domain routes via
  `--domain-resolver` / `OVPN_DOMAIN_RESOLVER` (e.g. `8.8.8.8` or
  `1.1.1.1:53`). Defaults to the container's `/etc/resolv.conf`,
  which inside Docker is the embedded 127.0.0.11 forwarder and can
  be flaky. Pinning to a public resolver gives reproducible IP sets
  across nodes.
- **Configurable refresh interval** (`domain_refresh_interval_hours`
  in server-config, default 24). The background scheduler reads it
  live, so a UI change takes effect at the next tick. Set to 0 (or
  negative) to disable the scheduler — manual refresh stays
  available via the existing buttons.
- **"Обновить DNS" button for per-user routes** in `CcdModal`. Picks
  up the same logic as Common Routes refresh — re-resolve domains,
  rewrite CCD if any IP changed, kick the user.
- New `POST /api/user/ccd/refresh` endpoint behind the same
  `auth(mfa(...))` gate as `apply`.

### Changed

- `DomainRefreshIntervalHours` classifies as a **soft** change —
  no openvpn restart, the scheduler picks the new value at the next
  loop iteration. Other server-config edits keep their previous
  classification.

## [2.0.8] — 2026-06-03

### Fixed

- **Hard config reload (DCO/port/cipher/tls-mode/etc) no longer breaks
  the admin UI in `docker-compose` deployments.** Saving such a change
  used to send SIGTERM into openvpn's mgmt → openvpn process exited →
  docker recreated the openvpn container with a NEW network namespace,
  but ovpn-admin was pinned via `network_mode: service:openvpn` to the
  OLD netns and became orphaned (502 on every UI request until manual
  `docker compose down && up`).
  
  `apply()` now self-exits ~1.2s after sending SIGTERM. With
  `restart: unless-stopped` + `depends_on: openvpn`, both containers
  come back in the right order and ovpn-admin rebinds to the new
  openvpn netns automatically. The HTTP caller still receives the
  success response before the exit.
  
  K8s deployments are unaffected by the original race (the pod's
  pause container holds the netns), and the self-exit is harmless
  there — kubelet just restarts the container in the same pod.

- Removed the now-unreachable `rollback()` path. Since we self-exit
  the rollback can't run from in-process. Bad-config protection still
  lives in `validateServerConfig` at save time.

## [2.0.7] — 2026-06-03

### Fixed

- **CCD files are now written with mode `0644` instead of `0600`.**
  OpenVPN drops privileges to `nobody` per `user nobody` in server.conf
  and reads `/etc/openvpn/ccd/<CN>` at each client connect. The previous
  `0600` made the file unreadable after the drop, silently disabling
  every per-user push directive (routes, DNS, gateway). This is the
  reason CCD-based features (per-user split-tunnel, hot revocation
  hints, common-routes targeting) appeared to do nothing. CCD content
  is push directives, not secrets, so 0644 is appropriate.
- Server template no longer emits the invented `data-channel-offload`
  directive. OpenVPN 2.6.x with `--enable-dco` engages DCO automatically
  when the kernel module is loaded; the only knob is `--disable-dco`
  to opt out. The template now emits `disable-dco` only when DCOEnabled
  is false, and nothing when DCOEnabled is true (DCO auto-attaches).
- `docker-compose.yaml` openvpn service gets `DAC_OVERRIDE`, `SETUID`,
  `SETGID`, `SETPCAP` capabilities. Without `SETPCAP` OpenVPN cannot
  retain `NET_ADMIN` after dropping to `nobody`, so DCO falls back to
  user-space crypto with a noisy "Cannot retain CAP_NET_ADMIN" log line.
- `docker-compose.yaml` ovpn-admin service gets `depends_on: openvpn`.
  Without it Compose may recreate openvpn first, leaving ovpn-admin
  bound to a dead network namespace (502 on every UI request until a
  manual `docker compose down && up`).
- `filesystemStore.SaveCcd` now runs `validateUsername` at point of use
  as defence-in-depth (matches BuildClient/GetClientCert).

## [2.0.6] — 2026-06-03

### Changed

- **openvpn image base switched from `alpine:3.23` to `debian:trixie-slim`.**
  Debian's `openvpn` package is built with `--enable-dco`, so the
  `data-channel-offload` directive now works once the kernel has the
  mainline `ovpn` module (kernel 6.16+) or an OOT `ovpn_dco` variant
  loaded. Operators with a DCO-capable host can flip DCO on in the UI
  without rebuilding the binary. Image grows ~50MB but stays under 100MB.
- Push-related server-config fields (`RedirectGateway`, `DNSServers`,
  `PushExtra`, `CustomDirectives`) now classify as **hard** reload
  changes instead of soft. A SIGHUP-only soft reload doesn't re-push
  to already-connected clients — they kept stale DNS/gateway until
  reconnect. Saving any push change now forces a clean restart so
  every session picks up the new config immediately. `Verb`,
  `KeepaliveInterval/Timeout`, `MaxClients` remain soft (no client
  impact, in-place SIGHUP).
- `setup/configure.sh` group-creation step now tries `groupadd`
  first (Debian) and falls back to BusyBox `addgroup` (Alpine), so
  the same script works in either base image.

## [2.0.5] — 2026-06-02

### Added

- `management-client-auth` is now actually handled. ovpn-admin keeps a
  long-lived connection to the OpenVPN management interface (per
  `--mgmt` alias) and answers `>CLIENT:CONNECT` / `>CLIENT:REAUTH`
  events with `client-auth-nt` (allow) or `client-deny` (reject) based
  on the cert's CN being present and `Valid` in easyrsa's index. This
  closes the bug where the server template emitted
  `management-client-auth` but no code consumed the events — clients
  would hang for 30s and get a misleading "no username/password" error.
- New `MgmtClientAuth` field in server-config (default true). When
  disabled the directive is omitted from the rendered server.conf and
  the auth loop is not started — OpenVPN then authorizes purely on
  cert validity + CRL.

### Security

- `/api/user/config/show` (downloads embedded client private key) now
  requires the MFA gate, matching every other sensitive endpoint. A
  stolen session cookie no longer hands out all client keys without
  the second factor.
- `userCreateHandler` now validates the username at the handler edge
  before any disk lookup, and `userCreate` itself validates BEFORE
  `checkUserExist`. Path-traversal CNs no longer reach store calls.
- `filesystemStore.BuildClient` and `GetClientCert` re-validate the
  CN at point of use as defence-in-depth, so a future caller that
  forgets to validate cannot trigger path traversal on the PKI dir.
- `consumeMfaJti` now rejects tokens with empty `jti`. `signMfaToken`
  has always emitted one, so an empty jti is now treated as a
  malformed/legacy token. Closes the residual replay window for
  pre-jti tokens after a signing-key carryover.
- `securityMiddleware` Cache-Control: no-store now honours the
  configured `--listen.base-url`, not just `/api/`. Non-root
  deployments no longer leak session-carrying responses to caches.
- `mgmtClientAuthLoop` validates that `cid` and `kid` from the
  management socket are decimal integers before interpolating them
  into the response, and tracks pending CONNECT blocks as an ordered
  slice (most-recent-wins) instead of a map sorted lexicographically
  — the prior tie-break compared decimal strings (`"9" > "10"`) and
  could mis-attribute ENV lines under contention.

## [2.0.4] — 2026-06-02

### Fixed

- Default `DCOEnabled` flipped from `true` to `false`. The previous
  default caused the rendered `server.conf` to include
  `data-channel-offload` whenever a DCO kernel module was detected,
  but the official Alpine `openvpn` package is built **without** DCO
  support and rejected the directive — putting the openvpn container
  into a crash-loop. DCO is now opt-in via the server-config UI for
  operators running a DCO-enabled binary.
- Server-config unit tests realigned with the new default
  (`TestDefaultServerConfig_PreservesBackwardCompat`,
  `TestRenderServerConfig_DCOEnabled`, `TestCategorizeChanges_HardFields`)
  and a new `TestRenderServerConfig_DCODisabledByDefault` pins the
  directive's absence.

### Note

- `v2.0.2` tag exists in git but CI never produced images (tests
  failed). `2.0.3` is the first successful release with the DCO
  default fix.

## [2.0.1] — 2026-06-02

### Fixed

- `detectDCOSupport` now also recognizes the out-of-tree `ovpn_dco_v2`
  kernel module (commonly preloaded on older Ubuntu hosts), in addition
  to mainline `ovpn` and OOT v1 `ovpn_dco`. Previously hosts running
  only `ovpn_dco_v2` showed the "DCO unavailable" banner in the server
  config UI even though kernel offload was usable.

### Added

- SVG favicon matching the in-app ShieldCheck logo (with `.ico` fallback
  for legacy browsers).

## [2.0.0] — 2026-06-01

Major release: large pragmatic refactor, MFA/TOTP for the admin UI, editable
OpenVPN server configuration through the UI, server-side firewall, and a
multi-round security audit (~70 OWASP ASVS findings closed).

### Added

- **MFA / TOTP** authentication for the admin UI. Two-step login (password →
  6-digit code), client-side QR generation (no external services, no secret
  leak), 8 one-time backup codes in `XXXX-XXXX` format (bcrypt-hashed),
  HMAC-signed intermediate `mfa_token` (5 min TTL) with single-use JTI to
  block replay. Toggleable via `--mfa` / `OVPN_MFA` (default on), state in
  `--mfa.db-path`. Per-IP rate limit on disable, 409 on duplicate setup.
- **Editable OpenVPN server configuration** through the UI ("Сервер" tab).
  ~15 params (proto, port, MTU, cipher, DCO, DNS push, redirect-gateway,
  custom directives) editable without `helm upgrade` or container restart.
  Hybrid reload: SIGHUP for soft fields, SIGTERM-with-rollback for hard
  fields. DCO kernel support auto-detected at startup.
- **Public hostname override** in Server Config UI:
  `PublicHostname` / `PublicPort` / `PublicProto` override what clients
  connect to in generated `.ovpn` files. Empty values fall back to
  `--ovpn.server` CLI flag.
- **Server-init gate**: `Initialized` flag on ServerConfig blocks user
  creation/rotation (HTTP 412) until admin explicitly saves config via UI.
  `serverInitialized` surfaced through `serverSettings` API; UI shows
  banner on Users tab, AddUser button disabled.
- **Common Routes** feature: push routes (IP/CIDR or domain) to all active
  clients. Domain entries resolved and refreshed. Stored in K8s Secret or
  JSON file via Store interface.
- **Server-side firewall enforcement**: per-client iptables default-deny
  built from CCD CustomRoutes + Common Routes; self-heal reconcile and
  management-interface event stream so disconnects clean up.
- **Persistent session blacklist**: revoked tokens written to JSON on every
  logout, loaded at startup, expired entries discarded. Closes the prior
  12-hour replay window on restart.
- **Persistent session signing key**: 64-byte random key in
  `.session_signing_key` (0600 perms), decoupled from htpasswd. Fails loud
  on corrupt file instead of silently regenerating.
- **Rate limiting on login**: per-IP tracker, lockout after 5 failures for
  15 minutes. `X-Forwarded-For` honored only when source matches
  `--trusted-proxies` CIDR list.
- **Security headers middleware**: `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`,
  `Permissions-Policy`, `Cache-Control: no-store` on `/api/`, and a 1 MB
  request body limit on writes.
- **Playwright E2E tests** (chromium headless): login page render, valid /
  invalid login, empty-password validation, logout, MFA modal states, QR
  code generation. Global setup builds the Go binary and starts the server
  against a temp environment.
- **MFA integration tests**: `TestMfaLogin_WithoutMFA`,
  `TestMfaLogin_WithMFA`, `TestMfaSetup_Confirm_Cycle`,
  `TestMfaLogin_BackupCode`, `TestMfaDisable`.
- **Operational runbooks** under `docs/runbooks/`:
  `firewall-testing.md`, `k8s-helm-deployment.md`, `release-and-publish.md`.
- **`.env.example`** documenting all docker-compose variables;
  `OVPN_PUBLIC_HOSTNAME`, `OVPN_PORT`, `OVPN_PROTO`, `OVPN_ADMIN_BIND`
  (default `127.0.0.1`), `OVPN_ADMIN_PORT`.
- **README "Deploy on a single VPS"** section with step-by-step guide.

### Changed

- **BREAKING**: HTTP API unified to JSON. All 9 user-management handlers,
  `userShowCcdHandler`, and `/api/login` now decode `application/json` only;
  `application/x-www-form-urlencoded` bodies are rejected. Frontend
  `api.js` switched from `formData()` to `JSON.stringify`; the
  `formData()` helper is gone.
- **BREAKING**: Migrated from archived `gobuffalo/packr/v2` to Go 1.16+
  `//go:embed`. `templates/` and `frontend/static/` are embedded via
  `embed.FS`. Build no longer requires `packr2`; `go build` produces a
  self-contained binary. 550 lines removed from `go.sum`.
- **BREAKING**: Default `OVPN_MASTER_TOKEN` value (`VerySecureToken`) now
  causes startup failure when `--role=master`. Must be set explicitly.
- **BREAKING**: ovpn-admin container runs as non-root `ovpnadmin` user.
  `cap_net_admin+ep` set on `xtables-nft-multi` via `setcap` so iptables
  works without root. Container joined to shared GID 2000
  (`ovpnshared`) for the dynamic volume.
- **BREAKING (Helm users)**: firewall is enabled by default in the Helm
  chart for new installs. Existing installs upgrading the chart will get
  `--firewall=true` unless explicitly disabled:
  ```yaml
  ovpnAdmin:
    firewall:
      enabled: false
  ```
- Refactored `main.go` from 1933 lines to ~367 lines. Extracted into:
  `app.go` (387 lines, OvpnAdmin struct + state + config rendering),
  `users.go` (367, user CRUD + handlers), `ccd.go` (386, CCD parsing /
  domain resolution / handlers), `mgmt.go` (200, management-interface
  comms), `sync.go` (188, master-slave replication), `metrics.go` (107,
  Prometheus declarations). Purely mechanical extraction.
- Introduced **`storage.Store` interface** (`internal/storage/store.go`)
  with `filesystemStore` and `kubernetesStore` implementations. Replaces
  18 scattered `if *storageBackend == "kubernetes.secrets"` dispatches
  across `main.go`, `common_routes.go`, `server_config.go`. Single
  dispatch point in `main()`.
- Introduced **`CcdReader` interface** in `firewall.go`. Firewall no
  longer holds an `*OvpnAdmin` backpointer — uses `getCcd` +
  `commonRoutesSnapshot`. Now testable with a fake.
- Test suite: 113 of 120 tests run with `t.Parallel()` (94%). Global
  mutations (`ccdDir`, `storageBackend`) replaced with constructor
  injection. The 7 sequential tests mock the `domainResolver` package var.
- Write handlers: explicit HTTP method enforcement via `requireMethod`
  middleware on user list / statistic / show-config / show-ccd /
  user-disconnect / user-change-password and others.
- Slave-role guard: `requireMaster` middleware replaces ~14 inline
  duplicated checks. `userChangePasswordHandler` and
  `userDisconnectHandler` now correctly reject writes on slave nodes.
- Sync token: `X-Sync-Token` header only (query-string fallback removed);
  constant-time comparison via `subtle.ConstantTimeCompare`. Fails fast
  on master role when set to the insecure default.
- Session cookie: `Secure: true` by default.
- Login form no longer prefills `admin` as the username.
- `commonRoutesItemHandler` honors `--listen.base-url`.
- Atomic writes use unique tmp names, clean up on rename failure, 0600
  perms.
- Error responses to clients are generic; full errors go to server logs.
  `runBash` calls in `store_filesystem.go` replaced with `exec.Command`
  where possible. `-- ` end-of-options added to easyrsa calls
  (defense in depth).
- JSON error responses use `json.Marshal` (was `fmt.Fprintf` with raw
  string interpolation — broke on quotes in usernames).
- Helm chart marks critical Secrets (PKI, CCD, common-routes) with
  `helm.sh/resource-policy: keep`.
- Helm chart no longer ships a static `server.conf` ConfigMap;
  ovpn-admin renders it into a shared `emptyDir` at startup, openvpn-
  container waits via init-loop.
- Helm `values.yaml` `openvpn.*` fields (`proto`, `port`, `network`,
  `networkMask`, `logLevel`) are now **initial defaults only** —
  runtime values come from the editable server-config store.
- docker-compose admin UI binds to `127.0.0.1:8080` by default (use SSH
  tunnel; `OVPN_ADMIN_BIND=0.0.0.0` to expose). `version: '3'`
  deprecation removed.
- docker-compose: `setup/openvpn.conf` removed. `configure.sh` no longer
  auto-appends `auth-user-pass-verify` when `OVPN_PASSWD_AUTH=true` —
  use the "Дополнительно" textarea instead.
- `configure.sh`: shared volume chowned to `root:2000` and chmodded `0770`
  (no longer world-writable). `/etc/openvpn/pki` → `easyrsa/pki` symlink
  so rendered `server.conf` finds `ta.key` / `ca.crt`.
  iptables MASQUERADE non-fatal on Docker Desktop (no nft support).
- Docker image: `openvpn-user` binary pinned with SHA256 verification.

### Fixed

- **Command injection** via password field in user create/rotate:
  `runBash(fmt.Sprintf(...))` replaced with `exec.Command` using
  separate args. All openvpn-user invocations and `ovpnUserInitDb`
  affected.
- **Path traversal** via `Ccd.User` / `req.Username` in CCD and cert
  handlers: `usernameRegexp` tightened (rejects leading `-`, single
  dots, empty, `--` sequences for easyrsa flag-injection prevention).
- **Zip Slip** in tar extraction during master-slave sync: validate
  paths stay within target dir via `filepath.Clean` prefix check.
- **Config injection** via newline in `CustomDirectives` / `PushExtra` /
  common-route `Description` / CCD `Description`: `validateDirectiveLine`
  rejects `\n` / `\r` / quotes.
- **Management-interface command injection** via newline in username
  (kill command).
- **Timing attack** in `verifyMfaToken`: was `!=`, now `hmac.Equal`.
- **Timing oracle** in `validateCredentials`: now runs a dummy bcrypt on
  unknown user so login time is constant.
- **JTI expiry mismatch** in `consumeMfaJti`: uses real token expiry
  instead of a fresh TTL — replay window now consistent.
- **MFA bypass**: `verifySession` now rejects tokens with `mfa` purpose
  (previously could be exchanged for a full session).
- **TOTP secret leak** to `api.qrserver.com`: QR code now generated
  client-side.
- **`UnrevokeClient` double-move bug**: cert is now copied to both
  destinations and then the source is deleted (previously the cert
  was never restored to `certs_by_serial/`).
- **`userDisconnectHandler` stub**: now actually disconnects via the
  management interface (previously just echoed the username).
- **Race condition** on `oAdmin.clients` slice: now protected by
  `RWMutex`.
- **Invalid JSON** in user-handler error responses (unescaped quotes
  broke the body).
- **`mfaLoginHandler` ordering**: nil-check moved before state mutation.
- **`signing-key` file corruption** silently regenerating — now fails
  loud.
- **Non-deterministic session secret**: map iteration order replaced
  with sorted keys.
- **Private key logging** at TRACE level — redacted.
- **OpenVPN proto rendering**: emits `tcp-server` when `Proto=tcp` and
  plain `udp` when `Proto=udp` (`udp-server` was invalid and rejected
  by OpenVPN).
- **`/metrics` endpoint** now protected by `requireAuth`.
- **Slowloris**: explicit HTTP server timeouts.
- **`serverConfigDefaultsHandler`** was missing method check — added.

### Security

- AES-256-GCM encryption for TOTP secrets at rest (via the Store layer).
- ~70 OWASP ASVS 5.0 findings addressed across three audit rounds
  (12 + 7 + 12 + 11 fixes; see commits `ff83508`, `b036a35`, `9af8277`,
  `b9780dc`).
- Helm chart per-container `securityContext`: dropped capabilities,
  `runAsNonRoot`, `seccompProfile: RuntimeDefault`.
- Helm RBAC tightened with `resourceNames` allowlist on PKI secrets.
- Helm `/lib/modules` hostPath made opt-in via `ovpnAdmin.dco.enabled`.

### Removed

- Deprecated `gobuffalo/packr/v2` and 6 transitive deps from `go.mod`
  (550 lines from `go.sum`).
- Form-urlencoded login endpoint (`/api/login`).
- Sync-token query-string fallback (header-only now).
- `Store.Bootstrap()` interface method (was no-op).
- Dead functions: `loadServerConfigFromFile`, `saveServerConfigToFile`,
  `loadCommonRoutesFromFile`, `saveCommonRoutesToFile` (production paths
  use the Store interface).
- Dead fields: `OvpnAdmin.commonRoutesPath`, `serverManager.storagePath`.
- Inline `signMfaTokenWithTTL` merged into `signMfaToken`.

### Documentation

- `docs/superpowers/specs/2026-05-26-server-config-design.md` — editable
  server config design.
- `docs/superpowers/specs/2026-05-27-mfa-totp-design.md` — MFA/TOTP
  design.
- `docs/superpowers/plans/2026-05-26-pragmatic-refactor.md`,
  `2026-05-26-server-config.md`, `2026-05-27-mfa-totp.md` —
  implementation plans.
- `docs/runbooks/firewall-testing.md`, `k8s-helm-deployment.md`,
  `release-and-publish.md` — operational runbooks.
- README "Deploy on a single VPS" section.

### Migration notes

For users upgrading from 1.x:

1. **Set `OVPN_MASTER_TOKEN`** to a strong random value (e.g.
   `openssl rand -hex 24`) before starting. The default
   `VerySecureToken` no longer works in `--role=master`.
2. **Frontend / API clients calling `/api/login` or user-management
   endpoints** must send JSON. Form-urlencoded bodies are rejected.
3. **Build process**: `packr2` is no longer required; `go build`
   directly produces a self-contained binary.
4. **First admin login after upgrade**: server-config defaults are
   applied automatically, but users can't be created or rotated until
   admin explicitly saves the config via UI ("Сервер" tab → Save).
   Existing PKI is preserved.
5. **MFA**: optional, enabled by default. Each admin can enable TOTP
   via the shield icon in the header. Disable globally with `--mfa=false`
   if not wanted.
6. **Helm users**: firewall is `enabled: true` by default for new
   installs. Set `ovpnAdmin.firewall.enabled: false` if you need the
   old behavior. Critical Secrets now carry
   `helm.sh/resource-policy: keep` — to actually wipe state on uninstall,
   `kubectl delete secret` them manually.
7. **docker-compose users**: admin UI binds to `127.0.0.1:8080` by
   default. Use an SSH tunnel for access, or set
   `OVPN_ADMIN_BIND=0.0.0.0` to expose it.

[2.0.0]: https://github.com/flant/ovpn-admin/releases/tag/v2.0.0

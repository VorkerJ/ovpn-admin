# Changelog

All notable changes to ovpn-admin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.31] — 2026-06-29

### Security

- **API-token scope matching is now anchored to whole path segments.** The
  v2.0.30 scope check used `strings.Contains`, so a lookalike path like
  `/api/user-admin` or `/api/userspace` would have been treated as an in-scope
  `/api/user*` route. No such endpoint exists today (not exploitable), but the
  match is now `== seg || HasPrefix(seg+"/")` against the base-URL-stripped
  path, so lookalikes are denied. Adversarially verified live: a token is held
  to 403 on server-config / MFA / admin-password / token-management / metrics
  and on every bypass attempt (path traversal, `%2f`/`%2e%2e` encoding, query
  injection, double slash), while in-scope user/route calls still work. Tokens
  remain SHA-256-at-rest (0600), constant-time compared, and never logged.

## [2.0.30] — 2026-06-29

### Added

- **Service-account API tokens for non-interactive integrations.** External
  systems (e.g. an access-management/Teleport-style tool) can now manage VPN
  users and routes over the API without the interactive session/MFA flow. A
  token is presented as `Authorization: Bearer <token>` (or `X-API-Token`);
  it bypasses the MFA and forced-password-change gates (a service can do
  neither) but is **scope-limited** to user- and route-management endpoints —
  it cannot touch server config, MFA, the admin password, or token management
  (those return `403`). Tokens are random, stored only as SHA-256, persisted on
  the auth state dir (PVC), and managed from a new **API-токены** screen in the
  admin UI (create — shown once — and revoke). Creating/revoking a token still
  requires an MFA-enabled admin session. Verified end-to-end: a token reads
  users/traffic (`200`), writes a common route (`201`, MFA bypassed), is denied
  out-of-scope (`403`), and stops working immediately on revoke (`401`).

## [2.0.29] — 2026-06-29

### Fixed

- **An expired/invalidated session no longer shows a raw "unauthorized" stuck in
  a view (notably the new Трафик tab, whose periodic auto-refresh surfaced it
  first).** Added a global axios response interceptor: any `401` from an API
  call after login drops the app back to the login screen with a "session
  expired" toast, instead of each view rendering the backend error. Verified in
  a browser: breaking the session and refreshing Traffic now returns to login.
- **The SPA `index.html` is no longer cached for 30 days.** `CacheControlWrapper`
  set `max-age=2592000` on *everything*, so after an upgrade browsers kept
  serving the old `index.html` (and thus the old asset bundle) — frontend
  changes silently didn't appear until the cache expired. Now content-hashed
  `/assets/*` are cached `immutable` (they're safe to), while `index.html` and
  the rest are served `no-cache` so updates take effect on the next reload.

## [2.0.28] — 2026-06-29

### Fixed

- **docker-compose now brings up a working VPN on a fresh deploy.** End-to-end
  testing of the production `docker-compose.yaml` surfaced two issues:
  - **The openvpn container never started.** ovpn-admin (non-root) renders
    `server.conf` into the shared `/etc/openvpn-dynamic` volume, but the openvpn
    container's `configure.sh` `chgrp`'d that volume to group 2000 *without* the
    `CHOWN` capability (it had `cap_drop: ALL` and a narrow `cap_add`), so the
    chgrp failed silently, ovpn-admin couldn't write `server.conf`, and openvpn
    waited for it forever. Added `CHOWN` to the openvpn `cap_add`.
  - **Durable auth state was missing.** Added an `OVPN_SESSION_STATE_DIR`
    (`/var/lib/ovpn-admin`) backed by a named `ovpn_admin_state` volume, so the
    session key, MFA secrets, self-changed admin password and cumulative traffic
    survive `down`/`up` — and don't land on the read-only htpasswd mount (which
    would otherwise crash startup). The ovpn-admin image pre-creates the dir
    owned by `ovpnadmin` so the named volume inherits writable ownership.

  Verified end-to-end locally: both containers up, server.conf rendered, openvpn
  reaches "Initialization Sequence Completed", mgmt interface connected. The
  Helm chart already handled both via its PVC + securityContext.

## [2.0.27] — 2026-06-26

### Added

- **Per-user cumulative traffic, with a new "Трафик" tab.** OpenVPN's mgmt
  `status` only reports *current-session* byte counters (they reset on every
  reconnect), so the UI had no "how much has each user used" view. A new
  `trafficAccountant` folds each mgmt poll into lifetime totals — adding the
  full counter on a new session (detected via `ConnectedSince`) and only the
  positive delta within an ongoing session — and persists them as JSON in the
  auth state dir (`<state-dir>/traffic.json`, on the PVC when enabled), so
  totals survive reconnects and restarts. New `GET /api/traffic` (auth-gated)
  returns per-user RX/TX/total plus live-connection status, sorted by volume.
  The frontend adds a sortable, searchable **Трафик** tab with summary cards.
  Note: without a PVC the totals live on the pod's ephemeral fs and reset on
  restart (same tradeoff as the other auth state).

## [2.0.26] — 2026-06-25

### Fixed

- **Chart no longer passes a non-existent `--firewall.startup-timeout` flag.**
  The deployment template rendered `--firewall.startup-timeout=...` whenever the
  firewall was enabled, but the binary has no such flag — and the firewall
  defaults to ON. So a fresh `helm install` of this chart would have
  CrashLoopBackOff'd on an "unknown flag" at startup (no in-cluster deployment
  used this chart yet, so nothing in production was affected). Removed the
  orphan flag and its `firewall.startupTimeout` value; the firewall's
  reconnect/retry backoffs are internal constants, not a configurable startup
  timeout.

## [2.0.25] — 2026-06-25

### Fixed

- **CI is green again, so the image/chart release actually runs.** Two CI jobs
  were failing, and the image builds + chart release `needs` them — so the
  v2.0.23 (native openvpn-user) and v2.0.24 (govulncheck) tags built no images.
  Fixed: (1) `errcheck` flagged unchecked `*sql.DB`/`*sql.Rows` `Close()` in the
  new `internal/ovpnuser` (the lint config only excludes `io.Closer.Close` on
  the interface type); (2) the `govulncheck` job resolved Go from the `go`
  directive (1.25.0, unpatched) — it now sets up the patched toolchain (1.26.4)
  explicitly. This release carries the full v2.0.23–v2.0.25 set into images.

## [2.0.24] — 2026-06-25

### Security

- **`govulncheck` now gates CI**, failing the build on any known CVE in the Go
  stdlib or an imported/required module that our code actually reaches. A
  `toolchain go1.26.4` directive pins the build to a patched Go release so the
  13 stdlib advisories `govulncheck` flagged against an older 1.26.0 toolchain
  (reachable via the HTTP server / crypto/x509 / net/url / os) stay resolved.
  The release images already built on `golang:1.26-bookworm` (go1.26.4), so the
  published artifacts were not affected; this makes it deterministic and
  enforced.

## [2.0.23] — 2026-06-25

### Changed

- **`openvpn-user` is now built from our own source — no third-party binary
  download.** Both images previously `wget`-ed a prebuilt `openvpn-user` binary
  from a personal GitHub release (`pashcovich/openvpn-user`). For an
  infrastructure component that is a supply-chain risk: a compromised upstream
  release (or a version bump that re-pins its hash to a poisoned artifact) would
  be baked straight into the image on the next rebuild. `openvpn-user` is now a
  native Go reimplementation (`internal/ovpnuser`, pure-Go `modernc.org/sqlite`,
  Apache-2.0 like the original) that is **wire-compatible** with existing
  `users.db` files — verified bidirectionally against the upstream binary
  (identical schema, stdout messages and exit codes; OpenVPN's `auth` contract
  of exit 0 = allow / non-zero = deny is preserved). The ovpn-admin binary
  serves the CLI itself when invoked as `openvpn-user` (argv[0] symlink), so the
  admin image ships a single binary; the OpenVPN server image builds a tiny
  standalone `cmd/openvpn-user` from the same source. New password hashes use
  bcrypt DefaultCost (10) instead of the upstream MinCost (4); existing hashes
  still verify. TOTP-secret generation uses `crypto/rand`.

## [2.0.22] — 2026-06-24

### Added

- **Durable auth state via `--session.state-dir` + an optional chart PVC.** The
  session signing key, logout blacklist, MFA (TOTP) secrets and the
  self-changed admin password previously landed on ephemeral paths (`/tmp`,
  CWD) or — worse, with a mounted htpasswd Secret — under the **read-only**
  `/etc/ovpn-admin/auth` mount, which crashed the pod on the signing-key write.
  A new `--session.state-dir` flag (`OVPN_SESSION_STATE_DIR`) points all of that
  at one writable directory; when set, the MFA secrets path defaults under it
  too (no second flag needed).
- **Helm chart `persistence` block.** When `persistence.enabled=true` the chart
  provisions a PVC, mounts it at `/var/lib/ovpn-admin`, passes
  `--session.state-dir` / `--mfa.db-path`, and sets `fsGroup` (default `2000`,
  the image's `ovpnshared` group) so the non-root `ovpnadmin` user can write it.
  Result: admin sessions, MFA enrollment and the forced-password-change state
  survive pod restarts. Defaults to an `emptyDir` (pod-lifetime) when disabled,
  so existing installs are unaffected until they opt in.

## [2.0.21] — 2026-06-22

### Security

- **Harden the self-changed-password persist path against a planted-file
  attack.** v2.0.20 persists a runtime admin password change to
  `/tmp/.ovpn-admin-admin.htpasswd` when no `ADMIN_HTPASSWD_FILE` is set, and
  loads it on startup. `/tmp` is world-writable, so a local user could plant a
  htpasswd with an attacker-known hash and ovpn-admin would silently adopt it
  (and skip the forced change). Startup now loads that file only if it is a
  regular file, owned by the current uid, with no group/world permission bits
  (`isOwnerOnlyCredFile`); on any mismatch it logs and regenerates a temporary
  password instead. Our own writes are atomic 0600, so they always pass.

## [2.0.20] — 2026-06-22

### Security

- **Forced password change on first login.** When no `ADMIN_HTPASSWD_FILE` is
  configured, ovpn-admin generates a temporary admin password and prints it to
  the logs. Anyone with log access could previously use it directly — and,
  because admin MFA is *required-but-not-yet-enrolled* on a fresh deploy, a
  first-mover could self-enroll MFA and lock the real admin out. The admin is
  now flagged `must-change`: after logging in with the temporary password,
  `requireAuth` returns `412 password change required` for **every** endpoint
  (including `/metrics`) except the change-password flow, until a new password
  (min 12 chars) is set via `POST /api/admin/change-password`. The change
  requires the current password (a hijacked session alone can't rotate it) and
  is persisted (atomic, 0600) so it survives restarts without re-triggering the
  prompt. A non-dismissable modal drives this in the UI.
- **`getOvpnCaCertExpireDate` no longer panics on an unreadable/garbage
  `ca.crt`.** A read error was logged but execution continued into
  `pem.Decode(nil)` → `certPem.Bytes` nil-deref → `SIGSEGV` crash loop. It now
  returns early on read failure and on a missing PEM block.
- **`secretGenTaKeyAndDHParam` (k8s PKI bootstrap) switched from `bash -c` +
  `fmt.Sprintf` to argv-based `exec.Command`.** The paths are fixed constants
  today (no injection), but the shell form would become command injection the
  moment any argument turned user-derived. Defensive hardening.

## [2.0.19] — 2026-06-10

### Fixed

- **Domain routes that share an IP now round-trip correctly.** When several
  domains resolved to the same address (e.g. nine `*.telegram.org` /
  `t.me` / `telesco.pe` domains → one Telegram front-end IP), `mergePushRoutes`
  collapsed them onto a single push line with a comma-joined source comment
  (`# __user_domain__:t.me,__user_domain__:telegram.org,…`). `parseCcd` then
  read the whole comma string back as one bogus "hostname", which failed
  validation on the next re-render — so the periodic DNS refresh for those
  users was silently skipped (`CustomRoute.Domain "…" is not a valid
  hostname`). Their existing routes kept working (the failed re-render left
  the CCD file untouched), but the domains could not get fresh IPs over time.
  `parseCcd` now splits the merged source on `,` and registers the IP under
  every listed domain. Pre-existing bug (the prior parser had the same
  single-domain logic); surfaced during the v2.0.18 deploy. Regression test
  added with the real Telegram shape.

## [2.0.18] — 2026-06-09

Security hardening release following a full audit (auth, injection, CVEs,
container, full-tunnel/CCD). Backwards-compatible: existing CCD files and
server configs are unaffected — verified by parsing real production CCDs
through the rewritten parser (no spurious full-tunnel, no spurious
exclusions, all per-user routes preserved). No migration or client
reconfiguration required.

### Fixed

- **HIGH — CCD marker confusion.** `parseCcd` classified push lines by
  substring-scanning the whole line for control markers
  (`__redirect_gateway__`, `__exclusion_user__`, …), but a route's free-text
  description renders into that same trailing comment. A description such as
  `__redirect_gateway__` or `__exclusion_user__ …` was therefore re-read as
  control state on the next round-trip (apply / import / 24h scheduler /
  rerenderAllCcds), silently dropping the route and persisting a forged
  full-tunnel flag or exclusion — letting anyone with route-edit/import
  rights bypass the VPN for chosen traffic. Fixed two ways: (1) `parseCcd`
  now splits each line into directive + comment and trusts a marker ONLY
  when the directive SHAPE matches (`redirect-gateway` vs `route` vs
  `route … net_gateway`), which only our own renderer produces; (2) the
  three description validators reject the reserved marker substrings at
  write time. Regression-tested against forged descriptions and against
  every legitimate line shape for backwards compatibility.
- **MEDIUM — `0.0.0.0/0` accepted as a full-tunnel exclusion** silently
  cancelled `redirect-gateway def1` for affected users. `validateSubnet`
  now rejects a `/0` mask with a clear message pointing to the
  redirect-gateway toggle instead.

### Security

- **Go build toolchain bumped 1.25 → 1.26** in `Dockerfile.ovpn-admin`.
  `govulncheck` flagged 13 reachable Go stdlib CVEs against the 1.25 base,
  including the HTTP/2 transport infinite-loop (GO-2026-4918) and the
  TLS 1.3 KeyUpdate connection-retention DoS (GO-2026-4870), both remotely
  reachable from the admin HTTP server and the k8s client. The `golang:1.26`
  rolling tag pulls the latest patched 1.26.x at build time.
- Removed a stale, unused `OVPN_MASTER_TOKEN` secret left in the local
  `.env` (leftover from the removed master/slave feature; gitignored but a
  plaintext-secret hygiene risk).

### Audit notes (no code change — documented as accepted / deferred)

- TOTP replay guard tracks only the last-used code (90s) rather than the
  consumed time-step counter — narrow replay window, deferred.
- Kubernetes storage backend lacks the defense-in-depth `validateUsername`
  the filesystem backend has (not reachable today; handlers validate first).
- Common Routes domain resolution has no cap on A-record count (availability
  risk if a domain returns thousands of records — can overflow PUSH_REPLY).
- Helm `init-sysctl` runs `privileged: true` for a single sysctl.
- Auth layer reviewed and found well-hardened (HMAC-signed sessions,
  secure-by-default cookies, enumeration timing closed, two-phase MFA with
  AES-GCM secret storage, every write endpoint MFA-gated).

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

## [2.0.17] — 2026-06-03

### Added

- **Per-user `redirect-gateway` toggle in the CCD modal**: a "Полный туннель"
  checkbox that, when on, renders `push "redirect-gateway def1"` into the
  user's CCD so every byte (DNS included) leaves through the VPN. Solves
  the "I just want it to work" case where the operator doesn't want to
  hunt down every CDN block for a single user.
- **Global redirect-gateway exclusions list in `ServerConfig`**: a structured
  table of `Address`/`Mask`/`Description` rows that render as
  `push "route X Y net_gateway"` for every full-tunnel user. Default ships
  with the typical home-LAN ranges (192.168/16, 10/8, 172.16/12, 169.254/16)
  so home printer / NAS / router admin keep working without manual setup.
- **Per-user exclusion list** layered on top: each user can add subnets that
  apply only to them (e.g. their corp-VPN range) without touching the global
  defaults. Render-side merge dedupes by `(Address, Mask)` and tags the
  combined `Source` comment so an operator grepping the CCD can tell where
  the entry came from.
- New `Subnet` type with strict IPv4 validation: rejects malformed addresses
  and masks, non-contiguous netmasks (e.g. `255.0.255.0`), addresses with
  host bits set under their mask (forces canonical network form), IPv6,
  and descriptions containing newlines / double quotes / NUL bytes /
  >200 chars — all of which would otherwise let an attacker with CCD-edit
  permission inject extra `push` directives.

### Changed

- `serverConfigHandler` now rerenders all CCDs in the background when
  `RedirectGateway` or `RedirectGatewayExclusions` change, so existing
  users pick up the new globals at next reconnect without a manual edit.
- `parseCcd` learns three new marker prefixes (`__redirect_gateway__`,
  `__exclusion_global__`, `__exclusion_user__`) so a saved CCD round-trips
  cleanly. Global exclusions are intentionally NOT re-imported into the
  per-user list — server-config stays authoritative for those.
- User-row dropdown action "Маршруты" renamed to "Настройки", and the
  modal title becomes "Настройки: <user>". The modal now uses three tabs
  (Подключение, Маршруты, Исключения) instead of a single long form, so
  the operator focuses on one concern at a time. Bulk import lives under
  an expandable section inside the Маршруты tab.
- Dialog body now scrolls internally (max-h-90vh) and locks `<body>`
  scroll while a modal is visible; the footer with Save/Close stays
  pinned above long forms. Affects every modal in the app.
- UsersTable and CommonRoutesView gain client-side pagination + a
  visible-range counter + a sticky thead, and the global ServerConfigView
  header (Save / Reset) sticks under the AppHeader so it stays reachable
  when editing collapsed sections lower on the page.
- Common-routes Add form is now a `<form>` so Enter submits, and known
  backend errors (`duplicate entry`, `invalid IP/mask/domain`) are
  surfaced in Russian.

### Migrations

- **`deserializeServerConfig` now backfills `redirect_gateway_exclusions`
  on upgrade** from any prior version that never wrote that field. Without
  this an operator who turned on full-tunnel for a single user after
  upgrade would lose home-LAN access entirely — no global LAN exclusions
  would be pushed because the loaded slice was empty. Distinguishes
  "missing field in JSON" from "explicitly empty list set by operator"
  via a `map[string]json.RawMessage` peek, so deliberately-cleared lists
  are respected and not re-populated on every load.
- `Dockerfile.ovpn-admin` honours BuildKit's `TARGETARCH` (defaulting to
  `amd64` for CI), so local builds on Apple Silicon produce a native
  arm64 binary instead of failing cross-compile via `gcc -m64`.

### Fixed

- **CcdModal silently dropped the `RedirectGateway` toggle when the
  operator added a per-user exclusion**: `withFullTunnelDefaults` reused
  the same `RedirectGatewayExclusions` array reference as `props.ccd`,
  so the per-user `push` mutation bubbled to props, fired the deep watch,
  and reset `localCcd` (with the old `RedirectGateway: false` from the
  initial GET). The toggle visibly stayed on in the UI but the POST
  body carried `false`. Caught by the new Playwright spec. Fix: clone
  each exclusion into its own object on initialisation.
- Default-exclusion `Description` validation now rejects NUL bytes (in
  addition to newlines, double quotes, and >200-char strings) so an
  attacker with CCD-edit permission can't truncate the rendered comment.

### Tests

- New Playwright spec `redirect-gateway.spec.ts` covers:
  - Unauthenticated `/api/server-config`, `/api/users/list`,
    `/api/auth/check`, `POST /api/user/ccd/apply`, and
    `PUT /api/server-config` all return 401.
  - Logging out invalidates the session cookie immediately.
  - End-to-end UI flow: open the user-settings modal, toggle full-tunnel,
    switch to Исключения tab, add a per-user exclusion, save — verifies
    both the outgoing POST body and the round-trip via parseCcd.
  - Backend validation rejects an exclusion whose address has host bits
    set under its mask (422 + "host bits" message).
- New `DataTable.vue` component extracts the sticky-thead +
  internal-scroll + empty-state shell shared by the routes and
  exclusions tables.

## [2.0.16] — 2026-06-03

### Fixed

- **MASQUERADE now follows the JSON-persisted subnet across openvpn
  container restarts**, completing the fix v2.0.14 attempted. The
  earlier attempt put the reconcile inside ovpn-admin, but
  ovpn-admin runs non-root with `no-new-privileges: true`, which
  blocks file capabilities on `iptables` even though the container
  has `cap_add: NET_ADMIN`. Every call ended in
  `Could not fetch rule set generation id: Permission denied`,
  silently keeping the stale env-derived rule in place — so a
  user-subnet change in the UI looked like it worked, openvpn
  served clients in the new subnet, but their egress was still
  natted only when packets matched the old subnet (i.e. never).
  
  Fix moved into the openvpn image where iptables actually has
  root: `setup/configure.sh` gains `ensure_masquerade`, which
  parses the rendered `/etc/openvpn-dynamic/server.conf` for the
  `server NETWORK NETMASK` line and re-installs the MASQUERADE
  rule for that subnet, removing any prior `-s X/Y ! -d X/Y -j
  MASQUERADE` shaped rules (so Docker bridge MASQUERADE is left
  alone). Runs once per openvpn container start, so any subsequent
  hard reload triggered by a UI save picks up the new subnet
  automatically (the SIGTERM → docker-restart → configure.sh chain
  re-runs the parse). The ovpn-admin-side reconcile is removed
  along with its dead `masquerade.go`.

## [2.0.15] — 2026-06-03

### Fixed

- **`DeleteClient` now also removes the user's CCD file.** Previously
  it only wiped the PKI artefacts (`*.key`, `*.crt`, `*.req`) and the
  per-user CCD persisted at `<ccdDir>/<CN>`. Recreating a user with the
  same CN inherited the previous tenant's per-user routes and fixed
  VPN IP — a real surprise for the operator and a policy hazard if
  the routes were sensitive. The CCD file and the inline-private
  artefact are now removed alongside the cert.
- **`userCreate` seeds a fresh CCD with the current Common Routes**
  immediately after `BuildClient` succeeds. Before this fix a newly-
  created user had no `/etc/openvpn/ccd/<CN>` at all and received only
  server-level push directives at first connect — Common Routes were
  silently dropped until the next `rerenderAllCcds` (which fires only
  on later admin actions, e.g. another Common Route change). With the
  seed, the very first PUSH_REPLY already carries every common route.

## [2.0.14] — 2026-06-03

### Fixed

- **MASQUERADE rule now follows the VPN subnet.** `configure.sh` set
  up an initial MASQUERADE for the env-derived `OVPN_SERVER_NET` at
  openvpn-container start. When the operator changed the VPN subnet
  in the server-config UI, ovpn-admin re-rendered `server.conf` and
  restarted openvpn, but the stale env-derived MASQUERADE stayed in
  iptables. Clients in the new subnet then egressed with their
  unroutable private source address and got dropped at the upstream
  gateway — symptom: "VPN connected, route table correct, but no
  internet". `apply()` now reconciles `nat POSTROUTING` after every
  save, dropping any prior `-s X/Y ! -d X/Y -j MASQUERADE` rule
  (the shape ovpn-admin emits, distinct from Docker bridge rules)
  and installing one for the current subnet.
- **Duplicate `push "route X 255.255.255.255"` lines deduped at
  render time.** When several domain routes resolved to overlapping
  CDN endpoints (google.com / youtube.com / googlevideo.com often
  share Fastly front-ends), the rendered CCD repeated the same IP
  on multiple lines. Windows OpenVPN GUI spammed
  `route addition failed because route exists` for every dup, and
  the bloated PUSH_REPLY threatened the 1024-byte default cap on
  busy users. `modifyCcd` now builds a unique `(Address, Mask)` set
  and emits each route exactly once; the trailing comment lists every
  source (domain or common tag) that asked for the IP, so an operator
  greping the file can still trace each line back to its origin.

## [2.0.13] — 2026-06-03

### Fixed

- `setup/configure.sh` no longer locks the easyrsa `pki/` directory to
  `755` at every openvpn-container start. ovpn-admin runs as a
  non-root user belonging to group `2000` (ovpnshared); 755 leaves the
  group with `r-x` and easyrsa fails with
  `Failed to create lock-file (permissions?)` on the next user-create,
  revoke, or CRL regeneration. The script now sets `2775` (setgid +
  rwxrwxr-x), so future files and dirs created under `pki/` inherit
  the right group automatically.

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

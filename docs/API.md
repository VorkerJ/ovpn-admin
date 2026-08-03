# ovpn-admin API — service-account integration

For non-interactive integrations (your backend creating/revoking VPN users and
managing their routes). Everything here is reachable with a **service-account API
token** — no browser session, no MFA prompt.

---

## Authentication

Create a token in the UI: header **🔑 (API tokens)** → give it a name → the token
is shown **once** (starts with `ovpnadm_`). Save it immediately; it is stored
hashed and cannot be retrieved again. (Creating tokens requires an MFA-enabled
admin — a security requirement on the human side only.)

Send it on every request as a Bearer token:

```
Authorization: Bearer ovpnadm_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

(Or the header `X-API-Token: ovpnadm_...` if a Bearer header is inconvenient.)

### Is the token static? Yes.

- **No expiry, no refresh.** It is valid until you revoke it in the UI. Service
  accounts can't do interactive TOTP, so there is no rotation flow — treat it like
  a long-lived secret (store in a vault/secret manager).
- Revocation is immediate: delete it in the UI and it stops working on the next
  request.
- To rotate: create a new token, switch your integration to it, then delete the
  old one.

### Scope (what a token may touch)

A token is **restricted to user and route management**. Allowed path prefixes:

| Prefix | Purpose |
|---|---|
| `/api/user`, `/api/users` | user lifecycle + per-user routes (CCD) + `.ovpn` |
| `/api/common-routes` | global routes pushed to all users |
| `/api/traffic` | per-user traffic (read) |

Anything else (`/api/server-config`, `/api/mfa/*`, `/api/api-tokens`,
`/api/admin/*`, `/metrics`, …) returns **403** — a token cannot change server
config, manage MFA, mint other tokens, or change the admin password.

---

## Conventions

- Base URL: your ovpn-admin origin, e.g. `https://vpn.example.com`. All paths
  below are relative to it (if you run with `--listen.base-url`, prepend it).
- Request bodies are JSON; set `Content-Type: application/json`.
- Usernames must match `^[A-Za-z0-9_@][A-Za-z0-9_.@-]{0,62}$` (validated
  server-side; invalid → `400`).
- Errors are `{"error":"<message>"}` with a matching HTTP status:
  `400` bad request/validation · `401` missing/invalid token ·
  `403` out of scope · `405` wrong method · `412` server not yet initialized ·
  `5xx` server error.
- **One-time setup:** users can only be created after the server has been
  initialized once in the UI (Server tab → Save). Until then user-create returns
  `412` (server-config is out of a token's scope, so this is a human step).

---

## Users

### List users

```
GET /api/users/list
```
Returns an array of users:
```json
[
  {
    "Identity": "alice",
    "AccountStatus": "Active",          // Active | Revoked | Expired
    "ExpirationDate": "2036-01-02 12:00:00",
    "RevocationDate": "",
    "ConnectionStatus": "Connected",    // "" when offline
    "Connections": 1,
    "PasswordRequired": false
  }
]
```

### Create a user (issues a certificate)

```
POST /api/user/create
{ "username": "alice", "password": "" }
```
`password` is only meaningful when per-user password auth is enabled; for
cert-only users send `""`. Response `200` `{"status":"ok", ...}`; the client cert
is generated and the user appears in the list.

### Download the user's `.ovpn`

```
POST /api/user/config/show
{ "username": "alice" }
```
Returns the ready-to-use OpenVPN config as **plain text** (not JSON). Hand this to
the client.

### Revoke / restore / rotate / delete

```
POST /api/user/revoke     { "username": "alice" }   # cert → CRL, session dropped, reversible
POST /api/user/unrevoke   { "username": "alice" }   # undo a revoke
POST /api/user/rotate     { "username": "alice" }   # new keypair, old cert revoked
POST /api/user/delete     { "username": "alice" }   # cert → CRL, files removed, NOT reversible
POST /api/user/disconnect { "username": "alice" }   # kick the live session (stays authorized)
```
Each returns `200` on success or `4xx` with `{"error":...}`.

### Per-user VPN password (optional second factor)

By default clients authenticate with their **certificate only**. You can require
an additional username+password *on top of* the cert for specific users. The
server-wide switch (Server tab → "password auth") must be enabled once in the UI
first — that toggle is out of a token's scope — after which a token can set or
clear individual users' passwords:

```
POST /api/user/change-password   { "username": "alice", "password": "s3cret" }   # set / change
POST /api/user/remove-password   { "username": "alice" }                         # back to cert-only
```
`change-password` marks the user as password-required and their `.ovpn` will then
carry `auth-user-pass`. `remove-password` returns `501` if password auth is
disabled server-wide. Both return `200` `{...}` on success.

### Per-user statistic

```
POST /api/user/statistic   { "username": "alice" }
```
Returns connection statistics for the user (bytes / sessions as tracked by the
mgmt interface). For cumulative per-month usage prefer `/api/traffic` below.

---

## Per-user routes (CCD)

A user's routes live in their **CCD**. There are two ways to change them:

- **Granular** (`ccd/route/add`, `ccd/route/remove`) — add or remove individual
  routes, leaving the rest untouched. **Recommended for automation**, especially
  when several changes can happen concurrently: each call is a server-side
  read-modify-write under a lock, so two async callers can't clobber each other.
- **Full replace** (`ccd/apply`) — you send the *entire* desired route set and it
  replaces what's there (PUT-style). Fine for a single sequential writer; with
  concurrent writers you'd risk a lost update, so prefer the granular endpoints.

All three are serialized server-side (a global CCD lock), so even `apply` is
internally consistent — the caveat with `apply` is only that *your* read (GET)
can go stale between GET and POST if something else writes in between.

### Get a user's CCD

```
POST /api/user/ccd
{ "username": "alice" }
```
Returns the CCD object:
```json
{
  "User": "alice",
  "ClientAddress": "dynamic",
  "RedirectGateway": false,
  "CustomRoutes": [
    { "Kind": "ip",     "Address": "10.8.0.0", "Mask": "255.255.255.0", "Description": "office" },
    { "Kind": "domain", "Domain": "github.com", "Description": "git" }
  ]
}
```

### Route fields

| Field | For | Notes |
|---|---|---|
| `Kind` | both | `"ip"` (default) or `"domain"` |
| `Address` + `Mask` | `ip` routes | dotted-quad network + mask |
| `Domain` | `domain` routes | server re-resolves periodically and pushes current IPs |
| `Description` | both | free text (ignored when matching for removal) |

A route's **identity** (for dedup on add, and for matching on remove) is:
`ip` → `Address`+`Mask`; `domain` → the hostname (case-insensitive).
`Description` is *not* part of the identity — you don't need to know it to remove
a route.

### Add route(s) — granular

```
POST /api/user/ccd/route/add
{ "username": "alice",
  "route": { "Kind": "ip", "Address": "10.8.0.0", "Mask": "255.255.255.0", "Description": "office" } }
```
Send a single `route` **or** a `routes` array (or both — they're concatenated):
```
POST /api/user/ccd/route/add
{ "username": "alice",
  "routes": [
    { "Kind": "ip",     "Address": "10.8.0.0", "Mask": "255.255.255.0" },
    { "Kind": "domain", "Domain": "internal.example.com", "Description": "app" }
  ] }
```
Response `200`:
```json
{
  "added":   [ { "Kind": "ip", "Address": "10.8.0.0", "Mask": "255.255.255.0", "Description": "office" } ],
  "skipped": [],
  "ccd":     { "User": "alice", "CustomRoutes": [ ... full updated list ... ] }
}
```
- Routes already present are returned in **`skipped`** (not an error) → the call
  is **idempotent**, safe to retry.
- Domain routes are resolved synchronously; the returned entry carries
  `ResolvedIPs`.
- `422` only if a supplied route fails validation (bad IP/mask, invalid hostname,
  description with a reserved marker, etc.) — nothing is written in that case.

### Remove route(s) — granular

```
POST /api/user/ccd/route/remove
{ "username": "alice",
  "route": { "Kind": "ip", "Address": "10.8.0.0", "Mask": "255.255.255.0" } }
```
(or a `routes` array, same as add). Match is by route **identity** — you can omit
`Description`. Response `200`:
```json
{
  "removed":   [ { "Kind": "ip", "Address": "10.8.0.0", "Mask": "255.255.255.0", "Description": "office" } ],
  "not_found": [],
  "ccd":       { "User": "alice", "CustomRoutes": [ ... full updated list ... ] }
}
```
Routes that weren't present come back in **`not_found`** (not an error) → also
**idempotent**.

### Set the whole route set — full replace

```
POST /api/user/ccd/apply
{
  "User": "alice",
  "ClientAddress": "dynamic",
  "RedirectGateway": false,
  "CustomRoutes": [
    { "Kind": "ip",     "Address": "10.8.0.0", "Mask": "255.255.255.0", "Description": "office" },
    { "Kind": "domain", "Domain": "internal.example.com", "Description": "app" }
  ]
}
```
`ClientAddress` is `"dynamic"` (pool-assigned) or a fixed IP. `RedirectGateway:
true` sends all of the user's traffic through the VPN. These two are **only**
settable via `apply` (the granular endpoints touch just `CustomRoutes`), so use
`apply` when you need to change the client address or the full-tunnel flag.

Any change (granular or full) rewrites the CCD and **disconnects the affected
session** so it reconnects with the new routes.

### Bulk import routes (from text)

```
POST /api/user/ccd/import
{ "username": "alice", "text": "example.com\n10.0.0.0/24\n1.2.3.4 255.255.0.0" }
```
Parses one route per line (`domain`, CIDR, `IP mask`, or bare IP → /32; `#`
comments ignored), appends the valid ones, skips duplicates. Returns
`{ "Added": [...], "Skipped": [...], "Errors": [ {"Line":N,"Reason":"..."} ] }`.
Handy for provisioning a user's routes in one call.

### Refresh a user's domain routes

```
POST /api/user/ccd/refresh
{ "username": "alice" }
```
Re-resolves every `domain` route in the user's CCD and rewrites it if any IP set
changed (kicking the user only when it did). Returns
`{ "changed": bool, "resolved": N, "failed": N }`. The server also does this on a
timer (`domain_refresh_interval_hours`); call this to force it immediately.

---

## Global routes (all users)

```
GET    /api/common-routes                 # list
POST   /api/common-routes                 # add     { "kind":"ip","address":"10.0.0.0","mask":"255.0.0.0","description":"corp" }
DELETE /api/common-routes/{id}            # remove by id (from the list)
POST   /api/common-routes/import          # bulk import  { "text": "example.com\n10.0.0.0/24" }
POST   /api/common-routes/refresh         # re-resolve all global domain routes now
```
`kind` is `"ip"` (with `address`+`mask`) or `"domain"` (with `domain`). These
apply to every active user on top of their per-user routes. `import` accepts the
same one-route-per-line text format as the per-user import and returns the same
`{Added,Skipped,Errors}` report; `refresh` re-resolves the global domain routes.

---

## Traffic (read)

```
GET /api/traffic                 # current month
GET /api/traffic?month=2026-06   # a specific month (YYYY-MM)
```
Returns `{ "month": "...", "months": ["2026-06", ...], "rows": [ { "user": "...",
"rx_bytes": N, "tx_bytes": N, "total_bytes": N, "all_time_bytes": N, "connected":
true, ... } ] }`. `rx_bytes` = client upload, `tx_bytes` = client download.

---

## End-to-end example (curl)

```bash
BASE=https://vpn.example.com
TOKEN=ovpnadm_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
auth=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")

# 1. create the user
curl -s "${auth[@]}" -X POST "$BASE/api/user/create" -d '{"username":"alice","password":""}'

# 2. give alice a personal route (granular — no read-modify-write needed)
curl -s "${auth[@]}" -X POST "$BASE/api/user/ccd/route/add" \
  -d '{"username":"alice","route":{"Kind":"ip","Address":"10.8.0.0","Mask":"255.255.255.0","Description":"office"}}'

# 2b. later, drop that one route (Description not needed to match)
curl -s "${auth[@]}" -X POST "$BASE/api/user/ccd/route/remove" \
  -d '{"username":"alice","route":{"Kind":"ip","Address":"10.8.0.0","Mask":"255.255.255.0"}}'

# 3. fetch the .ovpn to hand to the client
curl -s "${auth[@]}" -X POST "$BASE/api/user/config/show" -d '{"username":"alice"}' > alice.ovpn

# 4. later: revoke access
curl -s "${auth[@]}" -X POST "$BASE/api/user/revoke" -d '{"username":"alice"}'
```

---

## Notes for automation

- All write endpoints are idempotent-ish but not transactional; check the HTTP
  status and `{"error":...}` body.
- The token bypasses the MFA and forced-password-change gates by design (a service
  can do neither) but stays inside the scope above — it can never escalate.
- Keep the token out of logs and version control; rotate by create-new →
  switch → delete-old.

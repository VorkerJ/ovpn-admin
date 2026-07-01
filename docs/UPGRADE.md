# Upgrade guide: 2.0.19 → 2.0.36

This covers an in-place upgrade of a Docker-Compose deployment (the production
layout) from **2.0.19** to **2.0.36**. It was validated end-to-end on a local
copy of the production stack: MFA enrollment, admin login, users, PKI and CCD all
survive the upgrade.

> **TL;DR** — bump the image tags to `2.0.36`, `docker compose pull`, `up -d`.
> No `down -v`, no manual data migration. Your MFA and sessions are preserved
> automatically.

---

## Why upgrade (highlights 2.0.19 → 2.0.36)

- **[Critical security] MFA bypass fixed (v2.0.33).** In every release up to and
  including v2.0.32, anyone who knew the admin password could bypass the admin
  UI's 2FA entirely (an intermediate MFA token validated as a full session). If
  you have 2FA enabled, **upgrading is the fix.** All 2.0.x ≤ 2.0.32 are affected.
- **Per-user VPN password auth, managed from the UI (v2.0.34).** Optional password
  *on top of* the certificate — toggled in the Server tab, assigned per user. The
  `openvpn-user` verifier is now built into the image (no third-party download);
  `OVPN_PASSWD_AUTH` is no longer needed.
- **Per-user traffic, bucketed by month (v2.0.33).** A Traffic tab with a month
  picker and an all-time column; survives reconnects/restarts.
- **UI:** column sorting, a mobile card layout for the users table, and the
  selected tab persists across reloads.
- **Seamless auth-state migration (v2.0.35).** See below.
- **Granular per-user route API + CCD write hardening (v2.0.36).** New
  `POST /api/user/ccd/route/add` and `/remove` endpoints let a service account
  manage individual personal routes (idempotent) without the full-replace
  read-modify-write of `ccd/apply`. All CCD writes are now serialized to prevent
  lost updates from concurrent callers, and the management "kill" on the
  CCD-write path is bounded by a 5s timeout so it can't hang a request. See
  [`docs/API.md`](API.md).
- Hardening carried in the 2.0.20–2.0.32 line: forced first-login password
  change, durable auth state, native `openvpn-user` (own source), govulncheck CI.

Full detail per version is in [`CHANGELOG.md`](../CHANGELOG.md).

---

## What is preserved (verified)

| Data | Where | Survives upgrade? |
|---|---|---|
| PKI (CA, server + client certs, `index.txt`, CRL) | easyrsa volume/bind | ✅ |
| CCD (per-user routes) | ccd volume/bind | ✅ |
| Admin password (htpasswd) | `./auth/htpasswd` | ✅ |
| **MFA (TOTP) enrollment + backup codes** | state dir (`_mfa_secrets.json`) | ✅ (auto-migrated) |
| Admin sessions / signing key | state dir (`.session_signing_key`) | ✅ (auto-migrated) |
| API tokens, traffic history | state dir | ✅ (fresh on 2.0.19 — that release had neither) |

### The one thing that changed: the state directory

2.0.19 stored the session signing key and MFA secrets **next to the htpasswd
file** (e.g. `/mnt/auth`). Newer builds use a dedicated state directory
(`--session.state-dir`, default `/var/lib/ovpn-admin` in the shipped images).

On first start, 2.0.36 detects this and **copies the legacy files into the
configured state dir automatically** (never overwriting). You get a log line like:

```
legacy-migrate: imported _mfa_secrets.json from /mnt/auth
legacy-migrate: imported .session_signing_key from /mnt/auth
legacy-migrate: brought 2 auth-state file(s) forward ... — existing MFA/sessions preserved
```

Because of this, **both** upgrade paths are safe:

- **Keep your current compose** (no `OVPN_SESSION_STATE_DIR`): the state simply
  resolves to the htpasswd directory as before — nothing moves, nothing to do.
- **Adopt the newer compose** (sets `OVPN_SESSION_STATE_DIR=/var/lib/ovpn-admin`
  + a durable volume): the legacy files are migrated into it on first boot.

Either way, keep the state on **durable storage** (a bind mount or named volume in
Docker, a PVC in Kubernetes). On an ephemeral path a restart would drop MFA and
sessions.

---

## Docker-Compose upgrade steps

Assuming the production layout under `/opt/ovpn-admin` with image tags pinned in
`.env` (`OVPN_IMAGE` / `OVPN_ADMIN_IMAGE`):

```bash
ssh root@<backend>
cd /opt/ovpn-admin

# 1. (Optional but recommended) back up the auth state + PKI
tar czf ~/ovpn-admin-backup-$(date +%F).tgz auth/ /var/lib/ovpn-admin/easyrsa /var/lib/ovpn-admin/ccd

# 2. Point both images at 2.0.36
sed -i 's#:2\.0\.19#:2.0.36#g' .env     # adjust if your current tag differs

# 3. Pull and roll
docker compose pull
docker compose up -d                    # depends_on brings openvpn up first

# 4. Watch the logs come up clean
docker compose logs -f ovpn-admin | grep -iE 'migrate|MFA|Bind|fatal|error'
```

> ⚠️ **Do not run `docker compose down -v`** — that would delete the named volume
> holding the rendered `server.conf` (and any state on named volumes).

---

## Post-upgrade checklist

- [ ] Both containers `Up` (`docker compose ps`).
- [ ] `docker compose logs ovpn-admin` shows `Bind: http://0.0.0.0:8080/` and, if
      state moved, a `legacy-migrate: ... preserved` line. No `fatal`/`panic`.
- [ ] **Admin login still requires your 2FA code** (proves MFA was preserved, not
      dropped). Log in with password + TOTP.
- [ ] Users list is intact; an existing client's `.ovpn` still connects.
- [ ] OpenVPN is serving (an existing client connects; `index.txt` unchanged).

---

## Rollback

The upgrade doesn't rewrite PKI, CCD, htpasswd, or the MFA/session files (it only
*copies* legacy files forward, never deletes). To roll back, point the tags back
at your previous version and `docker compose up -d`. If you took the backup in
step 1, restore it first.

---

## Kubernetes (Helm)

Bump `image.tag` / `Chart.appVersion` to `2.0.36` and `helm upgrade`. **Set
`persistence.enabled=true`** (see [`charts/openvpn-admin/values.yaml`](../charts/openvpn-admin/values.yaml))
so the state dir is a PVC — otherwise a pod restart drops MFA, sessions, API
tokens and traffic history. The same auto-migration runs on first start.

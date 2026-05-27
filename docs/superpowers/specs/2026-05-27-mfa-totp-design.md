# MFA/TOTP for ovpn-admin — Design Spec

## Goal

Add optional two-factor authentication (TOTP) to the admin UI so that admin accounts can be protected beyond a single password.

## Constraints

- TOTP only (RFC 6238) — Google Authenticator, Authy, 1Password compatible
- Optional per-admin — admins who don't enable TOTP log in with password only
- Storage: SQLite database file (new `admin_mfa` table)
- No external dependencies (no Authelia, no Keycloak, no Telegram bot)
- Backup codes for device-loss recovery
- Must not break existing htpasswd-based auth flow

## Architecture

### Two-Step Login Flow

```
Client                         Server
  │                              │
  ├─ POST /api/login             │
  │  {username, password}        │
  │                              ├─ validate credentials
  │                              ├─ check: user has TOTP enabled?
  │                              │
  │  ◄── if NO TOTP ────────────┤  → set session cookie, return {ok:true}
  │                              │
  │  ◄── if TOTP enabled ───────┤  → return {mfa_required:true, mfa_token:"<temp>"}
  │                              │     (mfa_token: HMAC-signed, 5 min TTL, not a session)
  │                              │
  ├─ POST /api/login/mfa         │
  │  {mfa_token, code}           │
  │                              ├─ verify mfa_token signature + TTL
  │                              ├─ verify TOTP code (±1 window)
  │                              ├─ OR verify backup code (one-time)
  │                              │
  │  ◄── success ────────────────┤  → set session cookie, return {ok:true}
  │  ◄── failure ────────────────┤  → 401, rate-limited
```

### TOTP Setup Flow

```
Client                         Server
  │                              │
  ├─ POST /api/mfa/setup         │  (requires active session)
  │                              ├─ generate TOTP secret (20 bytes, base32)
  │                              ├─ store in admin_mfa with enabled=0
  │  ◄───────────────────────────┤  → {secret, qr_url} (otpauth:// URI)
  │                              │
  │  [user scans QR in app]      │
  │                              │
  ├─ POST /api/mfa/confirm       │
  │  {code: "123456"}            │
  │                              ├─ verify code against stored secret
  │                              ├─ set enabled=1
  │                              ├─ generate 8 backup codes
  │  ◄───────────────────────────┤  → {backup_codes: ["XXXX-XXXX", ...]}
  │                              │
  │  [user saves backup codes]   │
```

### TOTP Disable Flow

```
  ├─ DELETE /api/mfa             │
  │  {code: "123456"}            │  (requires active session + valid TOTP code)
  │                              ├─ verify code
  │                              ├─ delete admin_mfa row
  │  ◄───────────────────────────┤  → {ok:true}
```

## API Endpoints

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| POST | `/api/login` | none | `{username, password}` | `{ok:true}` or `{mfa_required:true, mfa_token:"..."}` |
| POST | `/api/login/mfa` | none | `{mfa_token, code}` | `{ok:true}` + set cookie |
| GET | `/api/mfa/status` | session | — | `{enabled:bool}` |
| POST | `/api/mfa/setup` | session | — | `{secret, qr_url}` |
| POST | `/api/mfa/confirm` | session | `{code}` | `{backup_codes:[...]}` |
| DELETE | `/api/mfa` | session | `{code}` | `{ok:true}` |

## Storage

### SQLite Table

```sql
CREATE TABLE IF NOT EXISTS admin_mfa (
    username     TEXT PRIMARY KEY,
    totp_secret  TEXT NOT NULL,
    enabled      INTEGER DEFAULT 0,
    backup_codes TEXT DEFAULT '[]',
    created_at   TEXT DEFAULT (datetime('now'))
);
```

- `totp_secret`: base32-encoded 20-byte secret (encrypted at rest with a key derived from session secret)
- `enabled`: 0 = setup started but not confirmed, 1 = active
- `backup_codes`: JSON array of bcrypt-hashed one-time codes

### CLI Flag

```
--mfa.db-path    path to MFA SQLite database (default: alongside htpasswd or ./mfa.db)
                 env: OVPN_MFA_DB_PATH
```

## Backup Codes

- 8 codes, format `XXXX-XXXX` (alphanumeric, crypto/rand)
- Stored as bcrypt hashes (same as passwords)
- Each code is one-time — deleted after successful use
- Shown to user ONCE during setup confirmation
- Using a backup code counts as valid MFA (no different from TOTP code in the flow)

## MFA Token (Intermediate)

The `mfa_token` returned after password validation is NOT a session — it only authorizes the `/api/login/mfa` endpoint. Structure:

```
HMAC-SHA256(base64({user: "admin", exp: now+5min, purpose: "mfa"}), sessionSecret)
```

Same signing mechanism as session tokens but with a 5-minute TTL and a `purpose` field that distinguishes it from session tokens.

## Security Considerations

- TOTP secrets encrypted at rest in SQLite (AES-256-GCM, key from session secret)
- Backup codes bcrypt-hashed (not reversible)
- MFA token has 5-min TTL — limits brute-force window on the TOTP code
- Rate limiting applies to `/api/login/mfa` (same per-IP limiter as login)
- TOTP verification uses ±1 time window (30-sec periods) to tolerate clock skew
- Disabling MFA requires a valid TOTP code (or backup code) — prevents unauthorized disable

## Frontend Changes

### LoginPage.vue

After password submit, if response has `mfa_required: true`:
- Show a 6-digit code input field (numeric, autofocus)
- Submit to `/api/login/mfa` with the `mfa_token`
- On success: proceed as normal (cookie set, redirect)

### MfaSetupModal.vue (new)

- Triggered from AppHeader "2FA" button (shield icon)
- Step 1: show QR code (rendered client-side from `qr_url` using a JS library or `<img>` with a QR API)
- Step 2: user enters 6-digit code to confirm
- Step 3: display backup codes with "copy" button + warning

### AppHeader.vue

- Add shield icon button next to logout
- Shows MFA status (enabled/disabled)
- Opens MfaSetupModal

## Dependencies

### Go
- `github.com/pquerna/otp` — TOTP generation and verification (well-maintained, 3k+ stars)
- `modernc.org/sqlite` — pure-Go SQLite driver (no CGO, already compatible with the build)

### Frontend
- `qrcode` npm package (or inline SVG generation) for QR code display

## Files to Create/Modify

### Backend
- **Create:** `totp.go` (~250 lines) — TOTP setup/verify/backup logic, SQLite CRUD, MFA token signing
- **Modify:** `auth.go` (~30 lines) — two-step login flow in `loginHandler`, new MFA handlers
- **Modify:** `main.go` (~10 lines) — CLI flag, route registration

### Frontend
- **Create:** `frontend/src/components/modals/MfaSetupModal.vue` (~150 lines)
- **Modify:** `frontend/src/components/LoginPage.vue` (~40 lines) — MFA code step
- **Modify:** `frontend/src/components/AppHeader.vue` (~10 lines) — 2FA button
- **Modify:** `frontend/src/api.js` (~20 lines) — new API functions

## Testing

- Unit tests for TOTP verify (valid code, expired code, wrong code, ±1 window)
- Unit tests for backup codes (generate, verify, one-time use)
- Unit tests for MFA token signing/verification
- Integration test: full login flow with MFA
- Integration test: setup → confirm → login → disable cycle

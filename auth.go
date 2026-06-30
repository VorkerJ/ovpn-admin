package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "ovpn_admin_session"
	sessionTTL        = 12 * time.Hour

	// adminBcryptCost bumps above bcrypt.DefaultCost (10) to align with the
	// OWASP Password Storage Cheat Sheet recommendation for newly deployed
	// systems. ~250ms per op on a modern x86 core — acceptable for admin
	// login frequency and meaningful against offline brute force if the
	// htpasswd file ever leaks.
	adminBcryptCost = 12
)

// htpasswdUsers хранит распарсенные записи: username -> bcrypt hash
var htpasswdUsers map[string]string

// adminAuthMu guards htpasswdUsers and adminPasswordMustChange. Needed because
// the runtime admin-password-change path mutates the map while
// validateCredentials reads it concurrently on every login.
var adminAuthMu sync.RWMutex

// adminPasswordMustChange is true when the admin is authenticated with an
// auto-generated temporary password. Until it is changed, requireAuth blocks
// every endpoint except the change-password / auth-check / settings allowlist,
// so a temp password leaked via logs can't be used to actually operate the
// portal (and the legit admin is forced to rotate it on first login).
var adminPasswordMustChange bool

// authStateDir is the resolved writable dir for persistent state (signing key,
// blacklist, admin password, traffic totals). Set by initAuth; reused by other
// subsystems (e.g. traffic accounting) that need durable storage on the PVC.
var authStateDir string

// adminHtpasswdPersistPath is where a runtime admin-password change is written.
// When ADMIN_HTPASSWD_FILE is set it points at that file; otherwise at a
// sibling of the session-state dir for best-effort durability across restarts.
var adminHtpasswdPersistPath string

const adminPasswordMinLength = 12

// revokedTokens — blacklist токенов после логаута (hmac → expiry)
var revokedTokens = map[string]int64{}
var revokedTokensMu sync.Mutex
var revokedTokensFile string

// sessionSigningKey is a 64-byte random key persisted to disk. It signs
// session and MFA tokens, and is the input to the MFA-secret encryption key.
// Decoupled from htpasswd so that a password change does not invalidate
// every active session globally.
var sessionSigningKey []byte
var sessionSigningKeyFile string

// trustedProxies holds CIDRs of reverse proxies whose X-Forwarded-For headers
// we honor when extracting the real client IP for rate limiting.
var trustedProxies []string

// ── Login rate limiting ──────────────────────────────────────────────────────

var (
	loginAttempts        sync.Map // map[string]*loginTracker
	maxLoginAttempts     = 5
	loginLockoutDuration = 15 * time.Minute
)

type loginTracker struct {
	mu       sync.Mutex
	failures int
	lockedAt time.Time
}

// checkLoginRateLimitKey returns false if the given key (IP or "user:<name>")
// is currently locked out.
func checkLoginRateLimitKey(key string) bool {
	val, _ := loginAttempts.LoadOrStore(key, &loginTracker{})
	tracker := val.(*loginTracker)
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if !tracker.lockedAt.IsZero() && time.Since(tracker.lockedAt) < loginLockoutDuration {
		return false
	}
	if !tracker.lockedAt.IsZero() && time.Since(tracker.lockedAt) >= loginLockoutDuration {
		tracker.failures = 0
		tracker.lockedAt = time.Time{}
	}
	return true
}

// checkLoginRateLimit checks both the per-IP and (optionally) per-username
// trackers. Either one being locked out denies the request — this prevents a
// single bad IP from locking out an entire user account, while still capping
// brute force from any one source.
func checkLoginRateLimit(ip string, usernames ...string) bool {
	if !checkLoginRateLimitKey(ip) {
		return false
	}
	for _, u := range usernames {
		if u == "" {
			continue
		}
		if !checkLoginRateLimitKey("user:" + u) {
			return false
		}
	}
	return true
}

func bumpFailures(key string) {
	val, _ := loginAttempts.LoadOrStore(key, &loginTracker{})
	tracker := val.(*loginTracker)
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.failures++
	if tracker.failures >= maxLoginAttempts {
		tracker.lockedAt = time.Now()
		log.Warnf("Login rate limit: key %s locked out for %v after %d failures", key, loginLockoutDuration, tracker.failures)
	}
}

func recordLoginFailure(ip string, usernames ...string) {
	bumpFailures(ip)
	for _, u := range usernames {
		if u != "" {
			bumpFailures("user:" + u)
		}
	}
}

func recordLoginSuccess(ip string, usernames ...string) {
	loginAttempts.Delete(ip)
	for _, u := range usernames {
		if u != "" {
			loginAttempts.Delete("user:" + u)
		}
	}
}

// clientIP returns the originating client IP for r. If the connecting peer is
// a trusted reverse proxy, the leftmost X-Forwarded-For entry is returned;
// otherwise the direct peer address is used. Loopback is always trusted so
// SSH-tunnel deployments keep working out of the box.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if isTrustedProxy(host) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			candidate := strings.TrimSpace(parts[0])
			if candidate != "" {
				return candidate
			}
		}
	}
	return host
}

func isTrustedProxy(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	if parsedIP.IsLoopback() {
		return true
	}
	for _, entry := range trustedProxies {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			if parsedIP.Equal(net.ParseIP(entry)) {
				return true
			}
			continue
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// setTrustedProxies parses a comma-separated list of CIDRs/IPs and stores
// them for isTrustedProxy. Invalid entries are logged and skipped — a typo
// should not bring the server down.
func setTrustedProxies(spec string) {
	trustedProxies = nil
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				log.Warnf("trusted-proxies: ignoring invalid CIDR %q: %v", entry, err)
				continue
			}
		} else if net.ParseIP(entry) == nil {
			log.Warnf("trusted-proxies: ignoring invalid IP %q", entry)
			continue
		}
		trustedProxies = append(trustedProxies, entry)
	}
}

// loadRevokedTokens reads the persisted blacklist from disk, discarding expired entries.
func loadRevokedTokens() {
	if revokedTokensFile == "" {
		return
	}
	data, err := os.ReadFile(revokedTokensFile)
	if err != nil {
		return // file doesn't exist yet — that's fine
	}
	revokedTokensMu.Lock()
	defer revokedTokensMu.Unlock()
	_ = json.Unmarshal(data, &revokedTokens)
	now := time.Now().Unix()
	for token, exp := range revokedTokens {
		if exp < now {
			delete(revokedTokens, token)
		}
	}
}

// saveRevokedTokens writes the current blacklist to disk.
func saveRevokedTokens() {
	if revokedTokensFile == "" {
		return
	}
	revokedTokensMu.Lock()
	data, _ := json.Marshal(revokedTokens)
	revokedTokensMu.Unlock()
	// Atomic write — a torn write here corrupts the JSON blacklist; on next
	// boot loadRevokedTokens would silently lose the entire list, letting
	// previously-revoked sessions reactivate until their natural TTL expires.
	if err := writeFileAtomicSecret(revokedTokensFile, data); err != nil {
		log.Warnf("failed to persist revoked tokens: %v", err)
	}
}

// initAuth загружает htpasswd-файл или генерирует временные credentials.
// Вызывается после kingpin.Parse().
func initAuth() {
	htpasswdUsers = make(map[string]string)

	// stateDir holds the session signing key, the logout blacklist and (in
	// no-htpasswd mode) the persisted admin password. An explicit
	// --session.state-dir (e.g. a writable PVC in k8s) decouples this from the
	// htpasswd directory, which is typically a read-only Secret mount — writing
	// the signing key there would otherwise crash the process on startup.
	stateDir := *sessionStateDir

	if *adminHtpasswdFile != "" {
		if err := loadHtpasswd(*adminHtpasswdFile); err != nil {
			log.Fatalf("Не удалось загрузить htpasswd-файл %s: %v", *adminHtpasswdFile, err)
		}
		log.Infof("Авторизация: загружено %d пользователей из %s", len(htpasswdUsers), *adminHtpasswdFile)
		// Operator chose the password — no forced rotation; persist changes back
		// to the same file.
		adminHtpasswdPersistPath = *adminHtpasswdFile
		if stateDir == "" {
			stateDir = filepath.Dir(*adminHtpasswdFile)
		}
	} else {
		if stateDir == "" {
			stateDir = "/tmp"
		}
		adminHtpasswdPersistPath = filepath.Join(stateDir, ".ovpn-admin-admin.htpasswd")
		// Reuse a previously self-changed password if it survived (e.g. the
		// state dir is on a mounted PVC) so we don't regenerate a temp password
		// — and don't re-trigger the forced change — on every restart.
		//
		// SECURITY: the default state dir is /tmp (world-writable, sticky).
		// Only trust the file if it is a regular file, owned by our uid, and
		// not group/world-accessible — otherwise a local user could plant a
		// htpasswd with an attacker-known hash and we'd silently adopt it (and
		// skip the forced change). On any mismatch we ignore it and regenerate.
		loaded := false
		if isOwnerOnlyCredFile(adminHtpasswdPersistPath) {
			if err := loadHtpasswd(adminHtpasswdPersistPath); err == nil && len(htpasswdUsers) > 0 {
				log.Infof("Авторизация: загружен ранее сохранённый пароль admin из %s", adminHtpasswdPersistPath)
				loaded = true
			}
		}
		if !loaded {
			htpasswdUsers = make(map[string]string)
			// Файл не задан — генерируем временный пароль для admin
			pass := generatePassword(16)
			hash, err := bcrypt.GenerateFromPassword([]byte(pass), adminBcryptCost)
			if err != nil {
				log.Fatalf("Ошибка генерации пароля: %v", err)
			}
			htpasswdUsers["admin"] = string(hash)
			adminPasswordMustChange = true
			log.Warnf("ADMIN_HTPASSWD_FILE не задан. Временный пароль для admin: %s", pass)
			log.Warn("ВАЖНО: при первом входе пароль нужно будет сразу сменить — до смены остальные действия заблокированы.")
			log.Warn("Для постоянных учётных данных создайте htpasswd-файл и задайте ADMIN_HTPASSWD_FILE.")
		}
	}

	authStateDir = stateDir

	// Legacy migration: builds before --session.state-dir kept the auth state
	// next to the htpasswd file. When an explicit state-dir is now configured
	// (e.g. the shipped compose sets OVPN_SESSION_STATE_DIR=/var/lib/ovpn-admin)
	// and it doesn't yet hold that state, copy the legacy files over ONCE — so an
	// in-place image upgrade doesn't silently drop the admin's MFA enrollment,
	// session signing key, logout blacklist, API tokens or traffic history.
	if *adminHtpasswdFile != "" {
		migrateLegacyAuthState(stateDir, filepath.Dir(*adminHtpasswdFile))
	}

	revokedTokensFile = filepath.Join(stateDir, ".session_blacklist.json")

	// Persistent session signing key — survives restarts and password changes,
	// rotates only when the file is deleted by the operator.
	sessionSigningKeyFile = filepath.Join(stateDir, ".session_signing_key")
	if err := loadOrGenerateSigningKey(); err != nil {
		log.Fatalf("Failed to init session signing key: %v", err)
	}

	loadRevokedTokens()

	// Bound memory growth of the loginAttempts map. Entries are created on
	// every distinct IP and per-username key; without the janitor a constant
	// trickle of failed logins from unique IPs leaks ~256 bytes forever.
	go loginAttemptsJanitor()
}

// migrateLegacyAuthState performs a one-time copy of persistent auth state from
// a legacy directory (where pre-state-dir builds stored it, next to the htpasswd
// file) into the configured state-dir — but only for files the state-dir does
// not already have, and it never overwrites. This keeps an in-place upgrade to a
// build that defaults to a separate state-dir seamless: MFA enrollment, session
// signing key, logout blacklist, API tokens and traffic history are preserved
// instead of silently reset.
func migrateLegacyAuthState(stateDir, legacyDir string) {
	if stateDir == "" || legacyDir == "" || stateDir == legacyDir {
		return
	}
	if _, err := os.Stat(legacyDir); err != nil {
		return
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		log.Warnf("legacy-migrate: cannot create state dir %s: %v", stateDir, err)
		return
	}
	// traffic.db is intentionally omitted: copying a live SQLite db + WAL/SHM
	// risks an inconsistent snapshot. The legacy JSON (traffic.json) is copied
	// instead and folded into the new db on first start.
	files := []string{
		"_mfa_secrets.json",
		".session_signing_key",
		".session_blacklist.json",
		"api_tokens.json",
		"traffic.json",
		".ovpn-admin-admin.htpasswd",
	}
	migrated := 0
	for _, f := range files {
		if ok, err := copyFileIfAbsent(filepath.Join(legacyDir, f), filepath.Join(stateDir, f)); err != nil {
			log.Warnf("legacy-migrate: copy %s failed: %v", f, err)
		} else if ok {
			migrated++
			log.Infof("legacy-migrate: imported %s from %s", f, legacyDir)
		}
	}
	if migrated > 0 {
		log.Infof("legacy-migrate: brought %d auth-state file(s) forward from %s into %s — existing MFA/sessions preserved", migrated, legacyDir, stateDir)
	}
}

// copyFileIfAbsent copies src to dst only if dst does not exist and src does.
// Returns (true, nil) when a copy happened. Never overwrites an existing dst.
func copyFileIfAbsent(src, dst string) (bool, error) {
	if _, err := os.Stat(dst); err == nil {
		return false, nil // state-dir already has it
	}
	info, err := os.Stat(src)
	if err != nil {
		return false, nil // legacy file absent — nothing to do
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(dst, data, info.Mode().Perm()); err != nil {
		return false, err
	}
	return true, nil
}

// loginAttemptsJanitor periodically evicts stale or expired loginTracker
// entries from loginAttempts so the map does not grow without bound.
//
// An entry is considered evictable when either:
//   - no failures have been recorded and the tracker is not currently locked
//     (a defensive race remnant — e.g. LoadOrStore landed but bumpFailures
//     never followed), OR
//   - the lockout window has elapsed and bumpFailures cleared the counters
//     (rare since checkLoginRateLimitKey already does opportunistic reset on
//     the read path, but this catches keys that are never read again).
func loginAttemptsJanitor() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		loginAttempts.Range(func(k, v interface{}) bool {
			tracker := v.(*loginTracker)
			tracker.mu.Lock()
			stale := tracker.failures == 0 && tracker.lockedAt.IsZero()
			expired := !tracker.lockedAt.IsZero() &&
				now.Sub(tracker.lockedAt) > loginLockoutDuration &&
				tracker.failures == 0
			tracker.mu.Unlock()
			if stale || expired {
				loginAttempts.Delete(k)
			}
			return true
		})
	}
}

// loadOrGenerateSigningKey loads a 64-byte signing key from disk, or generates
// and persists a fresh one on first start. Permissions are tightened to 0600
// on a 0700 directory because the key is equivalent to all active sessions.
//
// If the file exists but has the wrong length we FAIL LOUD rather than silently
// regenerating. A corrupted (or truncated) key file would otherwise rotate the
// session/MFA secret on every boot, invalidating all sessions AND breaking
// decryption of stored MFA secrets (mfaEncKey derives from the signing key).
// Operator must explicitly delete the file to opt into rotation.
func loadOrGenerateSigningKey() error {
	data, err := os.ReadFile(sessionSigningKeyFile)
	if err == nil {
		if len(data) == 64 {
			sessionSigningKey = data
			return nil
		}
		return fmt.Errorf("signing key file %s has invalid length %d (expected 64); delete the file to rotate the key", sessionSigningKeyFile, len(data))
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("read signing key: %w", err)
	}
	// File doesn't exist — generate a fresh key.
	sessionSigningKey = make([]byte, 64)
	if _, err := rand.Read(sessionSigningKey); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(sessionSigningKeyFile), 0o700); err != nil {
		return err
	}
	// Atomic write: a torn write would leave a short file behind, and the
	// length check in loadOrGenerateSigningKey would refuse to start until
	// the operator manually deletes the file.
	return writeFileAtomicSecret(sessionSigningKeyFile, sessionSigningKey)
}

// loadHtpasswd читает файл формата Apache htpasswd (username:hash, по одной записи на строку).
//
// Hashes that are not bcrypt (`$2a/$2b/$2y$`) — i.e. legacy crypt, SHA, MD5,
// plaintext — are rejected: htpasswd accepts them but they are unacceptably
// weak for an admin UI. We also warn (but accept) bcrypt entries whose cost
// is below the OWASP-recommended floor of 12, so the operator gets actionable
// signal without forcing a re-issue.
func loadHtpasswd(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		user, hash := parts[0], parts[1]
		if !isBcryptHash(hash) {
			log.Warnf("htpasswd: skipping %q — only bcrypt hashes are accepted (use `htpasswd -B` to generate)", user)
			continue
		}
		if cost, err := bcrypt.Cost([]byte(hash)); err == nil && cost < adminBcryptCost {
			log.Warnf("htpasswd: user %q uses bcrypt cost %d — below recommended minimum %d. Rehash with `htpasswd -B -C %d`.",
				user, cost, adminBcryptCost, adminBcryptCost)
		}
		htpasswdUsers[user] = hash
	}
	return scanner.Err()
}

// isBcryptHash reports whether s looks like a bcrypt modular crypt string.
// Apache htpasswd uses the $2y$ prefix; Go's bcrypt library accepts $2a$/$2b$.
// All three variants are interoperable in the bcrypt comparison routine.
func isBcryptHash(s string) bool {
	return strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$")
}

// dummyBcryptHash is computed once at process start so that validateCredentials
// can run a bcrypt comparison even for unknown usernames. Without this, an
// early `return false` on missing user leaks a ~100ms timing oracle that lets
// an attacker enumerate valid accounts.
var dummyBcryptHash = func() string {
	h, err := bcrypt.GenerateFromPassword([]byte("dummy"), adminBcryptCost)
	if err != nil {
		// bcrypt.GenerateFromPassword only errors on absurd cost values.
		// Fall back to an empty string — the subsequent CompareHashAndPassword
		// will always fail-fast, which still costs ~constant time relative to
		// a real hash mismatch (both are fast paths).
		return ""
	}
	return string(h)
}()

func validateCredentials(username, password string) bool {
	adminAuthMu.RLock()
	hash, ok := htpasswdUsers[username]
	adminAuthMu.RUnlock()
	if !ok {
		// Run bcrypt against a dummy hash so the timing of the "unknown user"
		// path matches the "wrong password" path. Result discarded.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ── Session ───────────────────────────────────────────────────────────────────

type sessionPayload struct {
	User    string `json:"u"`
	Exp     int64  `json:"exp"`
	Purpose string `json:"p,omitempty"`
}

func signSession(user string) string {
	secret := sessionSecret()
	p := sessionPayload{
		User:    user,
		Exp:     time.Now().Add(sessionTTL).Unix(),
		Purpose: "session",
	}
	data, _ := json.Marshal(p)
	enc := base64.RawURLEncoding.EncodeToString(data)
	mac := computeHMAC(enc, secret)
	return enc + "." + mac
}

func verifySession(token string) (string, bool) {
	secret := sessionSecret()
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	enc, mac := parts[0], parts[1]
	if !hmac.Equal([]byte(computeHMAC(enc, secret)), []byte(mac)) {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", false
	}
	var p sessionPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", false
	}
	// Require an explicit session purpose. An intermediate MFA token serializes
	// its purpose under a different JSON key ("purpose" vs our "p"), so it parses
	// here as Purpose=="" — accepting empty would let that token (issued after
	// only the first factor) pass as a full session and defeat MFA entirely.
	// Legacy empty-purpose tokens (pre-dating this field) are intentionally no
	// longer accepted; their holders simply re-login.
	if p.Purpose != "session" {
		return "", false
	}
	if time.Now().Unix() > p.Exp {
		return "", false
	}
	// Проверяем blacklist (токен отозван при логауте)
	revokedTokensMu.Lock()
	_, revoked := revokedTokens[mac]
	revokedTokensMu.Unlock()
	if revoked {
		return "", false
	}
	return p.User, true
}

// revokeToken добавляет токен в blacklist до истечения его TTL.
func revokeToken(token string) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return
	}
	enc, mac := parts[0], parts[1]
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return
	}
	var p sessionPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return
	}
	revokedTokensMu.Lock()
	revokedTokens[mac] = p.Exp
	// Очищаем просроченные записи
	now := time.Now().Unix()
	for k, exp := range revokedTokens {
		if now > exp {
			delete(revokedTokens, k)
		}
	}
	revokedTokensMu.Unlock()

	saveRevokedTokens()
}

// sessionSecret returns the HMAC signing key as a base64 string. The key is
// loaded from disk on startup (or generated on first start), so it survives
// restarts but is decoupled from htpasswd — changing a password no longer
// invalidates every session. Rotation is done by deleting the key file.
func sessionSecret() string {
	return base64.RawURLEncoding.EncodeToString(sessionSigningKey)
}

func computeHMAC(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// mfaTokenSecret derives a key distinct from the session-signing secret, so an
// intermediate MFA token is signed under a different key than a session cookie.
// This is domain separation: even if a purpose check were bypassed, an MFA
// token's MAC cannot validate in verifySession (and vice-versa), because the
// keys differ. Both derive from the same root signing key.
func mfaTokenSecret() string {
	return computeHMAC("ovpn-admin/mfa-token/v1", sessionSecret())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// loginHandler POST /api/login  body: {"username":"…","password":"…"}
//
// Method check is enforced by the requireMethod middleware at route
// registration time; do not re-check r.Method here.
func (oAdmin *OvpnAdmin) loginHandler(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}
	user := req.Username
	pass := req.Password

	if !checkLoginRateLimit(ip, user) {
		writeJSONError(w, http.StatusTooManyRequests, "too many login attempts, try again later")
		return
	}

	if !validateCredentials(user, pass) {
		recordLoginFailure(ip, user)
		time.Sleep(500 * time.Millisecond) // замедление брутфорса
		writeJSONError(w, http.StatusUnauthorized, "неверный логин или пароль")
		return
	}

	// If MFA is required, we MUST NOT clear the rate-limit counters yet —
	// otherwise an attacker who has already learned the password can repeatedly
	// re-login (each call resets the counter) and brute-force the second factor
	// without ever tripping the lockout. The success path is intentionally
	// delayed until mfaLoginHandler verifies the TOTP/backup code.
	if oAdmin.mfaStore != nil && oAdmin.mfaStore.isEnabled(user) {
		mfaToken := signMfaToken(user)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mfa_required": true,
			"mfa_token":    mfaToken,
		})
		return
	}

	// No MFA: full authentication achieved, safe to clear the counters.
	recordLoginSuccess(ip, user)

	token := signSession(user)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   !*insecureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":   true,
		"user": user,
	})
}

// logoutHandler POST /api/logout
//
// Public route (no requireAuth wrapper). If a session cookie is present and
// parseable we revoke it; the response always clears the cookie so a stale or
// malformed session does not leave the browser stuck logged in.
//
// Method check is enforced by the requireMethod middleware.
func (oAdmin *OvpnAdmin) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		revokeToken(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   !*insecureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// authCheckHandler GET /api/auth/check — 200 if authenticated, 401 otherwise
func (oAdmin *OvpnAdmin) authCheckHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// requireAuth middleware — проверяет сессионную cookie.
func (oAdmin *OvpnAdmin) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Service-account API token (non-interactive integrations). It bypasses
		// the MFA and forced-password-change gates — a service can do neither —
		// but is restricted to user/route management by apiTokenPathAllowed.
		if tok := bearerToken(r); tok != "" {
			if oAdmin.apiTokens == nil {
				writeJSONError(w, http.StatusUnauthorized, "invalid API token")
				return
			}
			at, ok := oAdmin.apiTokens.verify(tok)
			if !ok {
				writeJSONError(w, http.StatusUnauthorized, "invalid API token")
				return
			}
			if !apiTokenPathAllowed(r.URL.Path) {
				writeJSONError(w, http.StatusForbidden, "this API token is limited to user and route management")
				return
			}
			oAdmin.apiTokens.touch(at.ID)
			next(w, withServiceAccount(r, at.Name))
			return
		}

		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if _, ok := verifySession(cookie.Value); !ok {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		// Forced-password-change gate: while the admin is on a temporary
		// password, only the change-password flow (plus auth-check/settings so
		// the UI can render that screen) is reachable. Everything else — and
		// /metrics — is held until the password is rotated.
		if adminPasswordChangeRequired() && !passwordChangeAllowed(r.URL.Path) {
			writeJSONError(w, http.StatusPreconditionFailed, "password change required")
			return
		}
		next(w, r)
	}
}

// adminPasswordChangeRequired reports whether the admin must rotate a temporary
// password before any other action is allowed.
func adminPasswordChangeRequired() bool {
	adminAuthMu.RLock()
	defer adminAuthMu.RUnlock()
	return adminPasswordMustChange
}

// passwordChangeAllowed is the allowlist of endpoints reachable while the
// forced-password-change gate is active. Matched by suffix so the base-URL
// prefix doesn't matter.
func passwordChangeAllowed(path string) bool {
	for _, suffix := range []string{
		"api/admin/change-password",
		"api/auth/check",
		"api/server/settings",
		"api/logout",
	} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

// adminChangePasswordHandler POST /api/admin/change-password — rotates the
// admin's own password. Requires the current password (so a hijacked session
// alone can't lock the real admin out) and clears the forced-change gate.
//
// Method check is enforced by the requireMethod middleware; the session is
// verified by requireAuth.
func (oAdmin *OvpnAdmin) adminChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	user := oAdmin.sessionUser(r)
	if user == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if !validateCredentials(user, req.CurrentPassword) {
		time.Sleep(500 * time.Millisecond) // замедление перебора текущего пароля
		writeJSONError(w, http.StatusUnauthorized, "неверный текущий пароль")
		return
	}
	if err := validateAdminPassword(req.NewPassword); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.NewPassword == req.CurrentPassword {
		writeJSONError(w, http.StatusBadRequest, "новый пароль должен отличаться от текущего")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), adminBcryptCost)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "не удалось захешировать пароль")
		return
	}
	adminAuthMu.Lock()
	htpasswdUsers[user] = string(hash)
	adminPasswordMustChange = false
	adminAuthMu.Unlock()

	if err := saveAdminHtpasswd(adminHtpasswdPersistPath); err != nil {
		// Non-fatal: the change is live in memory for this process. Surface it
		// so the operator knows it won't survive a restart.
		log.Warnf("admin password changed in memory but failed to persist to %s: %v", adminHtpasswdPersistPath, err)
	} else {
		log.Infof("admin password changed and persisted to %s", adminHtpasswdPersistPath)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// validateAdminPassword enforces a minimum length for the admin UI password.
func validateAdminPassword(p string) error {
	if len([]rune(p)) < adminPasswordMinLength {
		return fmt.Errorf("пароль слишком короткий: минимум %d символов", adminPasswordMinLength)
	}
	return nil
}

// isOwnerOnlyCredFile reports whether path is safe to load admin credentials
// from: a regular file, owned by our effective uid, with no group/world
// permission bits. Guards the /tmp persist path against a planted-file attack.
func isOwnerOnlyCredFile(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false // missing/unreadable — treat as "no persisted password"
	}
	if !fi.Mode().IsRegular() {
		log.Warnf("persisted admin cred %s is not a regular file — ignoring", path)
		return false
	}
	if fi.Mode().Perm()&0o077 != 0 {
		log.Warnf("persisted admin cred %s is group/world-accessible (%#o) — ignoring and regenerating temp password", path, fi.Mode().Perm())
		return false
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		log.Warnf("persisted admin cred %s not owned by current uid — ignoring and regenerating temp password", path)
		return false
	}
	return true
}

// saveAdminHtpasswd persists the current htpasswd map to disk atomically with
// 0600 perms, so a self-changed admin password survives a restart.
func saveAdminHtpasswd(path string) error {
	if path == "" {
		return fmt.Errorf("персист-путь не сконфигурирован")
	}
	adminAuthMu.RLock()
	var b strings.Builder
	for u, h := range htpasswdUsers {
		b.WriteString(u)
		b.WriteByte(':')
		b.WriteString(h)
		b.WriteByte('\n')
	}
	adminAuthMu.RUnlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomicSecret(path, []byte(b.String()))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const passwordChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generatePassword(length int) string {
	buf := make([]byte, length)
	for i := range buf {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(passwordChars))))
		buf[i] = passwordChars[n.Int64()]
	}
	return string(buf)
}

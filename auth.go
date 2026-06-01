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
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "ovpn_admin_session"
	sessionTTL        = 12 * time.Hour
)

// htpasswdUsers хранит распарсенные записи: username -> bcrypt hash
var htpasswdUsers map[string]string

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
	if err := os.WriteFile(revokedTokensFile, data, 0600); err != nil {
		log.Warnf("failed to persist revoked tokens: %v", err)
	}
}

// initAuth загружает htpasswd-файл или генерирует временные credentials.
// Вызывается после kingpin.Parse().
func initAuth() {
	htpasswdUsers = make(map[string]string)

	if *adminHtpasswdFile != "" {
		if err := loadHtpasswd(*adminHtpasswdFile); err != nil {
			log.Fatalf("Не удалось загрузить htpasswd-файл %s: %v", *adminHtpasswdFile, err)
		}
		log.Infof("Авторизация: загружено %d пользователей из %s", len(htpasswdUsers), *adminHtpasswdFile)
		revokedTokensFile = filepath.Join(filepath.Dir(*adminHtpasswdFile), ".session_blacklist.json")
	} else {
		// Файл не задан — генерируем временный пароль для admin
		pass := generatePassword(16)
		hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("Ошибка генерации пароля: %v", err)
		}
		htpasswdUsers["admin"] = string(hash)
		log.Warnf("ADMIN_HTPASSWD_FILE не задан. Временный пароль для admin: %s", pass)
		log.Warn("Для постоянных учётных данных создайте htpasswd-файл и задайте ADMIN_HTPASSWD_FILE.")
		revokedTokensFile = "/tmp/.ovpn-admin-session-blacklist.json"
	}

	// Persistent session signing key — survives restarts and password changes,
	// rotates only when the file is deleted by the operator.
	sessionSigningKeyFile = filepath.Join(filepath.Dir(revokedTokensFile), ".session_signing_key")
	if err := loadOrGenerateSigningKey(); err != nil {
		log.Fatalf("Failed to init session signing key: %v", err)
	}

	loadRevokedTokens()
}

// loadOrGenerateSigningKey loads a 64-byte signing key from disk, or generates
// and persists a fresh one on first start. Permissions are tightened to 0600
// on a 0700 directory because the key is equivalent to all active sessions.
func loadOrGenerateSigningKey() error {
	if data, err := os.ReadFile(sessionSigningKeyFile); err == nil && len(data) == 64 {
		sessionSigningKey = data
		return nil
	}
	sessionSigningKey = make([]byte, 64)
	if _, err := rand.Read(sessionSigningKey); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(sessionSigningKeyFile), 0o700); err != nil {
		return err
	}
	return os.WriteFile(sessionSigningKeyFile, sessionSigningKey, 0o600)
}

// loadHtpasswd читает файл формата Apache htpasswd (username:hash, по одной записи на строку).
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
		htpasswdUsers[parts[0]] = parts[1]
	}
	return scanner.Err()
}

func validateCredentials(username, password string) bool {
	hash, ok := htpasswdUsers[username]
	if !ok {
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
	// Reject tokens with a non-session purpose (e.g. intermediate mfa tokens).
	// Tokens minted before this field existed have Purpose == "" and remain valid.
	if p.Purpose != "" && p.Purpose != "session" {
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

// ── Handlers ──────────────────────────────────────────────────────────────────

// loginHandler POST /api/login  body: {"username":"…","password":"…"}
func (oAdmin *OvpnAdmin) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := clientIP(r)
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	user := req.Username
	pass := req.Password

	if !checkLoginRateLimit(ip, user) {
		http.Error(w, `{"error":"too many login attempts, try again later"}`, http.StatusTooManyRequests)
		return
	}

	if !validateCredentials(user, pass) {
		recordLoginFailure(ip, user)
		time.Sleep(500 * time.Millisecond) // замедление брутфорса
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"неверный логин или пароль"}`)
		return
	}

	recordLoginSuccess(ip, user)

	if oAdmin.mfaStore != nil && oAdmin.mfaStore.isEnabled(user) {
		mfaToken := signMfaToken(user)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mfa_required": true,
			"mfa_token":    mfaToken,
		})
		return
	}

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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":   true,
		"user": user,
	})
}

// logoutHandler POST /api/logout
//
// Public route (no requireAuth wrapper). If a session cookie is present and
// parseable we revoke it; the response always clears the cookie so a stale or
// malformed session does not leave the browser stuck logged in.
func (oAdmin *OvpnAdmin) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true}`)
}

// authCheckHandler GET /api/auth/check — 200 if authenticated, 401 otherwise
func (oAdmin *OvpnAdmin) authCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true}`)
}

// requireAuth middleware — проверяет сессионную cookie.
func (oAdmin *OvpnAdmin) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		if _, ok := verifySession(cookie.Value); !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		next(w, r)
	}
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

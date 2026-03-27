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
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"sync"
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

// initAuth загружает htpasswd-файл или генерирует временные credentials.
// Вызывается после kingpin.Parse().
func initAuth() {
	htpasswdUsers = make(map[string]string)

	if *adminHtpasswdFile != "" {
		if err := loadHtpasswd(*adminHtpasswdFile); err != nil {
			log.Fatalf("Не удалось загрузить htpasswd-файл %s: %v", *adminHtpasswdFile, err)
		}
		log.Infof("Авторизация: загружено %d пользователей из %s", len(htpasswdUsers), *adminHtpasswdFile)
		return
	}

	// Файл не задан — генерируем временный пароль для admin
	pass := generatePassword(16)
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Ошибка генерации пароля: %v", err)
	}
	htpasswdUsers["admin"] = string(hash)
	log.Warnf("ADMIN_HTPASSWD_FILE не задан. Временный пароль для admin: %s", pass)
	log.Warn("Для постоянных учётных данных создайте htpasswd-файл и задайте ADMIN_HTPASSWD_FILE.")
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
	User string `json:"u"`
	Exp  int64  `json:"exp"`
}

func signSession(user string) string {
	secret := sessionSecret()
	p := sessionPayload{User: user, Exp: time.Now().Add(sessionTTL).Unix()}
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
}

// sessionSecret возвращает секрет для HMAC — хэш всех htpasswd-хэшей.
// Меняется при изменении паролей, автоматически инвалидируя сессии.
func sessionSecret() string {
	var sb strings.Builder
	for u, h := range htpasswdUsers {
		sb.WriteString(u)
		sb.WriteString(h)
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func computeHMAC(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// loginHandler POST /api/login  body: username=&password=
func (oAdmin *OvpnAdmin) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := r.FormValue("username")
	pass := r.FormValue("password")

	if !validateCredentials(user, pass) {
		time.Sleep(500 * time.Millisecond) // замедление брутфорса
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"неверный логин или пароль"}`)
		return
	}

	token := signSession(user)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"ok":true,"user":"%s"}`, user)
}

// logoutHandler POST /api/logout
func (oAdmin *OvpnAdmin) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		revokeToken(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
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

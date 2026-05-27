package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// ── MFA Store ────────────────────────────────────────────────────────────────

type mfaRecord struct {
	Secret      string   `json:"secret"`
	Enabled     bool     `json:"enabled"`
	BackupCodes []string `json:"backup_codes"`
	CreatedAt   string   `json:"created_at"`
}

type mfaStore struct {
	mu   sync.RWMutex
	path string
	data map[string]mfaRecord
}

func newMfaStore(path string) *mfaStore {
	s := &mfaStore{
		path: path,
		data: make(map[string]mfaRecord),
	}
	s.load()
	return s
}

func (s *mfaStore) load() {
	if s.path == "" {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return // file doesn't exist yet — that's fine
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := json.Unmarshal(raw, &s.data); err != nil {
		log.Warnf("mfaStore: failed to parse %s: %v", s.path, err)
	}
}

func (s *mfaStore) save() {
	if s.path == "" {
		return
	}
	s.mu.RLock()
	raw, err := json.Marshal(s.data)
	s.mu.RUnlock()
	if err != nil {
		log.Warnf("mfaStore: failed to marshal: %v", err)
		return
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Warnf("mfaStore: failed to create directory %s: %v", dir, err)
		return
	}
	if err := os.WriteFile(s.path, raw, 0600); err != nil {
		log.Warnf("mfaStore: failed to write %s: %v", s.path, err)
	}
}

func (s *mfaStore) get(username string) (mfaRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.data[username]
	return rec, ok
}

func (s *mfaStore) set(username string, rec mfaRecord) {
	s.mu.Lock()
	s.data[username] = rec
	s.mu.Unlock()
	s.save()
}

func (s *mfaStore) delete(username string) {
	s.mu.Lock()
	delete(s.data, username)
	s.mu.Unlock()
	s.save()
}

func (s *mfaStore) isEnabled(username string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.data[username]
	return ok && rec.Enabled
}

// ── TOTP functions ───────────────────────────────────────────────────────────

func generateTOTPKey(username string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      "ovpn-admin",
		AccountName: username,
	})
}

func verifyTOTPCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// ── Backup codes ─────────────────────────────────────────────────────────────

// backupCodeChars excludes ambiguous characters (0, O, I, 1, L).
const backupCodeChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func generateBackupCodes(count int) (plain []string, hashed []string) {
	plain = make([]string, count)
	hashed = make([]string, count)
	for i := 0; i < count; i++ {
		code := randomBackupCode()
		plain[i] = code
		hash, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		hashed[i] = string(hash)
	}
	return
}

func randomBackupCode() string {
	// Format: XXXX-XXXX
	buf := make([]byte, 8)
	for i := range buf {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(backupCodeChars))))
		buf[i] = backupCodeChars[n.Int64()]
	}
	return string(buf[:4]) + "-" + string(buf[4:])
}

func verifyBackupCode(code string, hashes []string) bool {
	for _, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(code)) == nil {
			return true
		}
	}
	return false
}

func consumeBackupCode(code string, hashes []string) []string {
	for i, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(code)) == nil {
			return append(hashes[:i], hashes[i+1:]...)
		}
	}
	return hashes
}

// ── MFA Token (intermediate, NOT a session) ──────────────────────────────────

const mfaTokenTTL = 5 * time.Minute

type mfaTokenPayload struct {
	User    string `json:"u"`
	Purpose string `json:"purpose"`
	Exp     int64  `json:"exp"`
}

func signMfaToken(user string) string {
	return signMfaTokenWithTTL(user, mfaTokenTTL)
}

func signMfaTokenWithTTL(user string, ttl time.Duration) string {
	secret := sessionSecret()
	p := mfaTokenPayload{
		User:    user,
		Purpose: "mfa",
		Exp:     time.Now().Add(ttl).Unix(),
	}
	data, _ := json.Marshal(p)
	enc := base64.RawURLEncoding.EncodeToString(data)
	mac := computeHMAC(enc, secret)
	return enc + "." + mac
}

func verifyMfaToken(token string) (string, bool) {
	secret := sessionSecret()
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	enc, mac := parts[0], parts[1]
	if computeHMAC(enc, secret) != mac {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", false
	}
	var p mfaTokenPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", false
	}
	if p.Purpose != "mfa" {
		return "", false
	}
	if time.Now().Unix() > p.Exp {
		return "", false
	}
	return p.User, true
}

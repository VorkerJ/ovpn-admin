package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

// mfaRecord represents a single user's MFA state on disk.
//
// Version semantics:
//
//	0 — legacy plaintext (base32) Secret. Migrated to v1 on first read.
//	1 — Secret holds AES-GCM ciphertext, base64-RawURL-encoded.
//
// LastUsedCode / LastUsedAt implement TOTP replay protection: the same
// 6-digit code submitted twice within 90s is rejected, even though
// pquerna/otp would otherwise accept it during its validity window.
type mfaRecord struct {
	Secret       string   `json:"secret"`
	Enabled      bool     `json:"enabled"`
	BackupCodes  []string `json:"backup_codes"`
	CreatedAt    string   `json:"created_at"`
	Version      int      `json:"version,omitempty"`
	LastUsedCode string   `json:"last_used_code,omitempty"`
	LastUsedAt   int64    `json:"last_used_at,omitempty"`
}

// ── Secret encryption (AES-GCM) ──────────────────────────────────────────────

// mfaEncKey derives a 256-bit AES key from the session signing key.
// Domain-separated from session HMACs via the literal prefix so the same
// underlying key material cannot be misused across contexts.
func mfaEncKey() []byte {
	s := sessionSecret()
	h := sha256.Sum256([]byte("ovpn-admin-mfa-encryption-v1:" + s))
	return h[:]
}

func encryptSecret(plaintext string) (string, error) {
	block, err := aes.NewCipher(mfaEncKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

func decryptSecret(ciphertext string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(mfaEncKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
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
	if err := json.Unmarshal(raw, &s.data); err != nil {
		log.Warnf("mfaStore: failed to parse %s: %v", s.path, err)
		s.mu.Unlock()
		return
	}

	// One-shot migration: v0 records hold the base32 secret in plaintext.
	// Re-encrypt under the current key and bump to v1 so future loads
	// take the fast path.
	migrated := false
	for user, rec := range s.data {
		if rec.Version == 0 && rec.Secret != "" {
			enc, err := encryptSecret(rec.Secret)
			if err != nil {
				log.Warnf("mfaStore: failed to migrate secret for %s: %v", user, err)
				continue
			}
			rec.Secret = enc
			rec.Version = 1
			s.data[user] = rec
			migrated = true
		}
	}
	s.mu.Unlock()
	if migrated {
		s.save()
		log.Infof("mfaStore: migrated plaintext secrets to AES-GCM (v1)")
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

// get returns a record with the Secret field DECRYPTED in memory. Callers
// (verifyTOTPCode etc.) work with plaintext base32; the encrypted form
// never leaves this file.
func (s *mfaStore) get(username string) (mfaRecord, bool) {
	s.mu.RLock()
	rec, ok := s.data[username]
	s.mu.RUnlock()
	if !ok {
		return mfaRecord{}, false
	}
	if rec.Version >= 1 && rec.Secret != "" {
		pt, err := decryptSecret(rec.Secret)
		if err != nil {
			log.Errorf("mfaStore: decrypt failed for %s: %v", username, err)
			return mfaRecord{}, false
		}
		rec.Secret = pt
	}
	return rec, true
}

// set accepts a record whose Secret field is plaintext base32. It encrypts
// the secret before persisting; callers must never see ciphertext.
func (s *mfaStore) set(username string, rec mfaRecord) {
	if rec.Secret != "" {
		enc, err := encryptSecret(rec.Secret)
		if err != nil {
			log.Errorf("mfaStore: encrypt failed for %s: %v", username, err)
			return
		}
		rec.Secret = enc
		rec.Version = 1
	}
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
	Jti     string `json:"jti,omitempty"`
}

// signMfaToken mints an intermediate token issued after first-factor success
// to authenticate the second-factor request. Single-use (jti tracked), short
// TTL (mfaTokenTTL). NOT a session token — verifySession rejects this purpose.
func signMfaToken(user string) string {
	secret := sessionSecret()
	jtiBytes := make([]byte, 16)
	_, _ = rand.Read(jtiBytes)
	p := mfaTokenPayload{
		User:    user,
		Purpose: "mfa",
		Exp:     time.Now().Add(mfaTokenTTL).Unix(),
		Jti:     base64.RawURLEncoding.EncodeToString(jtiBytes),
	}
	data, _ := json.Marshal(p)
	enc := base64.RawURLEncoding.EncodeToString(data)
	mac := computeHMAC(enc, secret)
	return enc + "." + mac
}

func verifyMfaToken(token string) (user string, jti string, exp int64, ok bool) {
	secret := sessionSecret()
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", "", 0, false
	}
	enc, mac := parts[0], parts[1]
	if !hmac.Equal([]byte(computeHMAC(enc, secret)), []byte(mac)) {
		return "", "", 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", "", 0, false
	}
	var p mfaTokenPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", "", 0, false
	}
	if p.Purpose != "mfa" {
		return "", "", 0, false
	}
	if time.Now().Unix() > p.Exp {
		return "", "", 0, false
	}
	return p.User, p.Jti, p.Exp, true
}

// usedMfaJtis tracks consumed mfa_token jti values to enforce single-use.
// Entries are kept until their token's exp passes, then garbage-collected
// opportunistically when a new jti is consumed.
var usedMfaJtis = struct {
	sync.Mutex
	m map[string]int64
}{m: map[string]int64{}}

// consumeMfaJti records the given jti as used and returns false if it was
// already seen. Empty jti is treated as "no replay protection available" and
// is allowed through (for backwards compatibility with old tokens).
func consumeMfaJti(jti string, exp int64) bool {
	if jti == "" {
		return true
	}
	usedMfaJtis.Lock()
	defer usedMfaJtis.Unlock()
	if _, used := usedMfaJtis.m[jti]; used {
		return false
	}
	usedMfaJtis.m[jti] = exp
	now := time.Now().Unix()
	for k, e := range usedMfaJtis.m {
		if e < now {
			delete(usedMfaJtis.m, k)
		}
	}
	return true
}

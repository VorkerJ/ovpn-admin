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
	"sort"
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
	// UsedTOTPSteps records the 30-second TOTP time-step counters already spent
	// within the ±1 acceptance window. Tracking the set of used steps (not just a
	// single last-used code) is what stops a TOTP replay across adjacent windows,
	// e.g. current → previous → current (audit F20).
	UsedTOTPSteps []int64 `json:"used_totp_steps,omitempty"`
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
	// markerPath records, durably and separately from the secrets store, the set
	// of usernames that have MFA enabled (audit N08). If the secrets store file
	// goes missing while this marker still lists enrolled users, the store was
	// lost/deleted and load() fails closed instead of treating it as a first run.
	markerPath string
	data       map[string]mfaRecord
	// loadErr is set when an EXISTING store could not be read or parsed. The
	// process must refuse to start in that case (audit F19): silently treating a
	// corrupt/unreadable store as "no MFA configured" would issue password-only
	// sessions and let an attacker who knows the password re-enroll the second
	// factor. A missing file is NOT an error (first run).
	loadErr error
}

func newMfaStore(path string) *mfaStore {
	s := &mfaStore{
		path: path,
		data: make(map[string]mfaRecord),
	}
	if path != "" {
		s.markerPath = path + ".enrolled"
	}
	s.load()
	return s
}

// enrolledMarkerUsers reads the durable enrollment marker. Returns an empty set
// when the marker is absent (never anyone enrolled), or an error when it exists
// but can't be read/parsed (audit N08: treat that as fail-closed).
func (s *mfaStore) enrolledMarkerUsers() (map[string]bool, error) {
	if s.markerPath == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(s.markerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var users []string
	if err := json.Unmarshal(raw, &users); err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(users))
	for _, u := range users {
		m[u] = true
	}
	return m, nil
}

// writeEnrolledMarkerLocked rewrites the marker to list exactly the
// currently-enabled users. The caller MUST hold s.mu (write lock) so the marker
// is written under the same lock as the store itself (audit N09) — otherwise a
// concurrent update could interleave and leave the marker inconsistent with the
// store. Best-effort: a failure only weakens future lost-store detection, so it
// is logged, not fatal.
func (s *mfaStore) writeEnrolledMarkerLocked() {
	if s.markerPath == "" {
		return
	}
	var users []string
	for u, rec := range s.data {
		if rec.Enabled {
			users = append(users, u)
		}
	}
	sort.Strings(users)
	raw, err := json.Marshal(users)
	if err != nil {
		log.Warnf("mfaStore: marshal enrollment marker: %v", err)
		return
	}
	if err := writeFileAtomicSecret(s.markerPath, raw); err != nil {
		log.Warnf("mfaStore: persist enrollment marker %s: %v", s.markerPath, err)
	}
}

func (s *mfaStore) load() {
	if s.path == "" {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			// Audit N08: a MISSING store is only a genuine first run if nobody was
			// ever enrolled. If the durable enrollment marker still lists enrolled
			// users, the secrets store was lost or deleted — fail closed (loadErr =>
			// fatal at startup) rather than silently issuing password-only sessions
			// and letting an attacker who knows the password re-enroll the 2nd factor.
			marker, merr := s.enrolledMarkerUsers()
			if merr != nil {
				s.loadErr = fmt.Errorf("read MFA enrollment marker %s: %w", s.markerPath, merr)
				return
			}
			if len(marker) > 0 {
				s.loadErr = fmt.Errorf("MFA store %s is missing but the enrollment marker lists %d enrolled user(s) — the store was lost or deleted; refusing to start with MFA silently disabled (restore the store, or delete %s to intentionally reset MFA)", s.path, len(marker), s.markerPath)
			}
			return // no marker (or empty) — genuine first run
		}
		// An existing store we cannot read (EACCES, I/O error) must fail closed.
		s.loadErr = fmt.Errorf("read MFA store %s: %w", s.path, err)
		return
	}
	s.mu.Lock()
	if err := json.Unmarshal(raw, &s.data); err != nil {
		// Corrupt store — fail closed rather than silently disabling MFA.
		s.data = make(map[string]mfaRecord)
		s.loadErr = fmt.Errorf("parse MFA store %s: %w", s.path, err)
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
		if err := s.save(); err != nil {
			// Best-effort: the re-encrypted secrets are live in memory; a failed
			// write just means the migration re-runs next boot.
			log.Warnf("mfaStore: failed to persist migrated secrets: %v", err)
		} else {
			log.Infof("mfaStore: migrated plaintext secrets to AES-GCM (v1)")
		}
	}
}

// save persists the store to disk. It returns an error so callers that enable
// or tear down MFA can refuse to report success on a lost write (a non-persisted
// enable would silently disable MFA after a restart).
// save takes the lock and persists. Used by the startup migration path.
func (s *mfaStore) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// saveLocked marshals AND writes while the caller holds s.mu (write lock). Audit
// N09 (sibling of the session-epochs/blacklist fix): the old code marshalled
// under a read lock, released it, then wrote outside any lock — so two
// concurrent set()/delete() calls could marshal different snapshots and have the
// older writer's file write land last, dropping a just-persisted enrollment
// (which would silently disable that user's MFA after a restart). Serializing
// mutate+marshal+write under the write lock closes that window; matches the
// apiTokenStore pattern (its save also runs under the caller's lock).
func (s *mfaStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	raw, err := json.Marshal(s.data)
	if err != nil {
		log.Warnf("mfaStore: failed to marshal: %v", err)
		return fmt.Errorf("marshal mfa store: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Warnf("mfaStore: failed to create directory %s: %v", dir, err)
		return fmt.Errorf("create mfa store dir: %w", err)
	}
	// Atomic write: a torn write would leave _mfa_secrets.json unparseable
	// at next boot, locking every MFA-enabled admin out of the UI.
	if err := writeFileAtomicSecret(s.path, raw); err != nil {
		log.Warnf("mfaStore: failed to write %s: %v", s.path, err)
		return fmt.Errorf("write mfa store: %w", err)
	}
	return nil
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
//
// Commit-then-respond: if the durable write fails, the in-memory change is
// rolled back so live state never claims an enable/rotate that isn't on disk.
func (s *mfaStore) set(username string, rec mfaRecord) error {
	if rec.Secret != "" {
		enc, err := encryptSecret(rec.Secret)
		if err != nil {
			log.Errorf("mfaStore: encrypt failed for %s: %v", username, err)
			return fmt.Errorf("encrypt mfa secret: %w", err)
		}
		rec.Secret = enc
		rec.Version = 1
	}
	// Audit N09: mutate + persist + marker under a single write-lock hold so a
	// concurrent set/delete can't lose an update on disk.
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.data[username]
	s.data[username] = rec
	if err := s.saveLocked(); err != nil {
		if had {
			s.data[username] = prev
		} else {
			delete(s.data, username)
		}
		return err
	}
	// Audit N08: keep the durable enrollment marker in sync so a later store
	// deletion is detectable at startup.
	s.writeEnrolledMarkerLocked()
	return nil
}

func (s *mfaStore) delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.data[username]
	delete(s.data, username)
	if err := s.saveLocked(); err != nil {
		// Roll back so a failed persist doesn't leave MFA disabled in memory
		// but re-enabled on disk (it would resurrect after a restart).
		if had {
			s.data[username] = prev
		}
		return err
	}
	// Audit N08: an intentional disable must prune the marker, so it doesn't later
	// look like a lost store for a user who legitimately turned MFA off.
	s.writeEnrolledMarkerLocked()
	return nil
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

// matchTOTPStep returns the 30-second time-step counter that `code` validates
// against within the ±1-step acceptance window, or (0,false) if it is not a
// currently-valid TOTP for secret. Skew:0 per step so the EXACT matched step is
// known — that identity is what verifyAndConsume records to reject replays.
func matchTOTPStep(secret, code string, now time.Time) (int64, bool) {
	opts := totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	for _, d := range []int64{-1, 0, 1} {
		t := now.Add(time.Duration(d*30) * time.Second)
		if ok, err := totp.ValidateCustom(code, secret, t, opts); err == nil && ok {
			return t.Unix() / 30, true
		}
	}
	return 0, false
}

// pruneTOTPSteps keeps only steps still inside (or just around) the current
// acceptance window so the used-step set can't grow without bound.
func pruneTOTPSteps(steps []int64, now time.Time) []int64 {
	cur := now.Unix() / 30
	out := steps[:0:0]
	for _, s := range steps {
		if cur-s <= 2 && s-cur <= 2 {
			out = append(out, s)
		}
	}
	return out
}

// mfaConsumeResult is the outcome of an atomic second-factor check.
type mfaConsumeResult int

const (
	mfaReject mfaConsumeResult = iota
	mfaOKTOTP
	mfaOKBackup
)

// verifyAndConsume atomically validates a TOTP or backup code for user and, on
// success, records its consumption while holding the store's write lock. This
// closes the get→verify→consume→set race (audit F20): two concurrent requests
// can no longer both spend the same one-shot backup code, and a TOTP step is
// marked used the instant it is accepted so it cannot be replayed. It persists
// the mutation atomically (rolling back the in-memory change on a write error)
// so a lost write never leaves a code counted-as-spent only in memory.
func (s *mfaStore) verifyAndConsume(user, code string, now time.Time) (mfaConsumeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.data[user]
	if !ok || !rec.Enabled {
		return mfaReject, nil
	}

	// s.data holds the ENCRYPTED secret; decrypt a copy only for verification.
	secret := rec.Secret
	if rec.Version >= 1 && rec.Secret != "" {
		pt, err := decryptSecret(rec.Secret)
		if err != nil {
			log.Errorf("mfaStore: decrypt failed for %s: %v", user, err)
			return mfaReject, nil
		}
		secret = pt
	}

	// TOTP first.
	if step, matched := matchTOTPStep(secret, code, now); matched {
		for _, used := range rec.UsedTOTPSteps {
			if used == step {
				return mfaReject, nil // replay of an already-spent step
			}
		}
		next := rec
		next.UsedTOTPSteps = pruneTOTPSteps(append(append([]int64(nil), rec.UsedTOTPSteps...), step), now)
		next.LastUsedCode = code
		next.LastUsedAt = now.Unix()
		if err := s.persistRecordLocked(user, rec, next); err != nil {
			return mfaReject, err
		}
		return mfaOKTOTP, nil
	}

	// Backup code.
	if verifyBackupCode(code, rec.BackupCodes) {
		next := rec
		next.BackupCodes = consumeBackupCode(code, append([]string(nil), rec.BackupCodes...))
		if err := s.persistRecordLocked(user, rec, next); err != nil {
			return mfaReject, err
		}
		return mfaOKBackup, nil
	}

	return mfaReject, nil
}

// persistRecordLocked stores next for user and writes the whole store to disk.
// The caller MUST hold s.mu (write lock); it marshals directly rather than
// calling save() (which would re-acquire the lock and deadlock). On a write
// failure it rolls the in-memory record back to prev so memory and disk agree.
func (s *mfaStore) persistRecordLocked(user string, prev, next mfaRecord) error {
	s.data[user] = next
	if s.path == "" {
		return nil
	}
	raw, err := json.Marshal(s.data)
	if err != nil {
		s.data[user] = prev
		return fmt.Errorf("marshal mfa store: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		s.data[user] = prev
		return fmt.Errorf("create mfa store dir: %w", err)
	}
	if err := writeFileAtomicSecret(s.path, raw); err != nil {
		s.data[user] = prev
		return fmt.Errorf("write mfa store: %w", err)
	}
	return nil
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
		// Backup codes carry the same blast radius as a TOTP secret. Match the
		// adminBcryptCost ceiling so a leaked _mfa_secrets.json file is not
		// trivially crackable offline (8 codes × ~250ms is still <2s at setup).
		hash, _ := bcrypt.GenerateFromPassword([]byte(code), adminBcryptCost)
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
	// Epoch is the user's session epoch when this first-factor token was minted.
	// verifyMfaToken rejects it once the epoch advances (password change / MFA
	// enable), so a password change between the two login steps invalidates any
	// in-flight MFA challenge (audit F22).
	Epoch int64 `json:"e,omitempty"`
}

// signMfaToken mints an intermediate token issued after first-factor success
// to authenticate the second-factor request. Single-use (jti tracked), short
// TTL (mfaTokenTTL). NOT a session token — verifySession rejects this purpose.
func signMfaToken(user string) string {
	secret := mfaTokenSecret()
	jtiBytes := make([]byte, 16)
	_, _ = rand.Read(jtiBytes)
	p := mfaTokenPayload{
		User:    user,
		Purpose: "mfa",
		Exp:     time.Now().Add(mfaTokenTTL).Unix(),
		Jti:     base64.RawURLEncoding.EncodeToString(jtiBytes),
		Epoch:   getUserEpoch(user),
	}
	data, _ := json.Marshal(p)
	enc := base64.RawURLEncoding.EncodeToString(data)
	mac := computeHMAC(enc, secret)
	return enc + "." + mac
}

func verifyMfaToken(token string) (user string, jti string, exp int64, ok bool) {
	secret := mfaTokenSecret()
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
	// Audit F22: reject a first-factor token minted before the user's epoch
	// advanced (password change / MFA enable between the two login steps).
	if p.Epoch != getUserEpoch(p.User) {
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
// already seen. Empty jti is rejected — signMfaToken always emits a jti,
// so a missing one means a malformed payload or a pre-jti token we no
// longer accept (refusing closes the replay window completely).
func consumeMfaJti(jti string, exp int64) bool {
	if jti == "" {
		return false
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

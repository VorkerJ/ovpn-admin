package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func init() {
	// Tests need htpasswdUsers initialized for sessionSecret() to work.
	if htpasswdUsers == nil {
		htpasswdUsers = map[string]string{"testuser": "$2a$10$dummy"}
	}
}

func TestMfaStore_RoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "mfa.json")

	s := newMfaStore(path)
	rec := mfaRecord{
		Secret:      "JBSWY3DPEHPK3PXP",
		Enabled:     true,
		BackupCodes: []string{"hash1", "hash2"},
		CreatedAt:   "2025-01-01T00:00:00Z",
	}
	s.set("alice", rec)

	// Verify in-memory
	got, ok := s.get("alice")
	if !ok {
		t.Fatal("expected to find alice in store")
	}
	if got.Secret != rec.Secret || got.Enabled != rec.Enabled || len(got.BackupCodes) != 2 {
		t.Fatalf("record mismatch: got %+v", got)
	}

	// Reload from disk
	s2 := newMfaStore(path)
	got2, ok := s2.get("alice")
	if !ok {
		t.Fatal("expected to find alice after reload")
	}
	if got2.Secret != rec.Secret || got2.Enabled != rec.Enabled {
		t.Fatalf("record mismatch after reload: got %+v", got2)
	}

	// Verify file permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected file permission 0600, got %04o", perm)
	}
}

func TestMfaStore_Delete(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "mfa.json")

	s := newMfaStore(path)
	s.set("bob", mfaRecord{Secret: "SECRET", Enabled: true})

	if !s.isEnabled("bob") {
		t.Fatal("bob should be enabled")
	}

	s.delete("bob")

	if _, ok := s.get("bob"); ok {
		t.Fatal("bob should be deleted")
	}
	if s.isEnabled("bob") {
		t.Fatal("bob should not be enabled after delete")
	}
}

func TestVerifyTOTP_ValidCode(t *testing.T) {
	t.Parallel()

	key, err := generateTOTPKey("testuser")
	if err != nil {
		t.Fatalf("generateTOTPKey: %v", err)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if !verifyTOTPCode(key.Secret(), code) {
		t.Error("expected valid code to pass verification")
	}
}

func TestVerifyTOTP_InvalidCode(t *testing.T) {
	t.Parallel()

	key, err := generateTOTPKey("testuser")
	if err != nil {
		t.Fatalf("generateTOTPKey: %v", err)
	}

	if verifyTOTPCode(key.Secret(), "000000") {
		t.Error("expected invalid code to be rejected")
	}
}

func TestBackupCodes_GenerateAndVerify(t *testing.T) {
	t.Parallel()

	plain, hashed := generateBackupCodes(8)

	if len(plain) != 8 || len(hashed) != 8 {
		t.Fatalf("expected 8 codes, got %d plain / %d hashed", len(plain), len(hashed))
	}

	// Verify format: XXXX-XXXX
	for _, code := range plain {
		if len(code) != 9 || code[4] != '-' {
			t.Errorf("unexpected backup code format: %q", code)
		}
	}

	// First code should verify
	if !verifyBackupCode(plain[0], hashed) {
		t.Error("first backup code should verify")
	}

	// Wrong code should be rejected
	if verifyBackupCode("ZZZZ-ZZZZ", hashed) {
		t.Error("wrong backup code should be rejected")
	}
}

func TestBackupCodes_OneTimeUse(t *testing.T) {
	t.Parallel()

	plain, hashed := generateBackupCodes(3)

	// Consume first code
	remaining := consumeBackupCode(plain[0], hashed)
	if len(remaining) != 2 {
		t.Fatalf("expected 2 remaining codes, got %d", len(remaining))
	}

	// First code should no longer verify against remaining
	if verifyBackupCode(plain[0], remaining) {
		t.Error("consumed backup code should no longer verify")
	}

	// Second code should still work
	if !verifyBackupCode(plain[1], remaining) {
		t.Error("unconsumed backup code should still verify")
	}
}

func TestMfaToken_SignAndVerify(t *testing.T) {
	t.Parallel()

	token := signMfaToken("alice")
	user, ok := verifyMfaToken(token)
	if !ok {
		t.Fatal("expected token to be valid")
	}
	if user != "alice" {
		t.Errorf("expected user 'alice', got %q", user)
	}
}

func TestMfaToken_Expired(t *testing.T) {
	t.Parallel()

	// Sign with a negative TTL so the token is already expired
	token := signMfaTokenWithTTL("alice", -1*time.Minute)
	_, ok := verifyMfaToken(token)
	if ok {
		t.Error("expected expired token to be rejected")
	}
}

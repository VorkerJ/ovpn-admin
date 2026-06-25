package ovpnuser

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &store{db: db}
	if rc := s.initDB(); rc != 0 {
		t.Fatalf("initDB rc=%d", rc)
	}
	if rc := s.migrateDB(); rc != 0 {
		t.Fatalf("migrateDB rc=%d", rc)
	}
	return s
}

func TestCreateAndAuth(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.createUser("alice", "Secret123"); err != nil {
		t.Fatalf("create: %v", err)
	}

	// correct password authenticates
	if ok, err := s.authUser("alice", "Secret123", ""); err != nil || !ok {
		t.Fatalf("auth correct: ok=%v err=%v", ok, err)
	}
	// wrong password is rejected
	if ok, err := s.authUser("alice", "nope", ""); ok || err != errPasswordMismatched {
		t.Fatalf("auth wrong: ok=%v err=%v", ok, err)
	}
	// unknown user is rejected (no panic, error returned)
	if ok, _ := s.authUser("ghost", "x", ""); ok {
		t.Fatal("auth unknown user must fail")
	}
	// duplicate create rejected
	if _, err := s.createUser("alice", "x"); err != errUserAlreadyExist {
		t.Fatalf("dup create: %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.createUser("bob", "old-password-1")

	if _, err := s.changePassword("bob", "new-password-2"); err != nil {
		t.Fatalf("change: %v", err)
	}
	if ok, _ := s.authUser("bob", "new-password-2", ""); !ok {
		t.Fatal("new password must authenticate")
	}
	if ok, _ := s.authUser("bob", "old-password-1", ""); ok {
		t.Fatal("old password must no longer authenticate")
	}
}

func TestRevokeRestoreDelete(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.createUser("carol", "carol-pass-99")

	if _, err := s.revokeUser("carol"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if ok, err := s.authUser("carol", "carol-pass-99", ""); ok || err != errUserIsNotActive {
		t.Fatalf("revoked must be inactive: ok=%v err=%v", ok, err)
	}

	if _, err := s.restoreUser("carol"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if ok, _ := s.authUser("carol", "carol-pass-99", ""); !ok {
		t.Fatal("restored user must authenticate")
	}

	if _, err := s.deleteUser("carol", true); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if s.userExists("carol") {
		t.Fatal("force-deleted user must be gone")
	}
}

// TestAuthCmdExitCodes locks the OpenVPN contract: exit 0 = allow, non-zero =
// deny — the single most important behaviour of this tool.
func TestAuthCmdExitCodes(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.createUser("dave", "dave-pass-77")

	if rc := s.authCmd("dave", "dave-pass-77", ""); rc != 0 {
		t.Fatalf("correct password must exit 0, got %d", rc)
	}
	if rc := s.authCmd("dave", "wrong", ""); rc == 0 {
		t.Fatalf("wrong password must exit non-zero, got %d", rc)
	}
	if rc := s.authCmd("dave", "x", "123456"); rc == 0 {
		t.Fatal("supplying both password and totp must be rejected")
	}
}

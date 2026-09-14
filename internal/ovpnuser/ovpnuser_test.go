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
	t.Cleanup(func() { _ = db.Close() })
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

// TestHasPassword covers the per-user "password-required" predicate that the
// OpenVPN auth.sh relies on to tell password users from cert-only users.
func TestHasPassword(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.createUser("erin", "erin-pass-12345")

	if !s.userActiveWithPassword("erin") {
		t.Fatal("active user with a password must be password-required")
	}
	if s.userActiveWithPassword("ghost") {
		t.Fatal("unknown user must not be password-required")
	}
	// revoked / deleted users are not password-required (cert handles them)
	_, _ = s.revokeUser("erin")
	if s.userActiveWithPassword("erin") {
		t.Fatal("revoked user must not be password-required")
	}
}

// TestActivePasswordUsers covers the batch set used to render the user list.
func TestActivePasswordUsers(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.createUser("u1", "pw-one-123456")
	_, _ = s.createUser("u2", "pw-two-123456")
	_, _ = s.createUser("u3", "pw-three-1234")
	_, _ = s.revokeUser("u3") // revoked → excluded

	// ActivePasswordUsers opens its own connection to the same file. Find the
	// db path via the test store's file (re-open through the public API).
	set := ActivePasswordUsers(dbPathOf(t, s))
	if !set["u1"] || !set["u2"] {
		t.Fatalf("u1,u2 must be in the set: %v", set)
	}
	if set["u3"] {
		t.Fatalf("revoked u3 must be excluded: %v", set)
	}
	if len(set) != 2 {
		t.Fatalf("expected exactly 2 password users, got %d: %v", len(set), set)
	}
}

// dbPathOf returns the file path backing the test store's connection.
func dbPathOf(t *testing.T, s *store) string {
	t.Helper()
	var path string
	// PRAGMA database_list returns (seq, name, file) for the main db.
	if err := s.db.QueryRow("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&path); err != nil {
		t.Fatalf("resolve db path: %v", err)
	}
	return path
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

// TestAuditPasswordStatusTriState locks audit F02: has-password's exit-code
// contract distinguishes password-required (0), cert-only (1) and error/denied
// (2). A DB failure must return 2 (deny), never 1 (cert-only allow).
func TestAuditPasswordStatusTriState(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.createUser("withpass", "Secret123"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := s.passwordStatus("withpass"); got != 0 {
		t.Fatalf("F02: user with password must be status 0 (required), got %d", got)
	}
	// Unknown user (no row) → cert-only.
	if got := s.passwordStatus("nobody"); got != 1 {
		t.Fatalf("F02: unknown user must be status 1 (cert-only), got %d", got)
	}
	// Revoked user → deny.
	if _, err := s.revokeUser("withpass"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got := s.passwordStatus("withpass"); got != 2 {
		t.Fatalf("F02: revoked user must be status 2 (deny), got %d", got)
	}
	// DB error → deny (2), never cert-only (1).
	_ = s.db.Close()
	if got := s.passwordStatus("withpass"); got != 2 {
		t.Fatalf("F02: DB error must be status 2 (deny), got %d", got)
	}
}

// TestAuditChangePasswordUpserts locks audit F04: change-password works for an
// existing user AND creates the row for a cert-only user (no prior entry),
// without the caller having to distinguish the two.
func TestAuditChangePasswordUpserts(t *testing.T) {
	s := newTestStore(t)

	// Existing user: change replaces the password.
	if _, err := s.createUser("alice", "OldPass123"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.changePassword("alice", "NewPass123"); err != nil {
		t.Fatalf("F04: change existing user: %v", err)
	}
	if rc := s.authCmd("alice", "NewPass123", ""); rc != 0 {
		t.Fatalf("F04: new password must authenticate, rc=%d", rc)
	}
	if rc := s.authCmd("alice", "OldPass123", ""); rc == 0 {
		t.Fatal("F04: old password must no longer authenticate")
	}

	// Cert-only user with no row yet: change-password creates it (upsert).
	if _, err := s.changePassword("certonly", "FreshPass123"); err != nil {
		t.Fatalf("F04: change-password for new row: %v", err)
	}
	if rc := s.authCmd("certonly", "FreshPass123", ""); rc != 0 {
		t.Fatalf("F04: upserted password must authenticate, rc=%d", rc)
	}
}

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateLegacyAuthState(t *testing.T) {
	legacy := t.TempDir()
	state := t.TempDir()

	// Legacy dir holds the pre-state-dir auth state.
	mustWrite(t, filepath.Join(legacy, "_mfa_secrets.json"), `{"admin":{}}`)
	mustWrite(t, filepath.Join(legacy, ".session_signing_key"), "KEYBYTES")
	mustWrite(t, filepath.Join(legacy, "api_tokens.json"), "[]")
	// A file that already exists in state-dir must NOT be overwritten.
	mustWrite(t, filepath.Join(legacy, ".session_blacklist.json"), "LEGACY")
	mustWrite(t, filepath.Join(state, ".session_blacklist.json"), "NEWER")

	migrateLegacyAuthState(state, legacy)

	// Migrated files land in state-dir with their content.
	if got := mustRead(t, filepath.Join(state, "_mfa_secrets.json")); got != `{"admin":{}}` {
		t.Fatalf("mfa secrets not migrated: %q", got)
	}
	if got := mustRead(t, filepath.Join(state, ".session_signing_key")); got != "KEYBYTES" {
		t.Fatalf("signing key not migrated: %q", got)
	}
	// Existing file preserved (never overwritten).
	if got := mustRead(t, filepath.Join(state, ".session_blacklist.json")); got != "NEWER" {
		t.Fatalf("existing state file must not be overwritten, got %q", got)
	}
}

func TestMigrateLegacyAuthState_NoopWhenSameDir(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "_mfa_secrets.json"), "x")
	// same dir → must not touch anything / not error
	migrateLegacyAuthState(dir, dir)
	if got := mustRead(t, filepath.Join(dir, "_mfa_secrets.json")); got != "x" {
		t.Fatalf("same-dir migration must be a no-op, got %q", got)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

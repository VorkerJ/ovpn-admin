package main

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// resetLoginAttempts wipes the package-global rate-limit map and restores it
// afterwards so rate-limit tests don't bleed into one another.
func resetLoginAttempts(t *testing.T) {
	t.Helper()
	loginAttempts = sync.Map{}
	t.Cleanup(func() { loginAttempts = sync.Map{} })
}

// ── FINDING #5: strict signing-key / credential file checks ──────────────────

// TestLoadSigningKeyRejectsPlantedFiles proves loadOrGenerateSigningKey fails
// closed on a signing-key file that a local user could have planted on a shared
// /tmp: a symlink, a group/world-accessible file, or (best-effort) a
// wrong-owner file. A proper 0600 owner-owned 64-byte file is accepted.
func TestLoadSigningKeyRejectsPlantedFiles(t *testing.T) {
	prevFile := sessionSigningKeyFile
	prevKey := sessionSigningKey
	t.Cleanup(func() {
		sessionSigningKeyFile = prevFile
		sessionSigningKey = prevKey
	})

	validKey := make([]byte, 64)
	if _, err := rand.Read(validKey); err != nil {
		t.Fatal(err)
	}

	t.Run("symlink is rejected", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "real_key")
		if err := os.WriteFile(target, validKey, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, ".session_signing_key")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		sessionSigningKey = nil
		sessionSigningKeyFile = link
		if err := loadOrGenerateSigningKey(); err == nil {
			t.Fatal("SECURITY: a symlinked signing-key file must be rejected (fail closed)")
		}
		if sessionSigningKey != nil {
			t.Fatal("SECURITY: signing key must not be populated from a rejected file")
		}
	})

	t.Run("group/world-readable is rejected", func(t *testing.T) {
		dir := t.TempDir()
		key := filepath.Join(dir, ".session_signing_key")
		if err := os.WriteFile(key, validKey, 0o644); err != nil {
			t.Fatal(err)
		}
		// os.WriteFile is subject to umask; force the mode explicitly.
		if err := os.Chmod(key, 0o644); err != nil {
			t.Fatal(err)
		}
		sessionSigningKey = nil
		sessionSigningKeyFile = key
		if err := loadOrGenerateSigningKey(); err == nil {
			t.Fatal("SECURITY: a group/world-accessible signing-key file must be rejected")
		}
		if sessionSigningKey != nil {
			t.Fatal("SECURITY: signing key must not be populated from a rejected file")
		}
	})

	t.Run("proper 0600 owner-owned file is accepted", func(t *testing.T) {
		dir := t.TempDir()
		key := filepath.Join(dir, ".session_signing_key")
		if err := os.WriteFile(key, validKey, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(key, 0o600); err != nil {
			t.Fatal(err)
		}
		sessionSigningKey = nil
		sessionSigningKeyFile = key
		if err := loadOrGenerateSigningKey(); err != nil {
			t.Fatalf("a proper 0600 owner-owned key file must be accepted: %v", err)
		}
		if len(sessionSigningKey) != 64 {
			t.Fatalf("expected the 64-byte key to be loaded, got %d bytes", len(sessionSigningKey))
		}
	})

	t.Run("absent file generates a fresh key with strict perms", func(t *testing.T) {
		dir := t.TempDir()
		key := filepath.Join(dir, ".session_signing_key")
		sessionSigningKey = nil
		sessionSigningKeyFile = key
		if err := loadOrGenerateSigningKey(); err != nil {
			t.Fatalf("first start must generate a key: %v", err)
		}
		if len(sessionSigningKey) != 64 {
			t.Fatalf("generated key must be 64 bytes, got %d", len(sessionSigningKey))
		}
		fi, err := os.Lstat(key)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("generated signing key must be owner-only, got mode %#o", fi.Mode().Perm())
		}
		// And the freshly-written file must itself pass the strict check on reload.
		if !isOwnerOnlyCredFile(key) {
			t.Fatal("generated signing key must pass the strict owner-only check")
		}
	})
}

// TestIsOwnerOnlyCredFileSymlink locks the Lstat-based symlink rejection at the
// helper level (the htpasswd path shares this helper).
func TestIsOwnerOnlyCredFileSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("admin:x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if isOwnerOnlyCredFile(link) {
		t.Fatal("SECURITY: a symlink must not be trusted even if its target is 0600 owner-owned")
	}
}

// ── FINDING #6: rate limiter semantics ───────────────────────────────────────

// TestSingleIPCannotLockAccount is the core of FINDING #6: repeated failures
// from ONE ip against a known username must not lock the account such that the
// legit admin from ANOTHER ip is blocked. The attacking IP itself is locked
// (that's the primary defense) but the account bucket stays open until failures
// arrive from several distinct IPs.
func TestSingleIPCannotLockAccount(t *testing.T) {
	resetLoginAttempts(t)

	const attacker = "1.1.1.1"
	for i := 0; i < maxLoginAttempts+5; i++ {
		recordLoginFailure(attacker, "admin")
	}

	// The attacker's own IP is locked — brute force from that source is stopped.
	if checkLoginRateLimit(attacker) {
		t.Fatal("the attacking IP should be locked out after exceeding the limit")
	}

	// The legit admin coming from a DIFFERENT IP must still be allowed: neither
	// their IP nor the account bucket is locked.
	if !checkLoginRateLimit("2.2.2.2", "admin") {
		t.Fatal("SECURITY REGRESSION: a single attacker IP locked the admin account out for other IPs")
	}
}

// TestDistributedFailuresLockAccount confirms the account bucket still protects
// against a distributed / IP-rotating brute force: failures from enough distinct
// IPs do hard-lock the account.
func TestDistributedFailuresLockAccount(t *testing.T) {
	resetLoginAttempts(t)

	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	for _, ip := range ips {
		recordLoginFailure(ip, "admin")
	}
	// failures == len(ips) >= maxLoginAttempts AND distinct IPs >= threshold.
	if checkLoginRateLimit("10.0.0.99", "admin") {
		t.Fatal("account should be locked after failures from many distinct IPs (distributed brute force)")
	}
}

// TestJanitorEvictsStalePartialFailures proves the TTL eviction: an entry with
// 1–4 failures (never locked) that hasn't been touched within the lockout
// window is dropped, closing the unbounded-growth leak. It also confirms a
// fresh partial-failure entry is NOT evicted prematurely.
func TestJanitorEvictsStalePartialFailures(t *testing.T) {
	resetLoginAttempts(t)

	recordLoginFailure("3.3.3.3") // 1 failure — below lockout threshold
	if _, ok := loginAttempts.Load("3.3.3.3"); !ok {
		t.Fatal("precondition: entry should exist after a failure")
	}

	// A cleanup at the present moment must keep the fresh entry.
	cleanupLoginAttempts(time.Now())
	if _, ok := loginAttempts.Load("3.3.3.3"); !ok {
		t.Fatal("a fresh partial-failure entry must not be evicted")
	}

	// A cleanup well past the lockout window must evict the now-stale entry.
	cleanupLoginAttempts(time.Now().Add(loginLockoutDuration + time.Minute))
	if _, ok := loginAttempts.Load("3.3.3.3"); ok {
		t.Fatal("a stale 1–4-failure entry must be evicted by the janitor TTL")
	}
}

// TestJanitorEnforcesCap proves the global entry cap: once the number of tracked
// entries exceeds maxLoginTrackerEntries, the janitor evicts oldest-first back
// to the cap so memory can't grow without bound.
func TestJanitorEnforcesCap(t *testing.T) {
	resetLoginAttempts(t)

	prevCap := maxLoginTrackerEntries
	maxLoginTrackerEntries = 3
	t.Cleanup(func() { maxLoginTrackerEntries = prevCap })

	base := time.Now()
	// Insert 6 fresh (non-stale) partial-failure entries with increasing
	// last-activity timestamps so eviction order is deterministic.
	for i := 0; i < 6; i++ {
		key := "ip-" + string(rune('a'+i))
		tr := &loginTracker{failures: 1, updatedAt: base.Add(time.Duration(i) * time.Second)}
		loginAttempts.Store(key, tr)
	}

	// Run cleanup at `base` so none are TTL-expired; only the cap should trigger.
	cleanupLoginAttempts(base)

	remaining := 0
	loginAttempts.Range(func(_, _ interface{}) bool { remaining++; return true })
	if remaining != maxLoginTrackerEntries {
		t.Fatalf("cap not enforced: want %d entries, got %d", maxLoginTrackerEntries, remaining)
	}
	// The three oldest (a,b,c) should be gone; the three newest (d,e,f) kept.
	for _, gone := range []string{"ip-a", "ip-b", "ip-c"} {
		if _, ok := loginAttempts.Load(gone); ok {
			t.Fatalf("oldest entry %s should have been evicted by the cap", gone)
		}
	}
	for _, kept := range []string{"ip-d", "ip-e", "ip-f"} {
		if _, ok := loginAttempts.Load(kept); !ok {
			t.Fatalf("newest entry %s should have been kept", kept)
		}
	}
}

// ── FINDING #6: X-Forwarded-For parsing ──────────────────────────────────────

// TestClientIPForwardedForRightToLeft proves clientIP picks the correct hop when
// an attacker PREPENDS a spoofed address to X-Forwarded-For and the real proxy
// appends the true peer. Right-to-left parsing must return the real client, not
// the spoofed leftmost value.
func TestClientIPForwardedForRightToLeft(t *testing.T) {
	prev := trustedProxies
	t.Cleanup(func() { trustedProxies = prev })
	trustedProxies = nil // loopback is always trusted; peer below is loopback

	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.RemoteAddr = "127.0.0.1:5555" // trusted peer → XFF is honored
	// Attacker prepends "1.2.3.4"; the trusted proxy appended the real client.
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 9.9.9.9")

	if got := clientIP(r); got != "9.9.9.9" {
		t.Fatalf("clientIP must return the real client (rightmost non-proxy), got %q — a spoofed leftmost XFF was trusted", got)
	}
}

// TestClientIPSkipsTrustedProxiesInChain confirms trusted-proxy hops at the tail
// of the chain are skipped so the real client (before them) is returned.
func TestClientIPSkipsTrustedProxiesInChain(t *testing.T) {
	prev := trustedProxies
	t.Cleanup(func() { trustedProxies = prev })
	trustedProxies = []string{"10.0.0.0/8"}

	r := httptest.NewRequest(http.MethodGet, "/api/auth/check", nil)
	r.RemoteAddr = "10.1.2.3:443" // trusted proxy peer
	// Real client, then two internal trusted proxies appended by the mesh.
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 10.5.5.5, 10.6.6.6")

	if got := clientIP(r); got != "9.9.9.9" {
		t.Fatalf("clientIP must skip trailing trusted proxies and return the client, got %q", got)
	}
}

// TestClientIPUntrustedPeerIgnoresXFF confirms an untrusted direct peer's XFF is
// ignored entirely (the peer address is authoritative).
func TestClientIPUntrustedPeerIgnoresXFF(t *testing.T) {
	prev := trustedProxies
	t.Cleanup(func() { trustedProxies = prev })
	trustedProxies = nil

	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.RemoteAddr = "203.0.113.7:9000" // NOT trusted
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	if got := clientIP(r); got != "203.0.113.7" {
		t.Fatalf("XFF from an untrusted peer must be ignored, got %q", got)
	}
}

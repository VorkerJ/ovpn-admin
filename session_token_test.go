package main

import (
	"encoding/base64"
	"testing"
)

// ensureSigningKey is defined in force_password_change_test.go and seeds a
// deterministic sessionSigningKey so the HMAC helpers work in isolation.

// TestMfaTokenIsNotASession locks the fix for the MFA-bypass: an intermediate
// MFA token (minted after only the first factor) must NEVER validate as a
// session cookie. Before the fix, the purpose discriminator was serialized
// under a different JSON key for each token type, so an MFA token parsed as
// Purpose=="" in verifySession and the empty-allowed clause let it through —
// defeating MFA for anyone who knew the password.
func TestMfaTokenIsNotASession(t *testing.T) {
	ensureSigningKey()

	mfa := signMfaToken("admin")
	if _, ok := verifySession(mfa); ok {
		t.Fatal("SECURITY: an MFA token must not be accepted as a session cookie")
	}

	// A real session must still work, and must NOT be usable as an MFA token.
	sess := signSession("admin")
	if u, ok := verifySession(sess); !ok || u != "admin" {
		t.Fatalf("a genuine session must verify: ok=%v user=%q", ok, u)
	}
	if _, _, _, ok := verifyMfaToken(sess); ok {
		t.Fatal("SECURITY: a session token must not be accepted as an MFA token")
	}

	// The MFA token must still verify through its own path (domain-separated key).
	if u, _, _, ok := verifyMfaToken(mfa); !ok || u != "admin" {
		t.Fatalf("MFA token must verify via verifyMfaToken: ok=%v user=%q", ok, u)
	}
}

// TestEmptyPurposeRejected guards the strict purpose check: a token whose
// payload carries no purpose at all must be rejected (closes the legacy
// empty-allowed loophole the MFA token slipped through).
func TestEmptyPurposeRejected(t *testing.T) {
	ensureSigningKey()
	secret := sessionSecret()
	// hand-craft an enc payload with no "p" field
	raw := []byte(`{"u":"admin","exp":9999999999}`)
	enc := base64.RawURLEncoding.EncodeToString(raw)
	token := enc + "." + computeHMAC(enc, secret)
	if _, ok := verifySession(token); ok {
		t.Fatal("a token with no purpose must not be accepted as a session")
	}
}

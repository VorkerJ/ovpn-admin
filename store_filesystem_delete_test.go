package main

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// writeFakeEasyrsa drops a stub easyrsa binary whose `revoke` exits with
// revokeExit and whose `gen-crl` is a no-op success (the test pre-writes
// pki/crl.pem so CRL verification has something deterministic to read).
func writeFakeEasyrsa(t *testing.T, dir string, revokeExit int) string {
	t.Helper()
	bin := filepath.Join(dir, "easyrsa-fake.sh")
	script := fmt.Sprintf(`#!/bin/sh
case "$*" in
  *revoke*) exit %d ;;
  *gen-crl*) exit 0 ;;
esac
exit 0
`, revokeExit)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake easyrsa: %v", err)
	}
	return bin
}

// fsTestEnv builds a filesystemStore over a temp PKI dir. index.txt is seeded
// with the given lines; crl holds the raw crl.pem bytes to place on disk.
func fsTestEnv(t *testing.T, revokeExit int, indexTxt string, crl []byte) *filesystemStore {
	t.Helper()
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0o755); err != nil {
		t.Fatalf("mkdir pki: %v", err)
	}
	ccd := filepath.Join(dir, "ccd")
	if err := os.MkdirAll(ccd, 0o755); err != nil {
		t.Fatalf("mkdir ccd: %v", err)
	}
	indexTxtPath := filepath.Join(pki, "index.txt")
	if err := os.WriteFile(indexTxtPath, []byte(indexTxt), 0o600); err != nil {
		t.Fatalf("write index.txt: %v", err)
	}
	if crl != nil {
		if err := os.WriteFile(filepath.Join(pki, "crl.pem"), crl, 0o644); err != nil {
			t.Fatalf("write crl.pem: %v", err)
		}
	}
	return &filesystemStore{
		easyrsaDirPath: dir,
		easyrsaBinPath: writeFakeEasyrsa(t, dir, revokeExit),
		ccdDir:         ccd,
		indexTxtPath:   indexTxtPath,
	}
}

func vLine(serialHex, cn string) string {
	return fmt.Sprintf("V\t990101000000Z\t\t%s\tunknown\t/CN=%s\n", serialHex, cn)
}

func rLine(serialHex, cn string) string {
	return fmt.Sprintf("R\t990101000000Z\t200101000000Z\t%s\tunknown\t/CN=%s\n", serialHex, cn)
}

// crlWith builds a real CRL PEM for the given certs, returning it plus the
// first cert's serial hex (as index.txt would store it).
func crlWith(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	caCert, caKey := testCA(t)
	var revoked []*RevokedCert
	for _, c := range certs {
		revoked = append(revoked, &RevokedCert{Cert: c})
	}
	buf, err := genCRL(revoked, caCert, caKey)
	if err != nil {
		t.Fatalf("genCRL: %v", err)
	}
	return buf.Bytes()
}

// The core P0 regression: a genuine easyrsa revoke failure must NOT be reported
// as a successful delete. Before the fix the error was logged and delete
// returned nil, leaving a still-valid cert removed only from the UI.
func TestDeleteClientAbortsOnRevokeFailure(t *testing.T) {
	idx := vLine("0A0B0C", "alice")
	s := fsTestEnv(t, 1 /*revoke fails*/, idx, nil)

	err := s.DeleteClient("alice")
	if err == nil {
		t.Fatalf("DeleteClient: expected error on revoke failure, got nil (false success)")
	}
	// index.txt must be untouched — alice not renamed away.
	got := fRead(s.indexTxtPath)
	if want := "/CN=alice"; !contains(got, want) {
		t.Fatalf("index.txt should still contain %q after aborted delete, got:\n%s", want, got)
	}
	if contains(got, "REVOKED-alice") {
		t.Fatalf("index.txt must not be rewritten after aborted delete, got:\n%s", got)
	}
}

// When the cert is already revoked (flag R), a revoke error is benign: proceed
// and, since the serial is in the (pre-written) CRL, succeed.
func TestDeleteClientProceedsWhenAlreadyRevoked(t *testing.T) {
	caCert, caKey := testCA(t)
	cert := testClientCert(t, caCert, caKey, "bob")
	serial := fmt.Sprintf("%X", cert.SerialNumber)
	crl := crlWithSerial(t, serial)

	idx := rLine(serial, "bob")
	s := fsTestEnv(t, 1 /*revoke reports already-revoked*/, idx, crl)

	if err := s.DeleteClient("bob"); err != nil {
		t.Fatalf("DeleteClient: unexpected error for already-revoked cert: %v", err)
	}
}

// Happy path: revoke succeeds, serial is in the regenerated CRL -> nil.
func TestDeleteClientHappyPath(t *testing.T) {
	caCert, caKey := testCA(t)
	cert := testClientCert(t, caCert, caKey, "carol")
	serial := fmt.Sprintf("%X", cert.SerialNumber)
	crl := crlWithSerial(t, serial)

	idx := vLine(serial, "carol")
	s := fsTestEnv(t, 0 /*revoke ok*/, idx, crl)

	if err := s.DeleteClient("carol"); err != nil {
		t.Fatalf("DeleteClient happy path: unexpected error: %v", err)
	}
}

// Defense-in-depth: revoke "succeeds" but the serial never made it into the CRL
// (empty CRL) -> delete must fail rather than report a false success.
func TestDeleteClientFailsWhenSerialMissingFromCRL(t *testing.T) {
	caCert, caKey := testCA(t)
	cert := testClientCert(t, caCert, caKey, "dave")
	serial := fmt.Sprintf("%X", cert.SerialNumber)
	emptyCRL := crlWith(t) // no serials

	idx := vLine(serial, "dave")
	s := fsTestEnv(t, 0, idx, emptyCRL)

	if err := s.DeleteClient("dave"); err == nil {
		t.Fatalf("DeleteClient: expected error when serial absent from CRL")
	}
}

func TestRevokeClientAbortsOnRealFailure(t *testing.T) {
	idx := vLine("0A0B0C", "erin")
	s := fsTestEnv(t, 1, idx, nil)

	if err := s.RevokeClient("erin"); err == nil {
		t.Fatalf("RevokeClient: expected error on genuine revoke failure")
	}
}

func TestRevokeClientProceedsWhenAlreadyRevoked(t *testing.T) {
	caCert, caKey := testCA(t)
	cert := testClientCert(t, caCert, caKey, "frank")
	serial := fmt.Sprintf("%X", cert.SerialNumber)
	crl := crlWithSerial(t, serial)

	idx := rLine(serial, "frank")
	s := fsTestEnv(t, 1, idx, crl)

	if err := s.RevokeClient("frank"); err != nil {
		t.Fatalf("RevokeClient: unexpected error for already-revoked cert: %v", err)
	}
}

// crlWithSerial builds a real CRL whose single entry has the given serial hex.
func crlWithSerial(t *testing.T, serialHex string) []byte {
	t.Helper()
	caCert, caKey := testCA(t)
	// Build a synthetic cert carrying exactly serialHex so the CRL entry matches.
	tmpl := testClientCert(t, caCert, caKey, "crl-holder")
	tmpl.SerialNumber = mustSerial(t, serialHex)
	buf, err := genCRL([]*RevokedCert{{Cert: tmpl}}, caCert, caKey)
	if err != nil {
		t.Fatalf("genCRL: %v", err)
	}
	return buf.Bytes()
}

func mustSerial(t *testing.T, serialHex string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(serialHex, 16)
	if !ok {
		t.Fatalf("bad serial hex %q", serialHex)
	}
	return n
}

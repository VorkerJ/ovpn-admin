package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"

	v1 "k8s.io/api/core/v1"
)

func newFakeSecret(certPEM []byte) *v1.Secret {
	return &v1.Secret{Data: map[string][]byte{certFileName: certPEM}}
}

// testCA builds a throwaway CA + one client cert for CRL tests.
func testCA(t *testing.T) (caCert *x509.Certificate, caKey *rsa.PrivateKey) {
	t.Helper()
	caKeyPEM, err := genPrivKey()
	if err != nil {
		t.Fatalf("genPrivKey(ca): %v", err)
	}
	caKey, err = decodePrivKey(caKeyPEM.Bytes())
	if err != nil {
		t.Fatalf("decodePrivKey(ca): %v", err)
	}
	caCertPEM, err := genCA(caKey)
	if err != nil {
		t.Fatalf("genCA: %v", err)
	}
	caCert, err = decodeCert(caCertPEM.Bytes())
	if err != nil {
		t.Fatalf("decodeCert(ca): %v", err)
	}
	return caCert, caKey
}

func testClientCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	// kingpin defaults are only applied by Parse(), which tests don't call.
	if clientCertExpirationDays == nil || *clientCertExpirationDays == "" {
		days := "3650"
		clientCertExpirationDays = &days
	}
	keyPEM, err := genPrivKey()
	if err != nil {
		t.Fatalf("genPrivKey(client): %v", err)
	}
	key, err := decodePrivKey(keyPEM.Bytes())
	if err != nil {
		t.Fatalf("decodePrivKey(client): %v", err)
	}
	certPEM, err := genClientCert(key, caKey, caCert, cn)
	if err != nil {
		t.Fatalf("genClientCert: %v", err)
	}
	cert, err := decodeCert(certPEM.Bytes())
	if err != nil {
		t.Fatalf("decodeCert(client): %v", err)
	}
	return cert
}

// A revokedAt-bearing cert must actually appear in the CRL that genCRL emits,
// and crlContainsSerial (which drives verifyRevokedInCRL) must agree. This
// validates the invariant the K8s delete/rotate/revoke paths rely on: the
// RevokedCerts list equals the CRL contents.
func TestGenCRLIncludesRevokedSerial(t *testing.T) {
	caCert, caKey := testCA(t)
	revoked := testClientCert(t, caCert, caKey, "alice")
	other := testClientCert(t, caCert, caKey, "bob")

	pki := &OpenVPNPKI{CACert: caCert, CAPrivKeyRSA: caKey}
	// Mirror what easyrsaGenCRL stores after building the revoked set.
	pki.RevokedCerts = []RevokedCert{{Cert: revoked}}

	if !pki.crlContainsSerial(revoked.SerialNumber) {
		t.Fatalf("crlContainsSerial: revoked serial %s reported absent", revoked.SerialNumber)
	}
	if pki.crlContainsSerial(other.SerialNumber) {
		t.Fatalf("crlContainsSerial: non-revoked serial %s reported present", other.SerialNumber)
	}
	if pki.crlContainsSerial(nil) {
		t.Fatalf("crlContainsSerial(nil) should be false")
	}

	// The generated CRL PEM must really carry the serial (crypto round-trip).
	crlBuf, err := genCRL([]*RevokedCert{{Cert: revoked}}, caCert, caKey)
	if err != nil {
		t.Fatalf("genCRL: %v", err)
	}
	block, _ := pem.Decode(crlBuf.Bytes())
	if block == nil {
		t.Fatalf("genCRL produced no PEM block")
	}
	rl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if !crlEntriesHave(rl.RevokedCertificateEntries, revoked.SerialNumber) {
		t.Fatalf("generated CRL does not contain revoked serial %s", revoked.SerialNumber)
	}
	if crlEntriesHave(rl.RevokedCertificateEntries, other.SerialNumber) {
		t.Fatalf("generated CRL unexpectedly contains non-revoked serial %s", other.SerialNumber)
	}
}

func crlEntriesHave(entries []x509.RevocationListEntry, serial *big.Int) bool {
	for i := range entries {
		if entries[i].SerialNumber != nil && entries[i].SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// verifyRevokedInCRL must fail when the serial did not make it into the CRL,
// so the caller aborts instead of returning a false success.
func TestVerifyRevokedInCRLDetectsMissingSerial(t *testing.T) {
	caCert, caKey := testCA(t)
	cert := testClientCert(t, caCert, caKey, "carol")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	secret := newFakeSecret(certPEM)

	// RevokedCerts is empty -> serial absent -> must error.
	pki := &OpenVPNPKI{CACert: caCert, CAPrivKeyRSA: caKey}
	if err := pki.verifyRevokedInCRL("carol", secret); err == nil {
		t.Fatalf("verifyRevokedInCRL: expected error when serial absent from CRL")
	}

	// Now present -> must pass.
	pki.RevokedCerts = []RevokedCert{{Cert: cert}}
	if err := pki.verifyRevokedInCRL("carol", secret); err != nil {
		t.Fatalf("verifyRevokedInCRL: unexpected error when serial present: %v", err)
	}
}

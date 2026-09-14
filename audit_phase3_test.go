package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// TestAuditReservedStaticIPRejected locks audit F29: the subnet's network,
// server (network+1) and broadcast addresses cannot be assigned to a client.
func TestAuditReservedStaticIPRejected(t *testing.T) {
	prev := *openvpnNetwork
	*openvpnNetwork = "172.16.100.0/24"
	t.Cleanup(func() { *openvpnNetwork = prev })

	app := &OvpnAdmin{store: testFilesystemStore(t.TempDir())}

	for _, bad := range []string{"172.16.100.0", "172.16.100.1", "172.16.100.255"} {
		if ok, msg := app.validateCcd(Ccd{User: "alice", ClientAddress: bad}); ok {
			t.Errorf("F29: reserved address %s must be rejected (msg=%q)", bad, msg)
		}
	}
	// A regular free host address still validates.
	if ok, msg := app.validateCcd(Ccd{User: "alice", ClientAddress: "172.16.100.5"}); !ok {
		t.Fatalf("F29: free address 172.16.100.5 must validate, got %q", msg)
	}
}

// TestAuditStaticCCDMaskFollowsVPN locks audit F28: ifconfig-push carries the
// server's actual subnet mask, not a hardcoded /24, for a non-/24 VPN network.
func TestAuditStaticCCDMaskFollowsVPN(t *testing.T) {
	prev := *openvpnNetwork
	*openvpnNetwork = "172.16.0.0/16"
	t.Cleanup(func() { *openvpnNetwork = prev })

	dir := t.TempDir()
	app := newTestAdminCcd(t, dir)

	ok, msg := app.modifyCcd(Ccd{User: "alice", ClientAddress: "172.16.5.5"}, nil)
	if !ok {
		t.Fatalf("modifyCcd: %s", msg)
	}
	data, err := os.ReadFile(dir + "/alice")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "ifconfig-push 172.16.5.5 255.255.0.0") {
		t.Fatalf("F28: expected /16 mask in ifconfig-push, got:\n%s", content)
	}
	if strings.Contains(content, "255.255.255.0") {
		t.Fatalf("F28: hardcoded /24 mask leaked into CCD:\n%s", content)
	}
}

// TestAuditCRLRegenerate locks audit F40: the store exposes a CRL regeneration
// entry point the renewal loop can call.
func TestAuditCRLRegenerate(t *testing.T) {
	// fsTestEnv's fake easyrsa treats gen-crl as exit 0.
	s := fsTestEnv(t, 0, vLine("0A0B0C", "alice"), nil)
	if err := s.RegenerateCRL(); err != nil {
		t.Fatalf("F40: RegenerateCRL must succeed with a working gen-crl: %v", err)
	}
}

// TestAuditCRLExpiryDetected locks the readiness half of audit F40: an expired
// CRL's NextUpdate is in the past, which readiness flags as unhealthy.
func TestAuditCRLExpiryDetected(t *testing.T) {
	caCert, caKey := testCA(t)
	dir := t.TempDir()
	path := dir + "/crl.pem"

	// A CRL whose NextUpdate is already in the past.
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-1 * time.Hour),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	nextUpdate, err := crlNextUpdate(path)
	if err != nil {
		t.Fatalf("crlNextUpdate: %v", err)
	}
	if !time.Now().After(nextUpdate) {
		t.Fatal("F40: an expired CRL must be detected (NextUpdate in the past)")
	}
}

// TestAuditPasswordAuthRejectedOnK8sBackend locks audit F18: enabling
// PasswordAuth is refused on the kubernetes.secrets backend (which provisions no
// auth-verify script / users.db), instead of rendering a broken server config.
func TestAuditPasswordAuthRejectedOnK8sBackend(t *testing.T) {
	prev := *storageBackend
	*storageBackend = "kubernetes.secrets"
	t.Cleanup(func() { *storageBackend = prev })

	cfg := defaultServerConfig()
	cfg.PasswordAuth = true
	if err := validateServerConfig(cfg); err == nil {
		t.Fatal("F18: password_auth on kubernetes.secrets backend must be rejected")
	}

	*storageBackend = "filesystem"
	if err := validateServerConfig(cfg); err != nil {
		t.Fatalf("F18: password_auth on filesystem backend must be allowed: %v", err)
	}
}

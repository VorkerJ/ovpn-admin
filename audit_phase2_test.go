package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"testing"
)

// fakeMgmtListener starts a throwaway TCP server that runs handle(conn) for each
// connection, and returns its address. Used to drive the mgmt-console code paths.
func fakeMgmtListener(t *testing.T, handle func(conn net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	return ln.Addr().String()
}

const mgmtWelcome = ">INFO:OpenVPN Management Interface Version 3 -- type 'help' for more info\n"

// TestAuditMgmtDuplicateCNHasDistinctAddresses locks audit F11: two concurrent
// sessions of one CN (duplicate-cn) each keep their own VPN IP, matched by
// CN+RealAddress rather than CN alone (which gave the first row both and left
// the second empty).
func TestAuditMgmtDuplicateCNHasDistinctAddresses(t *testing.T) {
	app := &OvpnAdmin{mgmtStatusTimeFormat: "2006-01-02 15:04:05"}
	status := "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n" +
		"alice,10.0.0.1:1111,100,200,2026-01-01 00:00:00\n" +
		"alice,10.0.0.2:2222,300,400,2026-01-01 00:00:00\n" +
		"ROUTING TABLE\n" +
		"Virtual Address,Common Name,Real Address,Last Ref\n" +
		"172.16.100.2,alice,10.0.0.1:1111,2026-01-01 00:00:00\n" +
		"172.16.100.3,alice,10.0.0.2:2222,2026-01-01 00:00:00\n" +
		"GLOBAL STATS\n" +
		"END\n"

	u := app.mgmtConnectedUsersParser(status, "main")
	if len(u) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(u))
	}
	byReal := map[string]string{}
	for _, c := range u {
		byReal[c.RealAddress] = c.VirtualAddress
	}
	if byReal["10.0.0.1:1111"] != "172.16.100.2" || byReal["10.0.0.2:2222"] != "172.16.100.3" {
		t.Fatalf("F11: duplicate-cn addresses not distinct: %+v", byReal)
	}
}

// TestAuditMgmtHasEndLine locks the standalone-END detection used by F12.
func TestAuditMgmtHasEndLine(t *testing.T) {
	if !mgmtHasEndLine("a\nEND\n") || !mgmtHasEndLine("x\r\nEND\r\n") {
		t.Fatal("F12: standalone END line must be detected")
	}
	if mgmtHasEndLine("SENDING\nnot done\n") {
		t.Fatal("F12: substring END inside a field must NOT count as terminator")
	}
}

// TestAuditMgmtClosedStreamIsUnknown locks audit F12: a console that closes
// after the welcome banner (no END) is reported as UNKNOWN (ok=false), not as an
// authoritative empty client list.
func TestAuditMgmtClosedStreamIsUnknown(t *testing.T) {
	addr := fakeMgmtListener(t, func(conn net.Conn) {
		defer conn.Close()
		_, _ = conn.Write([]byte(mgmtWelcome))
		r := bufio.NewReader(conn)
		_, _ = r.ReadString('\n') // read "status 1"
		// close WITHOUT sending any status / END
	})
	app := &OvpnAdmin{mgmtInterfaces: map[string]string{"main": addr}}
	clients, ok := app.mgmtGetActiveClients()
	if ok {
		t.Fatalf("F12: torn stream must be reported as unknown (ok=false), got ok=true clients=%v", clients)
	}
}

// TestAuditKillRequiresAck locks audit F13: mgmtKillUserConnection returns an
// error unless the console acknowledges with SUCCESS.
func TestAuditKillRequiresAck(t *testing.T) {
	// Server that ACKs.
	okAddr := fakeMgmtListener(t, func(conn net.Conn) {
		defer conn.Close()
		_, _ = conn.Write([]byte(mgmtWelcome))
		r := bufio.NewReader(conn)
		_, _ = r.ReadString('\n')
		_, _ = conn.Write([]byte("SUCCESS: common name 'alice' found, 1 client(s) killed\n"))
	})
	// Server that reports not-found (no SUCCESS).
	errAddr := fakeMgmtListener(t, func(conn net.Conn) {
		defer conn.Close()
		_, _ = conn.Write([]byte(mgmtWelcome))
		r := bufio.NewReader(conn)
		_, _ = r.ReadString('\n')
		_, _ = conn.Write([]byte("ERROR: common name 'alice' not found\n"))
	})

	app := &OvpnAdmin{mgmtInterfaces: map[string]string{"ok": okAddr, "bad": errAddr}}
	if err := app.mgmtKillUserConnection("alice", "ok"); err != nil {
		t.Fatalf("F13: acked kill must return nil, got %v", err)
	}
	if err := app.mgmtKillUserConnection("alice", "bad"); err == nil {
		t.Fatal("F13: kill without SUCCESS ack must return an error")
	}
	// Unreachable interface → error.
	app2 := &OvpnAdmin{mgmtInterfaces: map[string]string{"down": "127.0.0.1:1"}}
	if err := app2.mgmtKillUserConnection("alice", "down"); err == nil {
		t.Fatal("F13: unreachable mgmt must return an error")
	}
}

// TestAuditFirewallClientToClientRejected locks audit F08: when server-side
// enforcement (--firewall) is on, client-to-client must be rejected by config
// validation (it would bypass the per-user FORWARD rules).
func TestAuditFirewallClientToClientRejected(t *testing.T) {
	prev := firewallEnabled
	on := true
	firewallEnabled = &on
	t.Cleanup(func() { firewallEnabled = prev })

	cfg := defaultServerConfig()
	cfg.ClientToClient = true
	if err := validateServerConfig(cfg); err == nil {
		t.Fatal("F08: client_to_client + firewall must be rejected")
	}
	cfg.ClientToClient = false
	if err := validateServerConfig(cfg); err != nil {
		t.Fatalf("F08: client_to_client=false with firewall must validate: %v", err)
	}
}

// TestAuditFirewallPartialInstallRollsBack locks audit F09: if installing the
// ACCEPT set fails midway, the rules already added in that call are rolled back
// (a -D is issued) so a later retry starts clean and no duplicate leaks.
func TestAuditFirewallPartialInstallRollsBack(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	inserts := 0
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		if len(args) > 2 && args[0] == "-I" && args[2] == "2" {
			inserts++
			if inserts == 2 {
				return fmt.Errorf("iptables: simulated failure on 2nd rule")
			}
		}
		return nil
	}
	fc := newFirewallController(nil, "OVPN_FW", "iptables", vpnNet, iptMock)
	err := fc.installRulesFor("alice", "172.16.100.5", []string{"10.0.0.0/8", "192.168.0.0/16"})
	if err == nil {
		t.Fatal("F09: partial install must return an error")
	}
	// A -D must have been issued to roll back the first (successful) insert.
	rolledBack := false
	for _, c := range cmds {
		if len(c) > 1 && c[0] == "-D" && containsAll(joinSpace(c), "10.0.0.0/8") {
			rolledBack = true
		}
	}
	if !rolledBack {
		t.Fatalf("F09: first rule must be rolled back with -D; commands: %v", cmds)
	}
}

// TestAuditFirewallReconcileRefreshesLiveSession locks audit F10: the periodic
// reconcile recomputes policy for a STILL-LIVE session, so a change that arrived
// without a firewall event converges (old CIDR removed, new one added) instead
// of lingering for the life of the session.
func TestAuditFirewallReconcileRefreshesLiveSession(t *testing.T) {
	_, vpnNet, _ := net.ParseCIDR("172.16.100.0/24")
	var cmds [][]string
	iptMock := func(args ...string) error {
		cmds = append(cmds, append([]string(nil), args...))
		return nil
	}
	// Desired policy now allows only 192.168.0.0/16 (via a common route).
	reader := fakeCcdReader{common: CommonRoutesConfig{Routes: []CommonRouteEntry{
		{ID: "r1", Kind: "ip", Address: "192.168.0.0", Mask: "255.255.0.0"},
	}}}
	fc := newFirewallController(reader, "OVPN_FW", "iptables", vpnNet, iptMock)
	// A live session currently has the OLD CIDR installed.
	key := sessionKey{CN: "alice", VpnIP: "172.16.100.5"}
	fc.sessions[key] = &fwSession{CN: "alice", VpnIP: "172.16.100.5", AllowedCIDRs: []string{"10.0.0.0/8"}, RulesInstalled: true}
	fc.mgmtSnapshot = func() ([]clientStatus, bool) {
		return []clientStatus{{CommonName: "alice", VirtualAddress: "172.16.100.5"}}, true
	}

	fc.mu.Lock()
	fc.reconcileLocked()
	fc.mu.Unlock()

	delOld, addNew := false, false
	for _, c := range cmds {
		j := joinSpace(c)
		if c[0] == "-D" && containsAll(j, "10.0.0.0/8") {
			delOld = true
		}
		if c[0] == "-I" && containsAll(j, "192.168.0.0/16") {
			addNew = true
		}
	}
	if !delOld || !addNew {
		t.Fatalf("F10: reconcile must converge live session (delOld=%v addNew=%v); cmds: %v", delOld, addNew, cmds)
	}
}

// TestAuditSchedulerDoesNotRestoreDeletedRoute locks audit F33: if a common
// route is deleted while the DNS scheduler is mid-resolve, the scheduler's write
// (an atomic CAS that only touches routes still present) must NOT resurrect it.
func TestAuditSchedulerDoesNotRestoreDeletedRoute(t *testing.T) {
	dir := t.TempDir()
	app := &OvpnAdmin{
		store:        testFilesystemStore(dir),
		commonRoutes: &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{{ID: "r1", Kind: "domain", Domain: "example.com"}}}},
	}

	// The resolver deletes r1 (as a concurrent admin request would) BEFORE
	// returning, so by the time refreshCommonRoutesOnce commits, r1 is gone.
	prev := domainResolver
	domainResolver = func(ctx context.Context, d string) ([]string, error) {
		_, _ = app.commonRoutes.update(func(cfg *CommonRoutesConfig) error {
			cfg.Routes = nil // admin deleted the route mid-flight
			return nil
		}, app.persistCommonRoutes)
		return []string{"1.2.3.4"}, nil
	}
	t.Cleanup(func() { domainResolver = prev })

	app.refreshCommonRoutesOnce(context.Background())

	if got := len(app.commonRoutes.snapshot().Routes); got != 0 {
		t.Fatalf("F33: deleted route was resurrected by the scheduler (routes=%d)", got)
	}
}

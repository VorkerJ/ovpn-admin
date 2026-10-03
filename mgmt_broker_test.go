package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// N06 (F14): closing the review's last finding. While the mgmt-client-auth loop
// OWNS the single-client console, every other consumer must still work by being
// multiplexed over that one connection — not fail trying to open a second
// (refused) one. This drives the real scenario end-to-end on one fake console:
// an async >CLIENT: auth event is answered AND a sync `status` AND a sync `kill`
// all succeed concurrently.
func TestReauditMgmtBrokerMultiplexesAuthAndCommands(t *testing.T) {
	origIdx := *indexTxtPath
	t.Cleanup(func() { *indexTxtPath = origIdx })
	*indexTxtPath = writeIndexTxtWithUser(t, "alice")

	authCh := make(chan string, 1)
	var wmu sync.Mutex
	write := func(c net.Conn, s string) {
		wmu.Lock()
		_, _ = fmt.Fprint(c, s)
		wmu.Unlock()
	}

	addr := fakeMgmtListener(t, func(conn net.Conn) {
		// Welcome banner (drainWelcome waits for the "type 'help'" hint).
		write(conn, ">INFO:OpenVPN Management Interface -- type 'help' for more info\r\n")
		// Emit an async client-auth block shortly after connect — this must be
		// answered even while sync commands are in flight.
		go func() {
			time.Sleep(80 * time.Millisecond)
			write(conn, ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,common_name=alice\r\n>CLIENT:ENV,END\r\n")
		}()
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "status"):
				write(conn, "OpenVPN CLIENT LIST\r\n"+
					"Updated,2024-01-01 00:00:00\r\n"+
					"Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\r\n"+
					"alice,10.0.0.9:1194,100,200,2024-01-01 00:00:00\r\n"+
					"ROUTING TABLE\r\n"+
					"Virtual Address,Common Name,Real Address,Last Ref\r\n"+
					"10.20.30.9,alice,10.0.0.9:1194,2024-01-01 00:00:00\r\n"+
					"GLOBAL STATS\r\n"+
					"END\r\n")
			case strings.HasPrefix(line, "kill "):
				write(conn, "SUCCESS: common name 'alice' found, 1 client(s) killed\r\n")
			case strings.HasPrefix(line, "signal "):
				write(conn, "SUCCESS: signal thrown\r\n")
			case strings.HasPrefix(line, "client-auth-nt"):
				select {
				case authCh <- line:
				default:
				}
			}
		}
	})

	app := &OvpnAdmin{
		mgmtInterfaces:       map[string]string{"main": addr},
		mgmtStatusTimeFormat: "2006-01-02 15:04:05",
	}
	app.startMgmtClientAuth()
	t.Cleanup(app.stopMgmtClientAuth)

	// Wait for the broker to take ownership of the console.
	deadline := time.Now().Add(3 * time.Second)
	for app.lookupBroker("main") == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if app.lookupBroker("main") == nil {
		t.Fatal("N06: broker did not register — auth loop never took the console")
	}

	// (1) The async auth event is answered while the broker owns the console.
	select {
	case <-authCh:
	case <-time.After(3 * time.Second):
		t.Fatal("N06: >CLIENT auth event was not answered on the broker-owned console")
	}

	// (2) A sync status poll is multiplexed over the same connection.
	clients, ok := app.mgmtGetActiveClients()
	if !ok {
		t.Fatal("N06: mgmtGetActiveClients via broker returned not-ok")
	}
	found := false
	for _, c := range clients {
		if c.CommonName == "alice" {
			found = true
		}
	}
	if !found {
		t.Fatalf("N06: status via broker did not return alice: %+v", clients)
	}

	// (3) A sync kill is multiplexed over the same connection.
	if err := app.mgmtKillUserConnection("alice", "main"); err != nil {
		t.Fatalf("N06: kill via broker failed: %v", err)
	}
}

// Fallback contract: with no auth loop (mgmt-client-auth OFF — the common case),
// lookupBroker is nil so console ops take the direct-dial path unchanged.
func TestReauditMgmtBrokerAbsentFallsBackToDirect(t *testing.T) {
	app := &OvpnAdmin{mgmtInterfaces: map[string]string{"main": "127.0.0.1:1"}}
	if app.lookupBroker("main") != nil {
		t.Fatal("no auth loop started → broker must be nil (direct-dial path)")
	}
	// Direct path to a closed port returns not-ok (not a panic / not a broker hang).
	if _, ok := app.mgmtGetActiveClients(); ok {
		t.Fatal("expected not-ok from a closed mgmt port on the direct path")
	}
}

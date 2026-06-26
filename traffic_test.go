package main

import (
	"path/filepath"
	"testing"
)

func cs(name, since, rx, tx string) clientStatus {
	return clientStatus{CommonName: name, ConnectedSince: since, BytesReceived: rx, BytesSent: tx}
}

func totalOf(ta *trafficAccountant, user string) (uint64, uint64) {
	ta.mu.Lock()
	defer ta.mu.Unlock()
	t := ta.totals[user]
	if t == nil {
		return 0, 0
	}
	return t.RxBytes, t.TxBytes
}

func TestTrafficAccumulation(t *testing.T) {
	ta := newTrafficAccountant("")

	// First sighting: whole counter counts.
	ta.update([]clientStatus{cs("alice", "2026-01-01 10:00:00", "100", "200")})
	if rx, tx := totalOf(ta, "alice"); rx != 100 || tx != 200 {
		t.Fatalf("first poll: got rx=%d tx=%d, want 100/200", rx, tx)
	}

	// Same session grows: only the delta is added.
	ta.update([]clientStatus{cs("alice", "2026-01-01 10:00:00", "150", "260")})
	if rx, tx := totalOf(ta, "alice"); rx != 150 || tx != 260 {
		t.Fatalf("same-session: got rx=%d tx=%d, want 150/260", rx, tx)
	}

	// Reconnect (ConnectedSince changes, counters reset to small values):
	// the new session's counter is added in full on top of the old total.
	ta.update([]clientStatus{cs("alice", "2026-01-01 12:00:00", "10", "20")})
	if rx, tx := totalOf(ta, "alice"); rx != 160 || tx != 280 {
		t.Fatalf("reconnect: got rx=%d tx=%d, want 160/280", rx, tx)
	}
}

func TestTrafficDisconnectReconnect(t *testing.T) {
	ta := newTrafficAccountant("")
	ta.update([]clientStatus{cs("bob", "s1", "500", "500")}) // 500/500
	ta.update([]clientStatus{})                              // bob disconnects, session forgotten
	ta.update([]clientStatus{cs("bob", "s2", "300", "300")}) // reconnects -> +300/300

	if rx, tx := totalOf(ta, "bob"); rx != 800 || tx != 800 {
		t.Fatalf("disconnect/reconnect: got rx=%d tx=%d, want 800/800", rx, tx)
	}
}

func TestTrafficSnapshotSortedAndPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "traffic.json")
	ta := newTrafficAccountant(path)
	ta.update([]clientStatus{
		cs("small", "s", "10", "10"),   // total 20
		cs("big", "s", "1000", "1000"), // total 2000
		cs("mid", "s", "100", "100"),   // total 200
	})
	rows := ta.snapshot()
	if len(rows) != 3 || rows[0].User != "big" || rows[2].User != "small" {
		t.Fatalf("snapshot not sorted by total desc: %+v", rows)
	}
	if !rows[0].Connected || rows[0].TotalBytes != 2000 {
		t.Fatalf("big row: connected=%v total=%d", rows[0].Connected, rows[0].TotalBytes)
	}

	// Persist then reload into a fresh accountant — totals survive a restart.
	ta.persist()
	ta2 := newTrafficAccountant(path)
	if rx, tx := totalOf(ta2, "big"); rx != 1000 || tx != 1000 {
		t.Fatalf("reload: got rx=%d tx=%d, want 1000/1000", rx, tx)
	}
	// After reload (no live poll), the user is not marked connected.
	for _, r := range ta2.snapshot() {
		if r.User == "big" && r.Connected {
			t.Fatal("reloaded user must not be 'connected' until next poll")
		}
	}
}

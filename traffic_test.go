package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func cs(name, since, rx, tx string) clientStatus {
	return clientStatus{CommonName: name, ConnectedSince: since, BytesReceived: rx, BytesSent: tx}
}

// monthTotal reads a user's rx/tx for a given month bucket straight from the DB.
func monthTotal(t *testing.T, ta *trafficAccountant, user, month string) (uint64, uint64) {
	t.Helper()
	var rx, tx uint64
	err := ta.db.QueryRow("SELECT rx_bytes, tx_bytes FROM traffic_monthly WHERE username = ? AND month = ?", user, month).Scan(&rx, &tx)
	if err != nil {
		return 0, 0
	}
	return rx, tx
}

func newTestAccountant(t *testing.T) *trafficAccountant {
	t.Helper()
	ta := newTrafficAccountant(filepath.Join(t.TempDir(), "traffic.db"))
	if ta.db == nil {
		t.Fatal("expected an open SQLite db")
	}
	return ta
}

func TestTrafficAccumulation(t *testing.T) {
	ta := newTestAccountant(t)
	m := currentMonth()

	// First sighting: whole counter counts.
	ta.update([]clientStatus{cs("alice", "2026-01-01 10:00:00", "100", "200")})
	if rx, tx := monthTotal(t, ta, "alice", m); rx != 100 || tx != 200 {
		t.Fatalf("first poll: got rx=%d tx=%d, want 100/200", rx, tx)
	}

	// Same session grows: only the delta is added.
	ta.update([]clientStatus{cs("alice", "2026-01-01 10:00:00", "150", "260")})
	if rx, tx := monthTotal(t, ta, "alice", m); rx != 150 || tx != 260 {
		t.Fatalf("same-session: got rx=%d tx=%d, want 150/260", rx, tx)
	}

	// Reconnect (ConnectedSince changes, counters reset): new counter added in full.
	ta.update([]clientStatus{cs("alice", "2026-01-01 12:00:00", "10", "20")})
	if rx, tx := monthTotal(t, ta, "alice", m); rx != 160 || tx != 280 {
		t.Fatalf("reconnect: got rx=%d tx=%d, want 160/280", rx, tx)
	}
}

func TestTrafficDisconnectReconnect(t *testing.T) {
	ta := newTestAccountant(t)
	m := currentMonth()
	ta.update([]clientStatus{cs("bob", "s1", "500", "500")}) // 500/500
	ta.update([]clientStatus{})                              // bob disconnects, session forgotten
	ta.update([]clientStatus{cs("bob", "s2", "300", "300")}) // reconnects -> +300/300

	if rx, tx := monthTotal(t, ta, "bob", m); rx != 800 || tx != 800 {
		t.Fatalf("disconnect/reconnect: got rx=%d tx=%d, want 800/800", rx, tx)
	}
}

// TestTrafficRestartResumesSession verifies the persisted session snapshot stops
// a still-connected user's elapsed bytes from being double-counted on restart.
func TestTrafficRestartResumesSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.db")
	m := currentMonth()

	ta := newTrafficAccountant(path)
	ta.update([]clientStatus{cs("carol", "s1", "400", "400")})
	if rx, _ := monthTotal(t, ta, "carol", m); rx != 400 {
		t.Fatalf("pre-restart: rx=%d, want 400", rx)
	}
	_ = ta.db.Close()

	// Restart: same session keeps growing. The already-counted 400 must not be
	// re-added; only the growth (500-400=100) counts.
	ta2 := newTrafficAccountant(path)
	ta2.update([]clientStatus{cs("carol", "s1", "500", "500")})
	if rx, tx := monthTotal(t, ta2, "carol", m); rx != 500 || tx != 500 {
		t.Fatalf("post-restart same session: got rx=%d tx=%d, want 500/500", rx, tx)
	}
}

func TestTrafficSnapshotSortedAndAllTime(t *testing.T) {
	ta := newTestAccountant(t)
	ta.update([]clientStatus{
		cs("small", "s", "10", "10"),   // total 20
		cs("big", "s", "1000", "1000"), // total 2000
		cs("mid", "s", "100", "100"),   // total 200
	})
	resp := ta.snapshot("") // current month
	if len(resp.Rows) != 3 || resp.Rows[0].User != "big" || resp.Rows[2].User != "small" {
		t.Fatalf("snapshot not sorted by total desc: %+v", resp.Rows)
	}
	if !resp.Rows[0].Connected || resp.Rows[0].TotalBytes != 2000 || resp.Rows[0].AllTimeBytes != 2000 {
		t.Fatalf("big row: connected=%v total=%d allTime=%d", resp.Rows[0].Connected, resp.Rows[0].TotalBytes, resp.Rows[0].AllTimeBytes)
	}
	if len(resp.Months) == 0 || resp.Month == "" {
		t.Fatalf("snapshot must report month %q and months %v", resp.Month, resp.Months)
	}
}

// TestTrafficLegacyImport verifies a pre-existing traffic.json is folded into the
// monthly DB once, preserving the all-time total, and then renamed.
func TestTrafficLegacyImport(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "traffic.json")
	dbPath := filepath.Join(dir, "traffic.db")

	legacy := map[string]map[string]interface{}{
		"olduser": {"rx_bytes": 1234, "tx_bytes": 5678, "updated_at": "2026-05-20T10:00:00Z"},
	}
	raw, _ := json.Marshal(legacy)
	if err := os.WriteFile(jsonPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	ta := newTrafficAccountant(dbPath)
	if rx, tx := monthTotal(t, ta, "olduser", "2026-05"); rx != 1234 || tx != 5678 {
		t.Fatalf("legacy import: got rx=%d tx=%d, want 1234/5678 in 2026-05", rx, tx)
	}
	// all-time total surfaces in snapshot
	resp := ta.snapshot("2026-05")
	if len(resp.Rows) != 1 || resp.Rows[0].AllTimeBytes != 1234+5678 {
		t.Fatalf("legacy all-time: %+v", resp.Rows)
	}
	// JSON renamed to .imported, not re-imported on a second open
	if _, err := os.Stat(jsonPath); !os.IsNotExist(err) {
		t.Fatal("legacy json should have been renamed away")
	}
	if _, err := os.Stat(jsonPath + ".imported"); err != nil {
		t.Fatalf("legacy json backup missing: %v", err)
	}
}

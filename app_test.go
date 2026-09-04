package main

import "testing"

// TestApplyActiveClientsPollSkipsOnFailedPoll locks FINDING #13: a failed mgmt
// poll (ok==false) must NOT overwrite the cached active-clients snapshot with an
// empty/partial set — doing so would fabricate a disconnect for every client and
// corrupt traffic accounting. The last-known set must survive until the next
// successful poll.
func TestApplyActiveClientsPollSkipsOnFailedPoll(t *testing.T) {
	app := &OvpnAdmin{} // traffic is nil; this exercises the snapshot logic only

	known := []clientStatus{{CommonName: "alice"}, {CommonName: "bob"}}
	app.setActiveClients(known)

	// A failed poll must be a no-op for the snapshot and report no update.
	if app.applyActiveClientsPoll(nil, false) {
		t.Fatal("failed poll (ok=false) must report no snapshot update")
	}
	if got := app.snapshotActiveClients(); len(got) != 2 {
		t.Fatalf("failed poll overwrote the cached snapshot: want 2 last-known clients, got %d", len(got))
	}

	// A successful poll — even an empty one — legitimately replaces the snapshot.
	if !app.applyActiveClientsPoll([]clientStatus{}, true) {
		t.Fatal("successful poll must report an update")
	}
	if got := app.snapshotActiveClients(); len(got) != 0 {
		t.Fatalf("successful empty poll must clear the snapshot, got %d", len(got))
	}

	// A successful poll with clients installs the new set.
	app.applyActiveClientsPoll(known, true)
	if got := app.snapshotActiveClients(); len(got) != 2 {
		t.Fatalf("successful poll must install the new client set, got %d", len(got))
	}
}

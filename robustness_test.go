package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestActiveClients_ConcurrentAccessRaceClean exercises setState (the writer)
// and the readers of activeClients (snapshotActiveClients / getUserStatistic)
// concurrently. Before activeClientsMu was introduced this tripped the race
// detector; `go test -race` must now be clean.
func TestActiveClients_ConcurrentAccessRaceClean(t *testing.T) {
	app := &OvpnAdmin{}

	const workers = 8
	const iters = 200
	var wg sync.WaitGroup

	// Direct writers via the guarded setter (bypasses the single-flight guard,
	// so these truly run concurrently with the readers).
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				app.setActiveClients([]clientStatus{
					{CommonName: fmt.Sprintf("user-%d-%d", id, i)},
				})
			}
		}(w)
	}

	// Writers via setState — the real production write path (poll -> setter),
	// which also touches updateClients/usersList (another activeClients reader).
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				app.setState()
			}
		}()
	}

	// Readers.
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				_ = app.snapshotActiveClients()
				_ = app.getUserStatistic("user-0-0")
			}
		}()
	}

	wg.Wait()
}

// TestIndexTxtParser_MalformedLinesNoPanic feeds short/corrupt lines to the
// index.txt parser and asserts it skips them without panicking, while a
// well-formed V/R line still parses.
func TestIndexTxtParser_MalformedLinesNoPanic(t *testing.T) {
	t.Parallel()
	malformed := []string{
		"V",                 // V with no other fields
		"V\t260101000000Z",  // still too few for V
		"V\t1\t2\t3",        // 4 fields, V needs 5
		"R",                 // R with no other fields
		"R\t1\t2",           // too few for R
		"R\t1\t2\t3\t4",     // 5 fields, R needs 6
		"garbage line here", // no V/R prefix
		"",                  // empty
		"   ",               // whitespace only
	}
	for _, in := range malformed {
		got := indexTxtParser(in) // must not panic
		if len(got) != 0 {
			t.Errorf("indexTxtParser(%q) = %v; want empty", in, got)
		}
	}

	// A well-formed V line and R line still parse (strings.Fields collapses the
	// empty revocation column of the V line).
	good := "V\t260101000000Z\t\t3E\tunknown\t/CN=alice\n" +
		"R\t260101000000Z\t250101000000Z\t3F\tunknown\t/CN=bob\n"
	parsed := indexTxtParser(good)
	if len(parsed) != 2 {
		t.Fatalf("indexTxtParser(good) len = %d; want 2 (%v)", len(parsed), parsed)
	}
	if parsed[0].Identity != "alice" || parsed[1].Identity != "bob" {
		t.Errorf("identities = %q,%q; want alice,bob", parsed[0].Identity, parsed[1].Identity)
	}
}

// TestMgmtConnectedUsersParser_MalformedLinesNoPanic feeds truncated status
// rows to the CSV parser and asserts it skips them without panicking while a
// well-formed row is still parsed.
func TestMgmtConnectedUsersParser_MalformedLinesNoPanic(t *testing.T) {
	t.Parallel()
	app := &OvpnAdmin{mgmtStatusTimeFormat: "2006-01-02 15:04:05"}

	text := "" +
		"Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n" +
		"short,row\n" + // 2 fields, needs 5 -> skip
		"alice,1.2.3.4:5,100,200,2020-01-01 00:00:00\n" +
		"ROUTING TABLE\n" +
		"Virtual Address,Common Name,Real Address,Last Ref\n" +
		"short\n" + // 1 field, needs 4 -> skip
		"10.0.0.2,alice,1.2.3.4:5,2020-01-01 00:00:00\n" +
		"GLOBAL STATS\n"

	got := app.mgmtConnectedUsersParser(text, "server1") // must not panic
	if len(got) != 1 {
		t.Fatalf("parsed %d clients; want 1 (%v)", len(got), got)
	}
	if got[0].CommonName != "alice" || got[0].VirtualAddress != "10.0.0.2" {
		t.Errorf("client = %+v; want alice @ 10.0.0.2", got[0])
	}
}

// TestDecodeCert_NoPEMBlock ensures decodeCert returns an error (not a nil
// pointer panic) when handed data that holds no PEM block.
func TestDecodeCert_NoPEMBlock(t *testing.T) {
	t.Parallel()
	if _, err := decodeCert([]byte("this is not a PEM block")); err == nil {
		t.Fatal("decodeCert(non-PEM) = nil error; want error")
	}
}

// TestDecodePrivKey_NoPEMBlock ensures decodePrivKey returns an error rather
// than panicking on non-PEM input.
func TestDecodePrivKey_NoPEMBlock(t *testing.T) {
	t.Parallel()
	if _, err := decodePrivKey([]byte("this is not a PEM block")); err == nil {
		t.Fatal("decodePrivKey(non-PEM) = nil error; want error")
	}
}

// writeIndexTxtWithUser writes a minimal easyrsa index.txt containing a single
// valid cert for username and returns the path.
func writeIndexTxtWithUser(t *testing.T, username string) string {
	t.Helper()
	dir := t.TempDir()
	idx := filepath.Join(dir, "index.txt")
	line := fmt.Sprintf("V\t260101000000Z\t\t3E\tunknown\t/CN=%s\n", username)
	if err := os.WriteFile(idx, []byte(line), 0600); err != nil {
		t.Fatalf("write index.txt: %v", err)
	}
	return idx
}

// TestUserDelete_PropagatesOpenvpnUserError verifies that when the password-auth
// openvpn-user delete step fails, userDeleteHandler returns a non-200 instead of
// swallowing the failure and reporting success (FINDING #4).
func TestUserDelete_PropagatesOpenvpnUserError(t *testing.T) {
	origRun := runOpenvpnUser
	origAuth := *authByPassword
	origIdx := *indexTxtPath
	origDb := *authDatabase
	t.Cleanup(func() {
		runOpenvpnUser = origRun
		*authByPassword = origAuth
		*indexTxtPath = origIdx
		*authDatabase = origDb
	})

	*indexTxtPath = writeIndexTxtWithUser(t, "alice")
	*authByPassword = true
	*authDatabase = filepath.Join(t.TempDir(), "users.db")
	runOpenvpnUser = func(args ...string) (string, error) {
		return "boom", fmt.Errorf("simulated openvpn-user failure")
	}

	app := &OvpnAdmin{}
	req := httptest.NewRequest(http.MethodPost, "/api/user/delete", bytes.NewReader([]byte(`{"username":"alice"}`)))
	rec := httptest.NewRecorder()
	app.userDeleteHandler(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("expected non-200 when openvpn-user delete fails, got 200 body=%s", rec.Body.String())
	}
}

// TestUserChangePassword_PropagatesOpenvpnUserError verifies that a failed
// openvpn-user change-password step makes the handler return a non-200 rather
// than reporting a password change that did not happen (FINDING #4).
func TestUserChangePassword_PropagatesOpenvpnUserError(t *testing.T) {
	origRun := runOpenvpnUser
	origAuth := *authByPassword
	origIdx := *indexTxtPath
	origDb := *authDatabase
	t.Cleanup(func() {
		runOpenvpnUser = origRun
		*authByPassword = origAuth
		*indexTxtPath = origIdx
		*authDatabase = origDb
	})

	*indexTxtPath = writeIndexTxtWithUser(t, "alice")
	*authByPassword = true // makes passwordAuthActive() true
	*authDatabase = filepath.Join(t.TempDir(), "users.db")
	// Succeed on check/create, fail on change-password.
	runOpenvpnUser = func(args ...string) (string, error) {
		for _, a := range args {
			if a == "change-password" {
				return "", fmt.Errorf("simulated change-password failure")
			}
		}
		return "ok", nil
	}

	app := &OvpnAdmin{}
	body := []byte(`{"username":"alice","password":"hunter22"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/user/change-password", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.userChangePasswordHandler(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("expected non-200 when openvpn-user change-password fails, got 200 body=%s", rec.Body.String())
	}
}

// TestUserChangePassword_SucceedsWhenOpenvpnUserOK is the positive counterpart:
// with a runner that always succeeds, the handler returns 200.
func TestUserChangePassword_SucceedsWhenOpenvpnUserOK(t *testing.T) {
	origRun := runOpenvpnUser
	origAuth := *authByPassword
	origIdx := *indexTxtPath
	origDb := *authDatabase
	t.Cleanup(func() {
		runOpenvpnUser = origRun
		*authByPassword = origAuth
		*indexTxtPath = origIdx
		*authDatabase = origDb
	})

	*indexTxtPath = writeIndexTxtWithUser(t, "alice")
	*authByPassword = true
	*authDatabase = filepath.Join(t.TempDir(), "users.db")
	runOpenvpnUser = func(args ...string) (string, error) { return "ok", nil }

	app := &OvpnAdmin{}
	body := []byte(`{"username":"alice","password":"hunter22"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/user/change-password", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.userChangePasswordHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on success, got %d body=%s", rec.Code, rec.Body.String())
	}
}

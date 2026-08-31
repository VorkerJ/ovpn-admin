package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	_ "modernc.org/sqlite"
)

// Per-user traffic accounting, bucketed by calendar month.
//
// OpenVPN's management interface reports per-session byte counters that reset to
// zero on every reconnect, so the cumulative monthly totals are maintained here,
// not by OpenVPN. Each mgmt poll folds the growth-since-last-poll into the row
// for the current UTC month (YYYY-MM); a new month starts a fresh bucket
// automatically the first time a poll lands on the 1st. History is kept — past
// months stay queryable.
//
// Storage is a dedicated SQLite database (traffic.db) on the auth state-dir
// (the PVC in k8s), separate from the openvpn password DB. The pure-Go
// modernc.org/sqlite driver is already linked into the binary, so this adds no
// new dependency.

// sessionSnapshot records the last poll's live session state for a connected
// user, so we add only the per-poll growth and detect a reconnect (when
// ConnectedSince changes the session counters have reset to 0). It is persisted
// so an ovpn-admin restart while a user stays connected does not re-count the
// already-elapsed part of that session.
type sessionSnapshot struct {
	connectedSince          string
	connectedSinceFormatted string
	realAddress             string
	rx, tx                  uint64
}

type trafficAccountant struct {
	mu      sync.Mutex
	db      *sql.DB
	session map[string]sessionSnapshot
}

// currentMonth returns the UTC month bucket key, e.g. "2026-06".
func currentMonth() string { return time.Now().UTC().Format("2006-01") }

// newTrafficAccountant opens (and migrates) the traffic DB. On any failure it
// returns an accountant with a nil db: accounting silently no-ops and the
// traffic page shows no data, rather than crashing the panel.
func newTrafficAccountant(path string) *trafficAccountant {
	ta := &trafficAccountant{session: map[string]sessionSnapshot{}}
	if path == "" {
		return ta
	}
	// WAL + a busy timeout so the 28s writer and the on-demand reader don't trip
	// over each other.
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		log.Warnf("traffic: cannot open %s: %v — accounting disabled", path, err)
		return ta
	}
	if err := initTrafficSchema(db); err != nil {
		log.Warnf("traffic: schema init on %s failed: %v — accounting disabled", path, err)
		_ = db.Close()
		return ta
	}
	ta.db = db
	// Tighten perms regardless of umask / pre-existing state-dir mode: the DB
	// holds usernames, byte counters and client IPs. Sidecars inherit the dir.
	_ = os.Chmod(path, 0o600)
	// One-time, lossless upgrade from the old JSON store: fold any pre-existing
	// lifetime totals into the DB so deployed history is not lost. Runs only when
	// the DB is fresh; the JSON file is renamed afterwards so it is kept as a
	// backup and never re-imported.
	ta.importLegacyJSON(strings.TrimSuffix(path, ".db") + ".json")
	// Purge phantom "UNDEF"/empty rows left by older builds that recorded
	// unauthenticated sessions (revoked/deleted users retrying, mid-handshake).
	// Runs before loadSessions so they are not restored into the live snapshot.
	for _, tbl := range []string{"traffic_monthly", "session_state"} {
		if _, err := db.Exec("DELETE FROM " + tbl + " WHERE username = '' OR username = 'UNDEF'"); err != nil {
			log.Warnf("traffic: purge phantom rows from %s failed: %v", tbl, err)
		}
	}
	ta.loadSessions()
	var users int
	_ = db.QueryRow("SELECT count(DISTINCT username) FROM traffic_monthly").Scan(&users)
	log.Infof("traffic: SQLite store ready at %s (%d users with history)", path, users)
	return ta
}

// importLegacyJSON migrates the previous traffic.json (a flat per-user lifetime
// total, no month breakdown) into the monthly table. Each user's lifetime total
// is attributed to the month it was last updated (best available signal), so the
// all-time figure stays continuous across the upgrade. Idempotent: it bails if
// the DB already holds data, and renames the JSON once imported.
func (ta *trafficAccountant) importLegacyJSON(jsonPath string) {
	var existing int
	if err := ta.db.QueryRow("SELECT count(*) FROM traffic_monthly").Scan(&existing); err != nil || existing > 0 {
		return
	}
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		return // no legacy file — nothing to do
	}
	var legacy map[string]struct {
		RxBytes   uint64 `json:"rx_bytes"`
		TxBytes   uint64 `json:"tx_bytes"`
		UpdatedAt string `json:"updated_at"`
	}
	if err := json.Unmarshal(raw, &legacy); err != nil {
		log.Warnf("traffic: cannot parse legacy %s: %v — skipping import", jsonPath, err)
		return
	}
	imported := 0
	for name, t := range legacy {
		if name == "" || (t.RxBytes == 0 && t.TxBytes == 0) {
			continue
		}
		month := currentMonth()
		if t.UpdatedAt != "" {
			if parsed, err := time.Parse(time.RFC3339, t.UpdatedAt); err == nil {
				month = parsed.UTC().Format("2006-01")
			}
		}
		if _, err := ta.db.Exec(
			`INSERT INTO traffic_monthly(username, month, rx_bytes, tx_bytes, updated_at)
			 VALUES(?, ?, ?, ?, ?)
			 ON CONFLICT(username, month) DO UPDATE SET
			   rx_bytes = rx_bytes + excluded.rx_bytes,
			   tx_bytes = tx_bytes + excluded.tx_bytes`,
			name, month, t.RxBytes, t.TxBytes, t.UpdatedAt,
		); err != nil {
			log.Warnf("traffic: legacy import of %q failed: %v", name, err)
			continue
		}
		imported++
	}
	if imported > 0 {
		if err := os.Rename(jsonPath, jsonPath+".imported"); err != nil {
			log.Warnf("traffic: imported %d legacy user(s) but could not rename %s: %v", imported, jsonPath, err)
		} else {
			log.Infof("traffic: imported %d legacy user total(s) from %s (kept as %s.imported)", imported, jsonPath, jsonPath)
		}
	}
}

func initTrafficSchema(db *sql.DB) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS traffic_monthly(
  username   TEXT    NOT NULL,
  month      TEXT    NOT NULL,
  rx_bytes   INTEGER NOT NULL DEFAULT 0,
  tx_bytes   INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY(username, month)
);
CREATE TABLE IF NOT EXISTS session_state(
  username            TEXT PRIMARY KEY,
  connected_since     TEXT,
  connected_since_fmt TEXT,
  real_address        TEXT,
  rx                  INTEGER NOT NULL DEFAULT 0,
  tx                  INTEGER NOT NULL DEFAULT 0
);`
	_, err := db.Exec(ddl)
	return err
}

// loadSessions restores the live-session snapshots from the previous run so a
// restart while users stay connected resumes delta accounting correctly.
func (ta *trafficAccountant) loadSessions() {
	rows, err := ta.db.Query("SELECT username, connected_since, connected_since_fmt, real_address, rx, tx FROM session_state")
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		var s sessionSnapshot
		if err := rows.Scan(&name, &s.connectedSince, &s.connectedSinceFormatted, &s.realAddress, &s.rx, &s.tx); err != nil {
			continue
		}
		ta.session[name] = s
	}
}

// update folds one mgmt poll into the monthly totals. Called from setState every
// poll interval.
// isPhantomCN reports whether a CommonName is OpenVPN's placeholder for a
// connection with no authenticated identity ("" or "UNDEF"), which must never
// be recorded as a real user in the traffic stats.
func isPhantomCN(cn string) bool {
	return cn == "" || cn == "UNDEF"
}

func (ta *trafficAccountant) update(clients []clientStatus) {
	ta.mu.Lock()
	defer ta.mu.Unlock()
	if ta.db == nil {
		return
	}
	month := currentMonth()
	now := time.Now().UTC().Format(time.RFC3339)
	seen := make(map[string]struct{}, len(clients))

	for _, c := range clients {
		if isPhantomCN(c.CommonName) {
			// "" / "UNDEF" are OpenVPN's placeholders for a connection that has
			// not authenticated (mid-handshake, or a revoked/deleted user's
			// client retrying with its old .ovpn). It maps to no real user, so
			// recording it just leaves a phantom "UNDEF" row in the stats.
			continue
		}
		seen[c.CommonName] = struct{}{}
		rx := parseUint(c.BytesReceived)
		tx := parseUint(c.BytesSent)

		var addRx, addTx uint64
		prev, ok := ta.session[c.CommonName]
		if !ok || prev.connectedSince != c.ConnectedSince {
			// New session (reconnect) or first sighting: the whole current
			// session counter is traffic we have not counted yet.
			addRx, addTx = rx, tx
		} else {
			// Same session: add only the growth since the previous poll.
			if rx > prev.rx {
				addRx = rx - prev.rx
			}
			if tx > prev.tx {
				addTx = tx - prev.tx
			}
		}

		if addRx > 0 || addTx > 0 || !ok {
			if _, err := ta.db.Exec(
				`INSERT INTO traffic_monthly(username, month, rx_bytes, tx_bytes, updated_at)
				 VALUES(?, ?, ?, ?, ?)
				 ON CONFLICT(username, month) DO UPDATE SET
				   rx_bytes = rx_bytes + excluded.rx_bytes,
				   tx_bytes = tx_bytes + excluded.tx_bytes,
				   updated_at = excluded.updated_at`,
				c.CommonName, month, addRx, addTx, now,
			); err != nil {
				log.Warnf("traffic: update %q failed: %v", c.CommonName, err)
			}
		}

		ta.session[c.CommonName] = sessionSnapshot{
			connectedSince:          c.ConnectedSince,
			connectedSinceFormatted: c.ConnectedSinceFormatted,
			realAddress:             c.RealAddress,
			rx:                      rx,
			tx:                      tx,
		}
		if _, err := ta.db.Exec(
			`INSERT INTO session_state(username, connected_since, connected_since_fmt, real_address, rx, tx)
			 VALUES(?, ?, ?, ?, ?, ?)
			 ON CONFLICT(username) DO UPDATE SET
			   connected_since = excluded.connected_since,
			   connected_since_fmt = excluded.connected_since_fmt,
			   real_address = excluded.real_address,
			   rx = excluded.rx, tx = excluded.tx`,
			c.CommonName, c.ConnectedSince, c.ConnectedSinceFormatted, c.RealAddress, rx, tx,
		); err != nil {
			log.Warnf("traffic: session persist %q failed: %v", c.CommonName, err)
		}
	}

	// Forget sessions that are no longer connected so a later reconnect is
	// treated as a fresh session (and its full counter counted once).
	for name := range ta.session {
		if _, still := seen[name]; !still {
			delete(ta.session, name)
			if _, err := ta.db.Exec("DELETE FROM session_state WHERE username = ?", name); err != nil {
				log.Warnf("traffic: session cleanup %q failed: %v", name, err)
			}
		}
	}
}

// persist is a no-op: every update() writes through to SQLite immediately. Kept
// so the setState call site stays unchanged.
func (ta *trafficAccountant) persist() {}

// trafficRow is one row of the /api/traffic response for the selected month.
type trafficRow struct {
	User           string `json:"user"`
	RxBytes        uint64 `json:"rx_bytes"`       // selected month
	TxBytes        uint64 `json:"tx_bytes"`       // selected month
	TotalBytes     uint64 `json:"total_bytes"`    // selected month
	AllTimeBytes   uint64 `json:"all_time_bytes"` // every month summed
	Connected      bool   `json:"connected"`
	SessionRxBytes uint64 `json:"session_rx_bytes"`
	SessionTxBytes uint64 `json:"session_tx_bytes"`
	ConnectedSince string `json:"connected_since,omitempty"`
	RealAddress    string `json:"real_address,omitempty"`
	UpdatedAt      string `json:"updated_at,omitempty"`
}

// trafficResponse is the /api/traffic payload: the rows for one month plus the
// list of months that have data (for the UI month picker).
type trafficResponse struct {
	Month  string       `json:"month"`
	Months []string     `json:"months"`
	Rows   []trafficRow `json:"rows"`
}

// snapshot returns the per-user totals for the given month (empty = current),
// each enriched with the user's all-time total and live-session state, sorted by
// the month's total descending.
func (ta *trafficAccountant) snapshot(month string) trafficResponse {
	ta.mu.Lock()
	defer ta.mu.Unlock()
	resp := trafficResponse{Month: month, Months: []string{}, Rows: []trafficRow{}}
	if ta.db == nil {
		return resp
	}

	// months that have data, newest first
	if rows, err := ta.db.Query("SELECT DISTINCT month FROM traffic_monthly ORDER BY month DESC"); err == nil {
		for rows.Next() {
			var m string
			if rows.Scan(&m) == nil {
				resp.Months = append(resp.Months, m)
			}
		}
		_ = rows.Close()
	}
	if resp.Month == "" {
		resp.Month = currentMonth()
	}

	// all-time total per user
	allTime := map[string]uint64{}
	if rows, err := ta.db.Query("SELECT username, SUM(rx_bytes + tx_bytes) FROM traffic_monthly GROUP BY username"); err == nil {
		for rows.Next() {
			var name string
			var sum uint64
			if rows.Scan(&name, &sum) == nil {
				allTime[name] = sum
			}
		}
		_ = rows.Close()
	}

	// per-user totals for the selected month
	rowByUser := map[string]*trafficRow{}
	if rows, err := ta.db.Query(
		"SELECT username, rx_bytes, tx_bytes, updated_at FROM traffic_monthly WHERE month = ?", resp.Month,
	); err == nil {
		for rows.Next() {
			var r trafficRow
			if rows.Scan(&r.User, &r.RxBytes, &r.TxBytes, &r.UpdatedAt) != nil {
				continue
			}
			r.TotalBytes = r.RxBytes + r.TxBytes
			r.AllTimeBytes = allTime[r.User]
			rowByUser[r.User] = &r
		}
		_ = rows.Close()
	}

	// fold in live-session state; a user connected now but absent from the
	// selected month (e.g. viewing a past month) still appears with a live
	// indicator and zero month bytes.
	for name, s := range ta.session {
		r, ok := rowByUser[name]
		if !ok {
			r = &trafficRow{User: name, AllTimeBytes: allTime[name]}
			rowByUser[name] = r
		}
		r.Connected = true
		r.SessionRxBytes = s.rx
		r.SessionTxBytes = s.tx
		r.ConnectedSince = s.connectedSinceFormatted
		r.RealAddress = s.realAddress
	}

	for _, r := range rowByUser {
		resp.Rows = append(resp.Rows, *r)
	}
	sort.Slice(resp.Rows, func(i, j int) bool { return resp.Rows[i].TotalBytes > resp.Rows[j].TotalBytes })
	return resp
}

// trafficHandler GET /api/traffic[?month=YYYY-MM] — per-user traffic for a
// calendar month (current month by default), with all-time totals.
func (oAdmin *OvpnAdmin) trafficHandler(w http.ResponseWriter, r *http.Request) {
	if oAdmin.traffic == nil {
		writeJSON(w, http.StatusOK, trafficResponse{Months: []string{}, Rows: []trafficRow{}})
		return
	}
	month := strings.TrimSpace(r.URL.Query().Get("month"))
	if month != "" && !validMonth(month) {
		writeJSONError(w, http.StatusBadRequest, "invalid month, expected YYYY-MM")
		return
	}
	writeJSON(w, http.StatusOK, oAdmin.traffic.snapshot(month))
}

// validMonth checks the YYYY-MM shape (and that it parses as a real month).
func validMonth(s string) bool {
	_, err := time.Parse("2006-01", s)
	return err == nil
}

func parseUint(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n
}

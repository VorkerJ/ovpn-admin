package main

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// trafficTotal is the persisted lifetime traffic for one user.
//
// RxBytes — bytes the OpenVPN server received FROM the client (the client's
// upload). TxBytes — bytes the server sent TO the client (the client's
// download). OpenVPN's per-session counters reset on every reconnect, so these
// cumulative totals are maintained by the accountant below, not by OpenVPN.
type trafficTotal struct {
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	UpdatedAt string `json:"updated_at"`
}

// sessionSnapshot records the last poll's live session state for a connected
// user, so we can add only the per-poll growth and detect a reconnect (when
// ConnectedSince changes the session counters have reset to 0).
type sessionSnapshot struct {
	connectedSince          string
	connectedSinceFormatted string
	realAddress             string
	rx, tx                  uint64
}

type trafficAccountant struct {
	mu      sync.Mutex
	path    string
	totals  map[string]*trafficTotal
	session map[string]sessionSnapshot
	dirty   bool
}

func newTrafficAccountant(path string) *trafficAccountant {
	ta := &trafficAccountant{
		path:    path,
		totals:  map[string]*trafficTotal{},
		session: map[string]sessionSnapshot{},
	}
	ta.load()
	return ta
}

func (ta *trafficAccountant) load() {
	if ta.path == "" {
		return
	}
	data, err := os.ReadFile(ta.path)
	if err != nil {
		return // absent on first run — start empty
	}
	var saved map[string]*trafficTotal
	if err := json.Unmarshal(data, &saved); err != nil {
		log.Warnf("traffic: failed to parse %s: %v — starting fresh", ta.path, err)
		return
	}
	if saved != nil {
		ta.totals = saved
	}
	log.Infof("traffic: loaded cumulative totals for %d users from %s", len(ta.totals), ta.path)
}

// update folds one mgmt poll into the cumulative totals. Called from setState
// every poll interval.
func (ta *trafficAccountant) update(clients []clientStatus) {
	ta.mu.Lock()
	defer ta.mu.Unlock()
	seen := make(map[string]struct{}, len(clients))
	for _, c := range clients {
		if c.CommonName == "" {
			continue
		}
		seen[c.CommonName] = struct{}{}
		rx := parseUint(c.BytesReceived)
		tx := parseUint(c.BytesSent)

		tot := ta.totals[c.CommonName]
		if tot == nil {
			tot = &trafficTotal{}
			ta.totals[c.CommonName] = tot
		}
		prev, ok := ta.session[c.CommonName]
		if !ok || prev.connectedSince != c.ConnectedSince {
			// New session (reconnect) or first sighting: the whole current
			// session counter is traffic we have not counted yet.
			tot.RxBytes += rx
			tot.TxBytes += tx
		} else {
			// Same session: add only the growth since the previous poll.
			if rx > prev.rx {
				tot.RxBytes += rx - prev.rx
			}
			if tx > prev.tx {
				tot.TxBytes += tx - prev.tx
			}
		}
		tot.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		ta.session[c.CommonName] = sessionSnapshot{
			connectedSince:          c.ConnectedSince,
			connectedSinceFormatted: c.ConnectedSinceFormatted,
			realAddress:             c.RealAddress,
			rx:                      rx,
			tx:                      tx,
		}
		ta.dirty = true
	}
	// Forget sessions that are no longer connected so a later reconnect is
	// treated as a fresh session (and its full counter counted once).
	for name := range ta.session {
		if _, still := seen[name]; !still {
			delete(ta.session, name)
		}
	}
}

// persist writes the totals atomically (0600) when changed.
func (ta *trafficAccountant) persist() {
	ta.mu.Lock()
	if !ta.dirty || ta.path == "" {
		ta.mu.Unlock()
		return
	}
	data, err := json.Marshal(ta.totals)
	ta.dirty = false
	ta.mu.Unlock()
	if err != nil {
		return
	}
	if err := writeFileAtomicSecret(ta.path, data); err != nil {
		log.Warnf("traffic: persist to %s failed: %v", ta.path, err)
	}
}

// trafficRow is one row of the /api/traffic response.
type trafficRow struct {
	User           string `json:"user"`
	RxBytes        uint64 `json:"rx_bytes"`
	TxBytes        uint64 `json:"tx_bytes"`
	TotalBytes     uint64 `json:"total_bytes"`
	Connected      bool   `json:"connected"`
	SessionRxBytes uint64 `json:"session_rx_bytes"`
	SessionTxBytes uint64 `json:"session_tx_bytes"`
	ConnectedSince string `json:"connected_since,omitempty"`
	RealAddress    string `json:"real_address,omitempty"`
	UpdatedAt      string `json:"updated_at,omitempty"`
}

// snapshot returns all users with lifetime totals, sorted by total descending.
// It reads only the accountant's own state (under its mutex), so it is
// race-free regardless of concurrent setState writes to activeClients.
func (ta *trafficAccountant) snapshot() []trafficRow {
	ta.mu.Lock()
	defer ta.mu.Unlock()
	rows := make([]trafficRow, 0, len(ta.totals))
	for name, tot := range ta.totals {
		r := trafficRow{
			User:       name,
			RxBytes:    tot.RxBytes,
			TxBytes:    tot.TxBytes,
			TotalBytes: tot.RxBytes + tot.TxBytes,
			UpdatedAt:  tot.UpdatedAt,
		}
		if s, ok := ta.session[name]; ok {
			r.Connected = true
			r.SessionRxBytes = s.rx
			r.SessionTxBytes = s.tx
			r.ConnectedSince = s.connectedSinceFormatted
			r.RealAddress = s.realAddress
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].TotalBytes > rows[j].TotalBytes })
	return rows
}

// trafficHandler GET /api/traffic — lifetime per-user traffic totals.
func (oAdmin *OvpnAdmin) trafficHandler(w http.ResponseWriter, r *http.Request) {
	if oAdmin.traffic == nil {
		writeJSON(w, http.StatusOK, []trafficRow{})
		return
	}
	writeJSON(w, http.StatusOK, oAdmin.traffic.snapshot())
}

func parseUint(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n
}

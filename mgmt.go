package main

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// reUsernameSpec mirrors users.go regex — used as a defence-in-depth check
// in mgmt.go's isUserAuthorized so a hypothetical exotic CN reaching this
// path cannot be interpolated into the management response unchecked.

func (oAdmin *OvpnAdmin) mgmtRead(conn net.Conn) string {
	recvData := make([]byte, 32768)
	var out string
	var n int
	var err error
	for {
		n, err = conn.Read(recvData)
		if n <= 0 || err != nil {
			break
		} else {
			out += string(recvData[:n])
			if strings.Contains(out, "type 'help' for more info") || strings.Contains(out, "END") || strings.Contains(out, "SUCCESS:") || strings.Contains(out, "ERROR:") {
				break
			}
		}
	}
	return out
}

func (oAdmin *OvpnAdmin) mgmtConnectedUsersParser(text, serverName string) []clientStatus {
	var u []clientStatus
	isClientList := false
	isRouteTable := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		txt := scanner.Text()
		if regexp.MustCompile(`^Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since$`).MatchString(txt) {
			isClientList = true
			continue
		}
		if regexp.MustCompile(`^ROUTING TABLE$`).MatchString(txt) {
			isClientList = false
			continue
		}
		if regexp.MustCompile(`^Virtual Address,Common Name,Real Address,Last Ref$`).MatchString(txt) {
			isRouteTable = true
			continue
		}
		if regexp.MustCompile(`^GLOBAL STATS$`).MatchString(txt) {
			// isRouteTable = false // ineffectual assignment to isRouteTable (ineffassign)
			break
		}
		if isClientList {
			user := strings.Split(txt, ",")
			// A client-list row is: Common Name,Real Address,Bytes Received,
			// Bytes Sent,Connected Since (indices 0..4). Guard the field count
			// so a truncated/corrupt row skips instead of panicking on user[4].
			if len(user) < 5 {
				log.Warnf("mgmtConnectedUsersParser: skipping malformed client row: %q", txt)
				continue
			}

			userName := user[0]
			if isPhantomCN(userName) {
				// Unauthenticated / mid-handshake connection — OpenVPN reports
				// CN "UNDEF" (e.g. a deleted user's client retrying with a
				// revoked cert). Not a real session: keep it out of the
				// connected list, Prometheus metrics and traffic stats.
				continue
			}
			userAddress := user[1]
			userBytesReceived := user[2]
			userBytesSent := user[3]
			userConnectedSince := user[4]

			userStatus := clientStatus{CommonName: userName, RealAddress: userAddress, BytesReceived: userBytesReceived, BytesSent: userBytesSent, ConnectedSince: userConnectedSince, ConnectedTo: serverName}
			u = append(u, userStatus)
			bytesSent, _ := strconv.Atoi(userBytesSent)
			bytesReceive, _ := strconv.Atoi(userBytesReceived)
			ovpnClientConnectionFrom.WithLabelValues(userName, userAddress).Set(float64(parseDateToUnix(oAdmin.mgmtStatusTimeFormat, userConnectedSince)))
			ovpnClientBytesSent.WithLabelValues(userName).Set(float64(bytesSent))
			ovpnClientBytesReceived.WithLabelValues(userName).Set(float64(bytesReceive))
		}
		if isRouteTable {
			user := strings.Split(txt, ",")
			// A routing-table row is: Virtual Address,Common Name,Real
			// Address,Last Ref (indices 0..3). Guard before user[1]/user[3].
			if len(user) < 4 {
				log.Warnf("mgmtConnectedUsersParser: skipping malformed route row: %q", txt)
				continue
			}
			for i := range u {
				if u[i].CommonName == user[1] {
					u[i].VirtualAddress = user[0]
					u[i].LastRef = user[3]
					ovpnClientConnectionInfo.WithLabelValues(user[1], user[0]).Set(float64(parseDateToUnix(oAdmin.mgmtStatusTimeFormat, user[3])))
					break
				}
			}
		}
	}
	return u
}

func (oAdmin *OvpnAdmin) mgmtKillUserConnection(username, serverName string) {
	conn, err := net.DialTimeout("tcp", oAdmin.mgmtInterfaces[serverName], 5*time.Second)
	if err != nil {
		log.Errorf("openvpn mgmt interface for %s is not reachable by addr %s", serverName, oAdmin.mgmtInterfaces[serverName])
		return
	}
	defer conn.Close()
	// Bound the whole exchange. The OpenVPN management console serves a single
	// client at a time; if another consumer already holds it (e.g. the
	// mgmt-client-auth loop on the same port) our read of the welcome banner
	// would otherwise block forever — and this kill runs on the CCD-write path,
	// so an unbounded read here stalls the HTTP request (and, when the caller
	// holds ccdMu, every other CCD writer behind it). The CCD file is already
	// persisted by the time we get here; a missed kick just means the user
	// picks up new routes on their next natural reconnect.
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	oAdmin.mgmtRead(conn) // read welcome message
	username = strings.NewReplacer("\n", "", "\r", "").Replace(username)
	fmt.Fprintf(conn, "kill %s\n", username)
	fmt.Printf("%v", oAdmin.mgmtRead(conn))
}

// mgmtGetActiveClients returns the connected clients across every mgmt
// interface. The bool is false if ANY interface could not be reached (the
// single-client mgmt console was momentarily busy with another consumer, a
// poll collided, etc.). Callers that RECONCILE state off this snapshot (the
// firewall) MUST treat false as "unknown" and skip — never as "no clients" —
// or they'd tear down rules for still-connected users on a transient miss.
func (oAdmin *OvpnAdmin) mgmtGetActiveClients() ([]clientStatus, bool) {
	var activeClients []clientStatus
	ok := true

	for srv, addr := range oAdmin.mgmtInterfaces {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			log.Warnf("openvpn mgmt interface for %s is not reachable by addr %s", srv, addr)
			ok = false
			continue
		}
		// Bound the whole exchange (welcome read + "status 1" write + status
		// read). Without an absolute deadline a hung/half-open mgmt console
		// would block mgmtRead's blocking conn.Read forever, and this runs on
		// the 28s poll — a stuck poll would otherwise pin a goroutine and, via
		// the single-flight guard, stall every later tick.
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		oAdmin.mgmtRead(conn)            // read welcome message
		conn.Write([]byte("status 1\n")) //nolint:errcheck
		activeClients = append(activeClients, oAdmin.mgmtConnectedUsersParser(oAdmin.mgmtRead(conn), srv)...)
		conn.Close()
	}
	return activeClients, ok
}

func (oAdmin *OvpnAdmin) mgmtSetTimeFormat() {
	// time format for version 2.5 and may be newer
	oAdmin.mgmtStatusTimeFormat = "2006-01-02 15:04:05"
	log.Debugf("mgmtStatusTimeFormat: %s", oAdmin.mgmtStatusTimeFormat)

	type serverVersion struct {
		name    string
		version string
	}

	var serverVersions []serverVersion

	for srv, addr := range oAdmin.mgmtInterfaces {

		var conn net.Conn
		var err error
		for connAttempt := 0; connAttempt < 10; connAttempt++ {
			conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
			if err == nil {
				log.Debugf("mgmtSetTimeFormat: successful connection to %s/%s", srv, addr)
				break
			}
			log.Warnf("mgmtSetTimeFormat: openvpn mgmt interface for %s is not reachable by addr %s", srv, addr)
			time.Sleep(time.Duration(2) * time.Second)
		}
		if err != nil {
			break
		}

		// Bound the welcome+version exchange so a half-open console can't hang
		// startup indefinitely in mgmtRead's blocking read.
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		oAdmin.mgmtRead(conn)           // read welcome message
		conn.Write([]byte("version\n")) //nolint:errcheck
		out := oAdmin.mgmtRead(conn)
		conn.Close()

		log.Trace(out)

		for _, s := range strings.Split(out, "\n") {
			if strings.Contains(s, "OpenVPN Version:") {
				serverVersions = append(serverVersions, serverVersion{srv, strings.Split(s, " ")[3]})
				break
			}
		}
	}

	if len(serverVersions) == 0 {
		return
	}

	firstVersion := serverVersions[0].version

	if strings.HasPrefix(firstVersion, "2.4") {
		oAdmin.mgmtStatusTimeFormat = time.ANSIC
		log.Debugf("mgmtStatusTimeFormat changed: %s", oAdmin.mgmtStatusTimeFormat)
	}

	warn := ""
	for _, v := range serverVersions {
		if firstVersion != v.version {
			warn = "mgmtSetTimeFormat: servers have different versions of openvpn, user connection status may not work"
			log.Warn(warn)
			break
		}
	}

	if warn != "" {
		for _, v := range serverVersions {
			log.Infof("server name: %s, version: %s", v.name, v.version)
		}
	}
}

// isUserAuthorized verifies a CN against the easyrsa index. Returns
// (allow, reason). Reason is only meaningful when allow=false.
//
// Cert verification + CRL is already enforced by OpenVPN itself BEFORE
// we are asked. This call adds the "is the cert currently in our index
// and marked Valid" gate — which lets revocation take effect immediately
// without waiting for the client to refresh its CRL.
func (oAdmin *OvpnAdmin) isUserAuthorized(cn string) (bool, string) {
	cn = strings.TrimSpace(cn)
	if cn == "" {
		return false, "missing common name"
	}
	// Allowed CN charset is enforced at user-creation time by validateUsername.
	// We re-check here to defend against an attacker who somehow obtains a
	// cert with an exotic CN — be conservative.
	if err := validateUsername(cn); err != nil {
		return false, "invalid common name format"
	}
	dn := "/CN=" + cn
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.DistinguishedName == dn {
			if u.Flag == "V" {
				return true, ""
			}
			return false, "user " + cn + " is revoked or expired"
		}
	}
	return false, "user " + cn + " not found in store"
}

// startMgmtClientAuth opens a long-lived connection to each OpenVPN mgmt
// interface and answers >CLIENT:CONNECT / >CLIENT:REAUTH events. Required
// when server.conf has `management-client-auth`. The loop reconnects with
// backoff if the link drops.
func (oAdmin *OvpnAdmin) startMgmtClientAuth() {
	for srv, addr := range oAdmin.mgmtInterfaces {
		go oAdmin.mgmtClientAuthSupervisor(srv, addr)
	}
}

func (oAdmin *OvpnAdmin) mgmtClientAuthSupervisor(serverName, addr string) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		err := oAdmin.mgmtClientAuthLoop(serverName, addr)
		// Reset backoff after a long-running successful session.
		if err == nil {
			backoff = time.Second
		}
		log.Warnf("mgmt-client-auth[%s]: loop exited (%v); reconnecting in %v", serverName, err, backoff)
		time.Sleep(backoff)
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// mgmtClientAuthLoop runs one connection lifetime. Returns the error that
// caused it to exit so the supervisor can decide on backoff.
func (oAdmin *OvpnAdmin) mgmtClientAuthLoop(serverName, addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Drain the welcome banner (OpenVPN prints a help-hint line at start).
	// The deadline is enforced on the underlying conn so a peer that never
	// sends the banner cannot wedge us in ReadString; it is cleared once the
	// banner arrives because the loop below legitimately blocks between events.
	if err := drainWelcome(conn, reader, 5*time.Second); err != nil {
		return fmt.Errorf("welcome: %w", err)
	}

	log.Infof("mgmt-client-auth[%s]: connected to %s", serverName, addr)

	type pending struct {
		cid string
		kid string
		env map[string]string
	}
	// Limit on concurrent in-flight CLIENT:CONNECT blocks per connection.
	// OpenVPN serializes these on a single mgmt link, so 1 is enough in
	// practice; the slice guards against a malformed peer sending overlapping
	// blocks for distinct CIDs. We track insertion order so untagged
	// >CLIENT:ENV lines attribute to the most recently started block —
	// matches OpenVPN's actual emission order.
	inflight := []*pending{}
	indexByCID := map[string]int{}
	const maxInflight = 256
	// reCIDKID validates that the CID/KID strings sent over the management
	// protocol are decimal integers (per OpenVPN management interface spec).
	// Anything else is rejected before being interpolated into our reply.
	reCIDKID := regexp.MustCompile(`^\d+$`)
	removeInflight := func(cid string) {
		idx, ok := indexByCID[cid]
		if !ok {
			return
		}
		delete(indexByCID, cid)
		inflight = append(inflight[:idx], inflight[idx+1:]...)
		// Reindex shifted entries.
		for i := idx; i < len(inflight); i++ {
			indexByCID[inflight[i].cid] = i
		}
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")

		switch {
		case strings.HasPrefix(line, ">CLIENT:CONNECT,"), strings.HasPrefix(line, ">CLIENT:REAUTH,"):
			body := line
			if strings.HasPrefix(body, ">CLIENT:CONNECT,") {
				body = strings.TrimPrefix(body, ">CLIENT:CONNECT,")
			} else {
				body = strings.TrimPrefix(body, ">CLIENT:REAUTH,")
			}
			parts := strings.SplitN(body, ",", 2)
			if len(parts) != 2 {
				continue
			}
			cid, kid := parts[0], parts[1]
			if !reCIDKID.MatchString(cid) || !reCIDKID.MatchString(kid) {
				log.Warnf("mgmt-client-auth[%s]: drop event with non-numeric cid=%q kid=%q", serverName, cid, kid)
				continue
			}
			if len(inflight) >= maxInflight {
				// Backpressure: deny immediately rather than queue forever.
				_, _ = fmt.Fprintf(conn, "client-deny %s %s \"server overloaded\"\n", cid, kid)
				continue
			}
			// If OpenVPN sends a fresh CONNECT/REAUTH for an existing cid,
			// discard the stale block and replace.
			removeInflight(cid)
			indexByCID[cid] = len(inflight)
			inflight = append(inflight, &pending{cid: cid, kid: kid, env: map[string]string{}})

		case strings.HasPrefix(line, ">CLIENT:DISCONNECT,"):
			// Drop any partially-collected env for this CID. OpenVPN also
			// sends an ENV block here we don't need to act on.
			body := strings.TrimPrefix(line, ">CLIENT:DISCONNECT,")
			if i := strings.IndexByte(body, ','); i >= 0 {
				removeInflight(body[:i])
			}

		case strings.HasPrefix(line, ">CLIENT:ENV,"):
			body := strings.TrimPrefix(line, ">CLIENT:ENV,")
			// ENV lines belong to the most recently started pending block.
			// OpenVPN emits them strictly in order between the CLIENT:CONNECT
			// header and CLIENT:ENV,END terminator.
			if len(inflight) == 0 {
				continue
			}
			cur := inflight[len(inflight)-1]
			if body == "END" {
				cn := cur.env["common_name"]
				allowed, reason := oAdmin.isUserAuthorized(cn)
				if allowed {
					if _, werr := fmt.Fprintf(conn, "client-auth-nt %s %s\n", cur.cid, cur.kid); werr != nil {
						return fmt.Errorf("write client-auth-nt: %w", werr)
					}
					log.Infof("mgmt-client-auth[%s]: allow CN=%s cid=%s", serverName, cn, cur.cid)
				} else {
					// Sanitize reason for the protocol — it goes inside quotes.
					safe := strings.NewReplacer("\"", "'", "\n", " ", "\r", " ").Replace(reason)
					if _, werr := fmt.Fprintf(conn, "client-deny %s %s \"%s\"\n", cur.cid, cur.kid, safe); werr != nil {
						return fmt.Errorf("write client-deny: %w", werr)
					}
					log.Warnf("mgmt-client-auth[%s]: deny CN=%s cid=%s: %s", serverName, cn, cur.cid, reason)
				}
				removeInflight(cur.cid)
				continue
			}
			if k, v, ok := splitEnvKV(body); ok {
				// Cap env size per pending block (defense against a
				// chatty/malicious mgmt peer pushing megabytes of env).
				if len(cur.env) < 256 && len(v) < 4096 {
					cur.env[k] = v
				}
			}
		}
	}
}

// drainWelcome reads until OpenVPN's banner line that ends with the
// "type 'help'" hint, or until the deadline fires. It sets a real read
// deadline on the underlying conn so a blocking ReadString cannot hang
// forever, then clears it before returning so the caller's long-lived event
// loop can block between events. The connection stays open after this returns.
func drainWelcome(conn net.Conn, r *bufio.Reader, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)
	// Clear the read deadline on the way out — the caller reads events
	// indefinitely after the banner and must not inherit our deadline.
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck
	for time.Now().Before(deadline) {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.Contains(line, "type 'help'") {
			return nil
		}
	}
	return fmt.Errorf("timeout waiting for welcome banner")
}

func splitEnvKV(s string) (string, string, bool) {
	i := strings.IndexByte(s, '=')
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func isUserConnected(username string, connectedUsers []clientStatus) (bool, []string) {
	var connections []string
	var connected = false

	for _, connectedUser := range connectedUsers {
		if connectedUser.CommonName == username {
			connected = true
			connections = append(connections, connectedUser.ConnectedTo)
		}
	}
	return connected, connections
}

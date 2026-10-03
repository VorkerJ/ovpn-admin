package main

import (
	"fmt"
	"strings"
	"time"
)

// Audit N06 (F14): the OpenVPN management console serves ONE TCP client at a
// time. When `management-client-auth` is on, ovpn-admin must hold a persistent
// connection to answer >CLIENT: auth events — which means every OTHER consumer
// (status polls, kills, signals, version) can no longer open its own connection
// (the console refuses the second client). The result was contention: kicks and
// firewall reconciles silently failed while the auth loop held the console.
//
// mgmtBroker closes that gap by making the auth connection the SINGLE OWNER of
// the console and multiplexing over it:
//   - async ">"-prefixed notifications (>CLIENT:…) are handled by the auth loop;
//   - synchronous commands submitted via exec() are written one-at-a-time and
//     their reply lines collected until a terminator, with any interleaved async
//     lines still routed to the auth handler.
//
// A broker exists only while the auth loop is connected; when it isn't (the
// common case: mgmt-client-auth OFF), callers fall back to a direct short-lived
// dial, so the historical behaviour is unchanged.
type mgmtBroker struct {
	cmds chan mgmtCmd  // unbuffered: a send succeeds only when the owner is idle
	done chan struct{} // closed when the owning connection is gone
}

type mgmtCmd struct {
	line       string            // command to write (without the trailing newline)
	isComplete func(string) bool // true when a reply line terminates the response
	resp       chan mgmtResult
}

type mgmtResult struct {
	text string
	err  error
}

func newMgmtBroker() *mgmtBroker {
	return &mgmtBroker{
		cmds: make(chan mgmtCmd),
		done: make(chan struct{}),
	}
}

// exec submits a command to the owning connection and waits for its response.
// It bounds both the hand-off to the owner (the owner may be mid-command) and
// the response itself, so a busy or wedged console can never block a caller
// (e.g. a CCD-kick on the HTTP path) indefinitely. Returns an error if the
// broker's connection went away.
func (b *mgmtBroker) exec(cmd string, isComplete func(string) bool, timeout time.Duration) (string, error) {
	c := mgmtCmd{line: cmd, isComplete: isComplete, resp: make(chan mgmtResult, 1)}
	select {
	case b.cmds <- c:
	case <-b.done:
		return "", fmt.Errorf("mgmt broker closed")
	case <-time.After(timeout):
		return "", fmt.Errorf("mgmt broker busy (enqueue timed out after %s)", timeout)
	}
	select {
	case r := <-c.resp:
		return r.text, r.err
	case <-b.done:
		return "", fmt.Errorf("mgmt broker closed")
	case <-time.After(timeout):
		return "", fmt.Errorf("mgmt command %q timed out after %s", cmd, timeout)
	}
}

// --- response terminators ---

// mgmtRespSingleLine terminates on OpenVPN's single-line command acks
// (SUCCESS:/ERROR:), used by `kill`, `signal`, `client-*`.
func mgmtRespSingleLine(line string) bool {
	return strings.HasPrefix(line, "SUCCESS:") || strings.HasPrefix(line, "ERROR:")
}

// mgmtRespUntilEnd terminates on the "END" line that closes a multi-line reply
// (`status`, `version`).
func mgmtRespUntilEnd(line string) bool {
	return strings.TrimSpace(line) == "END"
}

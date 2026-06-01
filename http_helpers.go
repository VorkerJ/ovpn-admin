package main

import (
	"encoding/json"
	"net/http"
)

// writeJSON writes body as JSON with the given HTTP status code.
// Content-Type is always set to application/json.
//
// Use this helper instead of hand-rolled
//
//	w.Header().Set("Content-Type", "application/json")
//	w.WriteHeader(code)
//	fmt.Fprint(w, `{"..."}`)
//
// patterns — the latter is error-prone (forgotten header, malformed JSON via
// string interpolation) and inconsistent across handlers.
func writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// writeJSONError writes an {"error":"<msg>"} envelope with the given status code.
// Prefer this over http.Error with a JSON-looking body — http.Error forces
// Content-Type: text/plain, which is a real bug for clients that branch on it.
func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// requireMaster wraps a handler with a slave-role guard. Routes registered
// with this middleware return 423 Locked on slave nodes so the per-handler
// `if oAdmin.role == "slave"` boilerplate can be deleted.
func (oAdmin *OvpnAdmin) requireMaster(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if oAdmin.role == "slave" {
			writeJSONError(w, http.StatusLocked, "slave is read-only")
			return
		}
		next(w, r)
	}
}

// requireMethod wraps a handler with an HTTP-method guard. Routes registered
// with this middleware return 405 Method Not Allowed for any method other
// than the one specified, so per-handler `if r.Method != http.MethodX`
// boilerplate can be deleted.
func requireMethod(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		next(w, r)
	}
}

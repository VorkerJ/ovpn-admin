package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadyzHandlerHealthy(t *testing.T) {
	rc := readinessChecker{
		pkiReady:     func() error { return nil },
		crlReady:     func() error { return nil },
		storageReady: func() error { return nil },
		mgmtReady:    func() error { return nil },
	}
	rr := httptest.NewRecorder()
	readyzHandler(rc)(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), "ok") {
		t.Errorf("body = %q, want it to contain \"ok\"", rr.Body.String())
	}
}

func TestReadyzHandlerUnhealthy(t *testing.T) {
	cases := []struct {
		name         string
		rc           readinessChecker
		wantInReason string
	}{
		{
			name: "storage down",
			rc: readinessChecker{
				pkiReady:     func() error { return nil },
				crlReady:     func() error { return nil },
				storageReady: func() error { return errors.New("connection refused") },
				mgmtReady:    func() error { return nil },
			},
			wantInReason: "storage",
		},
		{
			name: "mgmt down",
			rc: readinessChecker{
				pkiReady:     func() error { return nil },
				crlReady:     func() error { return nil },
				storageReady: func() error { return nil },
				mgmtReady:    func() error { return errors.New("dial timeout") },
			},
			wantInReason: "mgmt",
		},
		{
			name: "pki broken reported first",
			rc: readinessChecker{
				pkiReady:     func() error { return errors.New("no CA") },
				crlReady:     func() error { return errors.New("no crl") },
				storageReady: func() error { return nil },
				mgmtReady:    func() error { return nil },
			},
			wantInReason: "pki",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			readyzHandler(tc.rc)(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
			}
			if !strings.Contains(rr.Body.String(), tc.wantInReason) {
				t.Errorf("body = %q, want it to mention %q", rr.Body.String(), tc.wantInReason)
			}
		})
	}
}

// TestReadinessCheckSkipsNilProbes ensures a nil probe func is treated as
// "not configured" rather than panicking.
func TestReadinessCheckSkipsNilProbes(t *testing.T) {
	rc := readinessChecker{storageReady: func() error { return nil }}
	if reason, ok := rc.check(); !ok {
		t.Errorf("check() = (%q, false), want ok with only nil probes + one healthy", reason)
	}
}

package main

import (
	"strings"
	"testing"
	"time"
)

func TestIndexTxtEntry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)
	const serial = "42"
	const name = "alice"

	tests := []struct {
		desc      string
		revokedAt string
		notAfter  time.Time
		wantFlag  string
	}{
		{"valid non-revoked cert => V", "", future, "V"},
		{"expired non-revoked cert => E", "", past, "E"},
		{"revoked cert (still valid) => R", "250101000000Z", future, "R"},
		{"revoked cert (also expired) => R (revocation wins)", "250101000000Z", past, "R"},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			line := indexTxtEntry(tc.revokedAt, tc.notAfter, now, serial, name)
			if !strings.HasSuffix(line, "\n") {
				t.Fatalf("entry not newline-terminated: %q", line)
			}
			fields := strings.Split(strings.TrimRight(line, "\n"), "\t")
			if fields[0] != tc.wantFlag {
				t.Errorf("flag = %q, want %q (line=%q)", fields[0], tc.wantFlag, line)
			}
			if !strings.Contains(line, "/CN="+name) {
				t.Errorf("line missing CN: %q", line)
			}
			if !strings.Contains(line, serial) {
				t.Errorf("line missing serial: %q", line)
			}
			// The revoked-at column must only be populated for R entries.
			if tc.wantFlag == "R" && fields[2] != tc.revokedAt {
				t.Errorf("R entry revokedAt col = %q, want %q", fields[2], tc.revokedAt)
			}
			if tc.wantFlag != "R" && fields[2] != "" {
				t.Errorf("%s entry should have empty revokedAt col, got %q", tc.wantFlag, fields[2])
			}
		})
	}
}

func TestValidateK8sLabelValue(t *testing.T) {
	valid := []string{"alice", "bob_1", "user.name", "a-b-c", "A0", "x"}
	for _, v := range valid {
		if err := validateK8sLabelValue(v); err != nil {
			t.Errorf("validateK8sLabelValue(%q) = %v, want nil", v, err)
		}
	}

	invalid := []string{
		"alice@example.com", // '@' not allowed as label value (but ok on FS)
		"user@host",
		"@leading",
		"-leading-dash",
		"trailing-dash-",
		".leading-dot",
		"",                      // empty CN
		strings.Repeat("a", 64), // 64 > 63 max
		"has space",
	}
	for _, v := range invalid {
		if err := validateK8sLabelValue(v); err == nil {
			t.Errorf("validateK8sLabelValue(%q) = nil, want error", v)
		}
	}
}

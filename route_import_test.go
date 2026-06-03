package main

import (
	"strings"
	"testing"
)

func TestParseImportLine_CIDR(t *testing.T) {
	t.Parallel()
	r, err := parseImportLine("10.0.0.0/24")
	if err != nil {
		t.Fatalf("CIDR: %v", err)
	}
	if r.Kind != "ip" || r.Address != "10.0.0.0" || r.Mask != "255.255.255.0" {
		t.Errorf("got %+v", r)
	}
}

func TestParseImportLine_IPSpaceMask(t *testing.T) {
	t.Parallel()
	r, err := parseImportLine("10.0.0.0 255.255.255.0")
	if err != nil {
		t.Fatalf("IP+mask: %v", err)
	}
	if r.Kind != "ip" || r.Address != "10.0.0.0" || r.Mask != "255.255.255.0" {
		t.Errorf("got %+v", r)
	}
}

func TestParseImportLine_BareIP(t *testing.T) {
	t.Parallel()
	r, err := parseImportLine("8.8.8.8")
	if err != nil {
		t.Fatalf("bare IP: %v", err)
	}
	if r.Kind != "ip" || r.Mask != "255.255.255.255" {
		t.Errorf("got %+v", r)
	}
}

func TestParseImportLine_Domain(t *testing.T) {
	t.Parallel()
	r, err := parseImportLine("example.com")
	if err != nil {
		t.Fatalf("domain: %v", err)
	}
	if r.Kind != "domain" || r.Domain != "example.com" {
		t.Errorf("got %+v", r)
	}
}

func TestParseImportLine_IPv6Rejected(t *testing.T) {
	t.Parallel()
	if _, err := parseImportLine("2001:db8::/32"); err == nil {
		t.Error("CIDR IPv6 must be rejected")
	}
	if _, err := parseImportLine("::1"); err == nil {
		t.Error("bare IPv6 must be rejected")
	}
}

func TestParseImportLine_GarbageRejected(t *testing.T) {
	t.Parallel()
	for _, line := range []string{"not a route", "10.0.0.0/99", "999.0.0.0", "@@@"} {
		if _, err := parseImportLine(line); err == nil {
			t.Errorf("%q: expected error", line)
		}
	}
}

func TestParseImportText_SkipsCommentsAndEmpties(t *testing.T) {
	t.Parallel()
	in := `
# comment
example.com

10.0.0.0/24
# another comment
8.8.8.8
`
	got, errs := parseImportText(in)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 routes, got %d: %+v", len(got), got)
	}
}

func TestParseImportText_DedupesInsideImport(t *testing.T) {
	t.Parallel()
	in := strings.Join([]string{"example.com", "EXAMPLE.com", "10.0.0.0/24", "10.0.0.0/24"}, "\n")
	got, errs := parseImportText(in)
	if len(got) != 2 {
		t.Fatalf("want 2 unique, got %d: %+v", len(got), got)
	}
	if len(errs) != 2 {
		t.Fatalf("want 2 dup errors, got %d: %+v", len(errs), errs)
	}
	for _, e := range errs {
		if !strings.Contains(e.Reason, "duplicate") {
			t.Errorf("expected duplicate-of reason, got %q", e.Reason)
		}
	}
}

func TestParseImportText_ReportsLineNumbersForErrors(t *testing.T) {
	t.Parallel()
	in := strings.Join([]string{
		"# top comment",
		"example.com",  // line 2, valid
		"@@@bad@@@",    // line 3, error
		"10.0.0.0/24",  // line 4, valid
	}, "\n")
	_, errs := parseImportText(in)
	if len(errs) != 1 {
		t.Fatalf("want 1 error, got %d: %+v", len(errs), errs)
	}
	if errs[0].Line != 3 {
		t.Errorf("expected line=3, got %d", errs[0].Line)
	}
}

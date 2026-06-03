package main

import (
	"fmt"
	"net"
	"strings"
)

// ImportedRoute is the route shape after a line of bulk-import text has
// been parsed and validated. Kind matches the existing route schema
// ("domain" | "ip"), Mask is dotted-decimal even when the source used
// CIDR — the rest of the code paths render dotted-decimal in CCD.
type ImportedRoute struct {
	Kind    string
	Domain  string
	Address string
	Mask    string
}

// ImportLineError records a line we refused to parse. Line is the 1-based
// position in the input file so the user can find it in their editor.
type ImportLineError struct {
	Line   int    `json:"line"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

// ImportResult is the JSON returned by /api/.../import. Added are the
// routes that ended up in the store, Skipped are duplicates (against
// existing routes AND within the same import), Errors are parse/validate
// failures. The caller can show all three to the user.
type ImportResult struct {
	Added   []ImportedRoute   `json:"added"`
	Skipped []ImportedRoute   `json:"skipped"`
	Errors  []ImportLineError `json:"errors"`
}

// parseImportText splits text into lines, parses each into ImportedRoute,
// and returns the per-line errors separately so the caller can decide
// whether to abort or import the good rows.
//
// Accepted line formats (whitespace-trimmed):
//   - `# comment`                         → skipped silently
//   - empty line                           → skipped silently
//   - `1.2.3.0/24`                        → IP route, mask derived
//   - `1.2.3.4`                           → IP route, /32 implied
//   - `1.2.3.0  255.255.255.0`            → IP route, explicit mask
//   - `example.com`                       → domain route
//   - `1.2.3.0/24  some description`      → IP route + description
//   - `example.com   work proxy`          → domain route + description
//
// A trailing free-text segment (space-separated, anything after the
// matched token) becomes Description so users can annotate imports.
func parseImportText(text string) ([]ImportedRoute, []ImportLineError) {
	var out []ImportedRoute
	var errs []ImportLineError
	seen := map[string]struct{}{}

	for idx, raw := range strings.Split(text, "\n") {
		lineNum := idx + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		route, err := parseImportLine(line)
		if err != nil {
			errs = append(errs, ImportLineError{Line: lineNum, Source: line, Reason: err.Error()})
			continue
		}
		// Dedupe inside the same import — same domain or same Address/Mask
		// shows up once.
		key := routeDedupKey(route)
		if _, dup := seen[key]; dup {
			errs = append(errs, ImportLineError{Line: lineNum, Source: line, Reason: "duplicate of an earlier line"})
			continue
		}
		seen[key] = struct{}{}
		out = append(out, route)
	}
	return out, errs
}

func routeDedupKey(r ImportedRoute) string {
	if r.Kind == "domain" {
		return "d:" + strings.ToLower(strings.TrimSpace(r.Domain))
	}
	return "i:" + r.Address + "/" + r.Mask
}

// parseImportLine handles a single non-empty non-comment input line.
// First field is matched against IP/CIDR/domain in that order; any
// remaining text is ignored (description is intentionally not yet
// surfaced into the route schema — callers can extend later).
func parseImportLine(line string) (ImportedRoute, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ImportedRoute{}, fmt.Errorf("empty")
	}
	first := fields[0]

	// CIDR: 10.0.0.0/24
	if strings.Contains(first, "/") {
		ip, ipnet, err := net.ParseCIDR(first)
		if err != nil {
			return ImportedRoute{}, fmt.Errorf("invalid CIDR %q: %v", first, err)
		}
		if ip.To4() == nil {
			return ImportedRoute{}, fmt.Errorf("IPv6 not supported: %q", first)
		}
		return ImportedRoute{
			Kind:    "ip",
			Address: ipnet.IP.String(),
			Mask:    net.IP(ipnet.Mask).String(),
		}, nil
	}

	// IP + space + dotted-decimal mask
	if len(fields) >= 2 && net.ParseIP(first) != nil && net.ParseIP(fields[1]) != nil {
		addr := net.ParseIP(first)
		mask := net.ParseIP(fields[1])
		if addr.To4() == nil || mask.To4() == nil {
			return ImportedRoute{}, fmt.Errorf("IPv6 not supported in %q", line)
		}
		return ImportedRoute{
			Kind:    "ip",
			Address: addr.String(),
			Mask:    mask.String(),
		}, nil
	}

	// Bare IP — assume /32
	if ip := net.ParseIP(first); ip != nil {
		if ip.To4() == nil {
			return ImportedRoute{}, fmt.Errorf("IPv6 not supported: %q", first)
		}
		return ImportedRoute{
			Kind:    "ip",
			Address: ip.String(),
			Mask:    "255.255.255.255",
		}, nil
	}

	// Domain — last resort. Uses the same regex everything else does so a
	// line that fails domain parse here gets the same error message a
	// user would see typing it manually.
	if domainRegexp.MatchString(first) {
		// `999.0.0.0` matches the domain regex (every label is "alnum")
		// but it's almost certainly an operator typo for a real IPv4 with
		// a bad octet. Reject the all-numeric-dotted form so the error
		// points at the right thing.
		if looksLikeBrokenIPv4(first) {
			return ImportedRoute{}, fmt.Errorf("looks like an invalid IPv4 (octet > 255?): %q", first)
		}
		return ImportedRoute{Kind: "domain", Domain: first}, nil
	}

	return ImportedRoute{}, fmt.Errorf("not a CIDR, IP+mask, IP, or domain: %q", first)
}

// looksLikeBrokenIPv4 returns true when s has exactly four dot-separated
// segments all of which are decimal digits. Used to distinguish a
// mistyped IPv4 from a (legal-but-unlikely) all-numeric hostname.
func looksLikeBrokenIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

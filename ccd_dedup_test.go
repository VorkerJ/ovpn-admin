package main

import (
	"strings"
	"testing"
)

func TestMergePushRoutes_DedupesIPsAcrossSources(t *testing.T) {
	t.Parallel()
	custom := []ccdRoute{
		{Kind: "domain", Domain: "yt.com", ResolvedIPs: []string{"5.5.5.5", "6.6.6.6"}},
		{Kind: "domain", Domain: "yt.be", ResolvedIPs: []string{"6.6.6.6", "7.7.7.7"}}, // shares 6.6.6.6
	}
	common := []ccdCommonRoute{
		{Address: "5.5.5.5", Mask: "255.255.255.255", Tag: "google"}, // already in custom
	}
	got := mergePushRoutes(custom, common)
	if len(got) != 3 {
		t.Fatalf("want 3 unique, got %d: %+v", len(got), got)
	}
	// 5.5.5.5 should mention BOTH user-domain and common in Source
	for _, r := range got {
		if r.Address == "5.5.5.5" {
			if !strings.Contains(r.Source, "__user_domain__:yt.com") || !strings.Contains(r.Source, "__common__:google") {
				t.Errorf("5.5.5.5 source must merge both: %q", r.Source)
			}
		}
		if r.Address == "6.6.6.6" {
			if !strings.Contains(r.Source, "yt.com") || !strings.Contains(r.Source, "yt.be") {
				t.Errorf("6.6.6.6 source must merge both domains: %q", r.Source)
			}
		}
	}
}

func TestMergePushRoutes_PreservesInsertionOrder(t *testing.T) {
	t.Parallel()
	custom := []ccdRoute{
		{Kind: "ip", Address: "1.1.1.1", Mask: "255.255.255.255"},
		{Kind: "ip", Address: "2.2.2.2", Mask: "255.255.255.255"},
		{Kind: "ip", Address: "1.1.1.1", Mask: "255.255.255.255"}, // dup, ignored
		{Kind: "ip", Address: "3.3.3.3", Mask: "255.255.255.255"},
	}
	got := mergePushRoutes(custom, nil)
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	want := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	for i, r := range got {
		if r.Address != want[i] {
			t.Errorf("index %d: got %s, want %s", i, r.Address, want[i])
		}
	}
}

func TestMergePushRoutes_SkipsEmptyAddress(t *testing.T) {
	t.Parallel()
	custom := []ccdRoute{
		{Kind: "ip", Address: "", Mask: "255.255.255.255"},  // skip
		{Kind: "ip", Address: "1.1.1.1", Mask: ""},          // skip
		{Kind: "ip", Address: "1.1.1.1", Mask: "255.0.0.0"}, // keep
	}
	got := mergePushRoutes(custom, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 kept, got %d: %+v", len(got), got)
	}
}

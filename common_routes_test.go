package main

import (
	"testing"
)

func TestValidateCommonRoute_IP_OK(t *testing.T) {
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.0.0", Description: "lan"}
	if err := validateCommonRoute(e); err != nil {
		t.Fatalf("expected ok, got: %v", err)
	}
}

func TestValidateCommonRoute_IP_BadAddress(t *testing.T) {
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.999", Mask: "255.255.0.0"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on bad address")
	}
}

func TestValidateCommonRoute_IP_BadMask(t *testing.T) {
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "not-a-mask"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on bad mask")
	}
}

func TestValidateCommonRoute_IP_DomainFieldNotEmpty(t *testing.T) {
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.0.0", Domain: "leak"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error when domain set for kind=ip")
	}
}

func TestValidateCommonRoute_Domain_OK(t *testing.T) {
	e := CommonRouteEntry{Kind: "domain", Domain: "youtube.com"}
	if err := validateCommonRoute(e); err != nil {
		t.Fatalf("expected ok, got: %v", err)
	}
}

func TestValidateCommonRoute_Domain_BadDomain(t *testing.T) {
	cases := []string{"", "no_underscore_allowed.com", "-leading-dash.com", "trailing-.com", "single"}
	for _, d := range cases {
		e := CommonRouteEntry{Kind: "domain", Domain: d}
		if err := validateCommonRoute(e); err == nil {
			t.Errorf("expected error for domain %q", d)
		}
	}
}

func TestValidateCommonRoute_Domain_IPFieldNotEmpty(t *testing.T) {
	e := CommonRouteEntry{Kind: "domain", Domain: "youtube.com", Address: "1.1.1.1"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error when address set for kind=domain")
	}
}

func TestValidateCommonRoute_BadKind(t *testing.T) {
	e := CommonRouteEntry{Kind: "weird"}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on bad kind")
	}
}

func TestValidateCommonRoute_DescriptionTooLong(t *testing.T) {
	long := make([]byte, 201)
	for i := range long {
		long[i] = 'x'
	}
	e := CommonRouteEntry{Kind: "ip", Address: "10.0.0.0", Mask: "255.255.0.0", Description: string(long)}
	if err := validateCommonRoute(e); err == nil {
		t.Fatal("expected error on description > 200")
	}
}

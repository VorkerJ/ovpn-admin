package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

// reconcileMasquerade ensures `nat POSTROUTING` contains exactly one
// MASQUERADE rule for the VPN subnet `network/mask`. Any existing
// MASQUERADE rule matching the "-s X/Y ! -d X/Y -j MASQUERADE" pattern
// (whatever subnet) is removed first — that's our shape, not Docker's,
// so we don't touch Docker bridge rules.
//
// Why this matters: configure.sh sets up the initial MASQUERADE from the
// `OVPN_SERVER_NET` env var read at container start. If the operator
// changes the VPN subnet in the server-config UI, server.conf is
// re-rendered with the new subnet, but the stale env-derived MASQUERADE
// is still in iptables. Clients then get IPs in the new subnet, the
// MASQUERADE doesn't match, and outbound traffic dies at the upstream
// gateway with unroutable private source addresses.
//
// Called from apply() on hard config changes that touch the subnet.
func reconcileMasquerade(network, mask string) error {
	maskIP := net.ParseIP(mask).To4()
	if maskIP == nil {
		return fmt.Errorf("invalid mask %q (need dotted-decimal IPv4)", mask)
	}
	ones, bits := net.IPMask(maskIP).Size()
	if bits != 32 || ones == 0 {
		return fmt.Errorf("non-contiguous or non-IPv4 mask %q", mask)
	}
	netIP := net.ParseIP(network).To4()
	if netIP == nil {
		return fmt.Errorf("invalid network %q", network)
	}
	cidr := fmt.Sprintf("%s/%d", netIP.String(), ones)

	// List current POSTROUTING in nat table in iptables-save format so we
	// can identify rules by their argument structure rather than by
	// matching a printed table.
	out, err := exec.Command("iptables", "-t", "nat", "-S", "POSTROUTING").CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables list nat/POSTROUTING: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	desiredMatch := fmt.Sprintf("-s %s ! -d %s -j MASQUERADE", cidr, cidr)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "-A POSTROUTING") {
			continue
		}
		// Our rule shape: "-A POSTROUTING -s X/Y ! -d X/Y -j MASQUERADE".
		if !strings.HasSuffix(line, "-j MASQUERADE") {
			continue
		}
		// Skip Docker / system rules that don't use the "! -d <same>"
		// exclusion (e.g. Docker bridge MASQUERADE uses -o docker0).
		if !strings.Contains(line, "! -d ") {
			continue
		}
		// If this is already what we want, leave it alone and we're done.
		if strings.Contains(line, desiredMatch) {
			return nil
		}
		// Otherwise it's a stale VPN-MASQUERADE — delete it. Rebuild the
		// args list, replacing "-A" with "-D".
		args := []string{"-t", "nat"}
		for _, p := range strings.Fields(line) {
			if p == "-A" {
				p = "-D"
			}
			args = append(args, p)
		}
		if dOut, dErr := exec.Command("iptables", args...).CombinedOutput(); dErr != nil {
			log.Warnf("masquerade reconcile: delete %q failed: %v (%s)", line, dErr, strings.TrimSpace(string(dOut)))
		} else {
			log.Infof("masquerade reconcile: removed stale rule %q", line)
		}
	}

	// Add the new rule.
	addArgs := []string{
		"-t", "nat", "-A", "POSTROUTING",
		"-s", cidr, "!", "-d", cidr,
		"-j", "MASQUERADE",
	}
	if out, err := exec.Command("iptables", addArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("iptables add MASQUERADE %s: %w (%s)", cidr, err, strings.TrimSpace(string(out)))
	}
	log.Infof("masquerade reconcile: installed -s %s ! -d %s -j MASQUERADE", cidr, cidr)
	return nil
}

# Firewall scale: ipset (stub)

**Trigger:** `ovpn_firewall_rules_total > 5000` OR user complaints about throughput.

## Why

Current implementation creates one iptables rule per (CN, CIDR) pair. With 100 clients × 30 CIDRs = 3000 rules, iptables traverses linearly per packet. Performance acceptable but degrades.

## Sketch

- One ipset per CN: `ovpn_cn_<hash>`, contains all allowed CIDRs
- One iptables rule per CN: `-s <vpn_ip> -m set --match-set ovpn_cn_<hash> dst -j ACCEPT`
- ipset binary added to Dockerfile
- Migration: detect ipset availability at startup; use it if present, fall back to raw rules

Estimated effort: ~200-400 lines plus tests.

See parent spec: `docs/superpowers/specs/2026-05-23-firewall-enforcement-design.md`.

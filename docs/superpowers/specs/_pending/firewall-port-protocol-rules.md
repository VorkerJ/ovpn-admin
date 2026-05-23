# Firewall: per-port and per-protocol rules (stub)

**Trigger:** user requests "allow only port 443 to youtube.com" or similar.

## Why

Current model is CIDR-only (`-d 10.0.0.0/8 -j ACCEPT`). Users may want finer control:
- "Allow only TCP port 443 to corporate"
- "Block DNS over VPN, force split-DNS"

## Sketch

Extend `CommonRouteEntry` and `ccdRoute` with optional fields:

    Protocol string // "tcp" | "udp" | "" (any)
    Ports    string // "443" | "1024-65535" | "" (any)

UI changes: add Protocol and Ports columns (collapsed by default).
iptables additions: `-p tcp --dport 443` matchers.

Estimated effort: ~300 lines (model, validation, render, UI).

See parent spec: `docs/superpowers/specs/2026-05-23-firewall-enforcement-design.md`.

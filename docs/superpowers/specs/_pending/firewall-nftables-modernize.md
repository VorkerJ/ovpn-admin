# Firewall: migrate to nftables (stub)

**Trigger:** modern Alpine defaults to nft only, or operator preference.

## Why

iptables (legacy) is being replaced by nftables in modern Linux distros. nft offers:
- Atomic transactions (entire ruleset swap)
- Programmable Go API via `github.com/google/nftables`
- Native sets (replaces ipset)

## Sketch

- Replace `exec.Command("iptables", ...)` with `nftables` library calls
- Same logical structure (chain → rules per CN → catch-all DROP)
- Behind a `--firewall.backend=iptables|nftables` flag for transition

Estimated effort: ~300-500 lines, more if we keep both backends.

See parent spec: `docs/superpowers/specs/2026-05-23-firewall-enforcement-design.md`.

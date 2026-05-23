# Changelog

## [Unreleased]

### Added
- **Common Routes**: new tab in admin UI to push routes (IP/CIDR or domain) to all active clients ([spec](docs/superpowers/specs/2026-05-20-common-routes-design.md))
- **Server-side firewall enforcement**: per-client iptables rules so VPN clients can only reach explicitly allowed destinations ([spec](docs/superpowers/specs/2026-05-23-firewall-enforcement-design.md))

### Changed
- **BREAKING (Helm users only)**: firewall is enabled by default in the Helm chart for new installs. Existing installations upgrading the chart will get `--firewall=true` unless explicitly disabled via:
  ```yaml
  ovpnAdmin:
    firewall:
      enabled: false
  ```
  When enabled, clients can no longer manually add `ip route add ... via tun0` and have it work — only push-route-aligned destinations are reachable.
- Helm chart marks critical Secrets (PKI, CCD, common-routes) with `helm.sh/resource-policy: keep` to survive accidental `helm uninstall`. Run `kubectl delete secret ...` manually if you actually want to wipe state.

### Fixed
- (none for this release)

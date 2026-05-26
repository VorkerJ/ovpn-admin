# Changelog

## [Unreleased]

### Added
- **Common Routes**: new tab in admin UI to push routes (IP/CIDR or domain) to all active clients ([spec](docs/superpowers/specs/2026-05-20-common-routes-design.md))
- **Server-side firewall enforcement**: per-client iptables rules so VPN clients can only reach explicitly allowed destinations ([spec](docs/superpowers/specs/2026-05-23-firewall-enforcement-design.md))
- **Editable OpenVPN server config**: new "Сервер" tab edits ~15 server params
  (proto, port, MTU, cipher, DCO, DNS push, custom directives) without
  `helm upgrade`. Auto-detect DCO kernel support. ([spec](docs/superpowers/specs/2026-05-26-server-config-design.md))

### Deprecated
- Helm `values.yaml` openvpn.* fields (`proto`, `port`, `network`,
  `networkMask`, `logLevel`) are now **initial defaults only** — runtime
  values come from the editable server config store. After first start,
  changes via UI are authoritative; values.yaml is ignored on subsequent
  applies.

### Changed
- **BREAKING (Helm users only)**: firewall is enabled by default in the Helm chart for new installs. Existing installations upgrading the chart will get `--firewall=true` unless explicitly disabled via:
  ```yaml
  ovpnAdmin:
    firewall:
      enabled: false
  ```
  When enabled, clients can no longer manually add `ip route add ... via tun0` and have it work — only push-route-aligned destinations are reachable.
- Helm chart marks critical Secrets (PKI, CCD, common-routes) with `helm.sh/resource-policy: keep` to survive accidental `helm uninstall`. Run `kubectl delete secret ...` manually if you actually want to wipe state.
- Helm chart no longer ships a static `server.conf` ConfigMap.
  ovpn-admin renders the file into a shared `emptyDir` volume at startup,
  openvpn-container waits for it via init-loop.
- docker-compose: `setup/openvpn.conf` removed. `configure.sh` no longer
  auto-appends `auth-user-pass-verify` when `OVPN_PASSWD_AUTH=true` — add
  those directives via the UI's «Дополнительно» textarea instead.

### Fixed
- (none for this release)

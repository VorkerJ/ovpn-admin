# Runbook: Testing the iptables Firewall on a Real Linux Server

This runbook covers end-to-end verification of the server-side per-client
firewall feature (`OVPN_FIREWALL=true`). The feature relies on the host's
`nf_tables` / `iptables` kernel modules, which means it **cannot be tested on
Docker Desktop** (macOS / Windows) — it requires a real Linux host or a Linux
VM that exposes those modules to containers.

---

## 1. Why Docker Desktop will not work

Docker Desktop on macOS and Windows runs containers inside a minimal LinuxKit
VM. That VM intentionally ships **without the `nf_tables` kernel module**, and
the `iptables` userland inside the container talks to a kernel that does not
implement the `nft` family.

Symptoms when you try anyway:

```text
ovpn-admin | Failed to initialize nft: Protocol not supported
ovpn-admin | iptables v1.8.x (nf_tables): Could not fetch rule set generation id: Invalid argument
```

The `iptables-legacy` userland may load, but `xt_*` modules required for
match/target extensions are also absent or unavailable to unprivileged
containers, so per-client ACCEPT rules will silently no-op or refuse to insert.

**Bottom line:** use a real Linux host (bare metal, EC2, Hetzner Cloud,
Proxmox VM, ...) for this runbook.

---

## 2. Prerequisites

Tested host configurations:

| OS              | Kernel | Userland           |
|-----------------|--------|--------------------|
| Ubuntu 22.04+   | 5.15+  | `nftables` package |
| Ubuntu 24.04    | 6.8+   | `nftables` package |
| Debian 12+      | 6.1+   | `nftables` package |
| AlmaLinux 9 / Rocky 9 / RHEL 9 | 5.14+ | `nftables` package |

Required packages on the **host** (not inside the container):

```bash
# Debian / Ubuntu
sudo apt-get update
sudo apt-get install -y nftables iptables docker.io docker-compose-plugin
sudo modprobe nf_tables
sudo modprobe nft_chain_nat   # optional, only if you need NAT testing

# RHEL / Alma / Rocky
sudo dnf install -y nftables iptables docker-ce docker-compose-plugin
sudo modprobe nf_tables
```

Verify the host kernel actually has nftables loaded:

```bash
lsmod | grep nf_tables
# Expected: nf_tables 339968 ... (size will vary)

sudo nft list ruleset >/dev/null && echo "nft OK"
```

Docker daemon must be running and your user must be in the `docker` group
(or use `sudo`).

---

## 3. Quick setup

```bash
# 1. Clone
git clone https://github.com/<org>/ovpn-admin.git
cd ovpn-admin

# 2. (Optional) Build local images. CI images from ghcr.io work too.
#    NOTE: per project policy, always build without cache locally.
docker compose -f docker-compose.firewall-test.yml down -v
docker compose -f docker-compose.firewall-test.yml build --no-cache

# 3. Bring the stack up
docker compose -f docker-compose.firewall-test.yml up -d

# 4. Tail logs and look for "firewall: chain OVPN_FW initialized"
docker compose -f docker-compose.firewall-test.yml logs -f ovpn-admin
```

The compose file already sets:

- `OVPN_FIREWALL=true`
- `OVPN_FIREWALL_CHAIN=OVPN_FW`
- `cap_add: [NET_ADMIN]` on the `ovpn-admin` and `openvpn` services
- `privileged: false` (NET_ADMIN is sufficient — do not use `privileged`)

---

## 4. Verification

All commands below run **on the host**, not inside the container, because the
container shares the host's network namespace for iptables operations.

### 4.1 Chain exists at startup

```bash
sudo iptables -S OVPN_FW
# Expected (empty chain, just the policy header):
#   -N OVPN_FW
#   -A OVPN_FW -j RETURN
```

If the chain is missing, `initChain()` failed — see Troubleshooting below.

### 4.2 Connect a test client → per-client ACCEPT rule appears

On a separate machine (or VM) generate a client cert in the UI, download the
`.ovpn` profile, and connect:

```bash
sudo openvpn --config alice.ovpn
```

On the server, within ~2 seconds:

```bash
sudo iptables -L OVPN_FW -n -v --line-numbers
# Expected sample output:
# Chain OVPN_FW (1 references)
# num  pkts bytes target  prot opt in     out   source         destination
# 1      12   840 ACCEPT  all  --  tun0   *     10.8.0.6       10.20.0.0/24
# 2      0     0  ACCEPT  all  --  tun0   *     10.8.0.6       10.30.7.5
# 3      0     0  RETURN  all  --  *      *     0.0.0.0/0      0.0.0.0/0
```

Each row corresponds to one `iroute` / `push "route ..."` line in the client's
CCD file.

### 4.3 Modify CCD via UI → rules update within seconds

1. Open the admin UI, edit `alice`'s CCD, add a new `push "route 10.40.0.0
   255.255.0.0"` entry, save.
2. Within 2-5 seconds the firewall reconciler picks up the change:

```bash
watch -n1 'sudo iptables -L OVPN_FW -n | grep 10.40'
```

A new ACCEPT row for `10.40.0.0/16` should appear.

### 4.4 Disconnect client → rules removed

```bash
# On the client machine
sudo killall openvpn
```

Back on the server:

```bash
sudo iptables -L OVPN_FW -n -v
# Expected: alice's rows are gone within ~10 seconds; only RETURN remains
```

---

## 5. Troubleshooting

### 5.1 `Failed to initialize nft: Protocol not supported`

The host kernel does not expose `nf_tables`. Fix on the host:

```bash
sudo apt-get install -y nftables    # or: dnf install -y nftables
sudo modprobe nf_tables
echo "nf_tables" | sudo tee /etc/modules-load.d/nftables.conf
sudo systemctl restart docker
```

If you are on a kernel where `nf_tables` is not built (extremely old custom
kernels), fall back to `iptables-legacy` by setting
`OVPN_FIREWALL_BACKEND=legacy` in the compose env block and ensure
`iptables-legacy` is installed inside the image.

### 5.2 Rules disappear after server restart

Expected: the `OVPN_FW` chain is **recreated on every ovpn-admin startup** by
`initChain()` (see `firewall/chain.go`). If after restart the chain is missing:

```bash
docker compose -f docker-compose.firewall-test.yml logs ovpn-admin \
    | grep -iE 'chain|firewall|nft|iptables'
```

Look for `chain OVPN_FW initialized`. If you see `permission denied`, the
container is missing `NET_ADMIN` — re-check `cap_add` in compose.

### 5.3 Self-heal / reconcile interval

Default reconcile is **every 5 minutes** (configurable with
`OVPN_FIREWALL_RECONCILE_INTERVAL=5m`). To verify it is firing, temporarily
break the ruleset and watch it heal:

```bash
# Connect a client first, then:
sudo iptables -F OVPN_FW
sudo iptables -A OVPN_FW -j RETURN

# Wait up to 5 minutes (or set interval to 30s for testing), then:
sudo iptables -L OVPN_FW -n -v
# Expected: per-client rules are back
```

For faster testing, override the interval:

```yaml
environment:
  OVPN_FIREWALL_RECONCILE_INTERVAL: "30s"
```

### 5.4 Container starts but no rules ever appear

Check that the OpenVPN management socket is reachable from `ovpn-admin`:

```bash
docker compose -f docker-compose.firewall-test.yml exec ovpn-admin \
    sh -c 'echo status | nc -q1 openvpn 7505 | head'
```

You should see the OpenVPN status table. If `nc` cannot connect, the firewall
package never receives the `CLIENT_CONNECT` / `CLIENT_DISCONNECT` events that
trigger rule updates.

---

## 6. Performance tuning

The default chain uses **one rule per client per destination subnet**, which
is fine up to a few hundred concurrent clients. Past that, rule evaluation
becomes O(N) per packet and ksoftirqd CPU usage will climb.

For deployments with **>1000 concurrent clients**, switch to the ipset-backed
backend. Design doc and migration plan:

- `docs/superpowers/specs/_pending/firewall-ipset-scale.md`

Related upcoming work:

- `docs/superpowers/specs/_pending/firewall-nftables-modernize.md` — native
  `nft` family rules instead of the `iptables-nft` shim
- `docs/superpowers/specs/_pending/firewall-port-protocol-rules.md` —
  per-port / per-protocol granularity (currently L3 only)

---

## 7. References

- Compose file used in CI: `docker-compose.firewall-test.yml`
- Firewall implementation: `firewall/` package
- E2E spec: `tests/e2e/firewall.spec.ts`

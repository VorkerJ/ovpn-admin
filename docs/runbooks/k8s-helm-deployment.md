# Runbook: Deploying ovpn-admin to Kubernetes with Helm

This runbook covers a production install of `ovpn-admin` on a real Kubernetes
cluster using the Helm chart in `charts/openvpn-admin/`. It assumes a cluster
admin role and shell access to `kubectl` and `helm`.

> Placeholders called out explicitly: `<org>`, `<repo-url>`, `<your-domain>`,
> `<storage-class>`. Replace all of them before running the commands.

---

## 1. Prerequisites

- **Kubernetes 1.25+** — required because the chart targets the `restricted`
  PodSecurity admission profile (PSA replaced PSP in 1.25).
- **kubectl** with cluster-admin or equivalent RBAC on the target namespace.
- **Helm 3.12+**.
- A working **StorageClass** if you want persistence for PKI / CCD beyond
  Secrets (most installs do not need this — the chart stores PKI in Secrets
  by default).
- A LoadBalancer-capable network layer (MetalLB on-prem, ELB/NLB on AWS,
  GCLB on GCP, Azure LB, etc.) for the UDP/1194 VPN endpoint.
- `cert-manager` 1.13+ if you want automatic TLS for the admin UI Ingress.
- `htpasswd` (Apache utils) locally to generate the admin password file.

Verify your cluster:

```bash
kubectl version --short
kubectl get nodes -o wide
kubectl get storageclass
kubectl get ns kube-system -o jsonpath='{.metadata.labels}'   # PSA labels
```

---

## 2. Quick install

```bash
# 1. Add the chart repo (HTTPS or OCI — pick one)
helm repo add ovpn-admin <repo-url>
helm repo update

# 2. Generate secrets you will pass to the chart
htpasswd -Bbn admin "$(openssl rand -base64 24)" > admin.htpasswd

# 3. Create namespace + htpasswd Secret
kubectl create namespace vpn
kubectl -n vpn create secret generic ovpn-admin-htpasswd \
    --from-file=auth=admin.htpasswd

# 4. Install
helm install ovpn ovpn-admin/ovpn-admin \
    -n vpn \
    --set ovpnAdmin.adminHtpasswdSecret=ovpn-admin-htpasswd \
    --set image.tag=2.0.0
```

`helm status ovpn -n vpn` should report `STATUS: deployed`.

> Save `admin.htpasswd` in your password manager. It is
> not recoverable from the cluster (the file is hashed).

---

## 3. Values you MUST override in production

| Value | Why | How |
|-------|-----|-----|
| `ovpnAdmin.adminHtpasswdSecret` | Name of a Secret with key `auth` containing bcrypt htpasswd. | Generate with `htpasswd -Bbn admin <pw>`, create Secret, set the name. |
| `image.tag` | Default may be `latest`. Pinning is mandatory for reproducible rollbacks. | `--set image.tag=2.0.0` |
| `ingress.hosts[0].host` | Public DNS name of the admin UI. | `--set ingress.hosts[0].host=vpn-admin.<your-domain>` |
| `openvpn.service.loadBalancerIP` (optional) | Stable public IP for clients' `remote` line. | `--set openvpn.service.loadBalancerIP=203.0.113.10` |

Recommended: keep all overrides in a `values.prod.yaml` file under version
control (without secrets) and pass `-f values.prod.yaml`.

---

## 4. Pod security verification

The chart sets a `restricted`-compatible `securityContext`. Verify after
install:

```bash
kubectl -n vpn get pod -l app.kubernetes.io/name=ovpn-admin \
    -o jsonpath='{.items[0].spec.securityContext}' | jq
```

Expected fields:

```json
{
  "runAsNonRoot": true,
  "runAsUser": 65532,
  "seccompProfile": { "type": "RuntimeDefault" },
  "fsGroup": 65532
}
```

And on the container:

```bash
kubectl -n vpn get pod -l app.kubernetes.io/name=ovpn-admin \
    -o jsonpath='{.items[0].spec.containers[0].securityContext}' | jq
```

Expected:

```json
{
  "allowPrivilegeEscalation": false,
  "capabilities": { "drop": ["ALL"] },
  "readOnlyRootFilesystem": true
}
```

If the namespace enforces `restricted`, missing any of the above will block
pod admission with a clear error.

---

## 5. Networking

### 5.1 VPN data plane (UDP/1194)

```yaml
openvpn:
  service:
    type: LoadBalancer
    port: 1194
    protocol: UDP
    # On bare metal with MetalLB:
    # loadBalancerIP: 192.0.2.10
    externalTrafficPolicy: Local   # preserve client source IP
```

Verify:

```bash
kubectl -n vpn get svc openvpn
# EXTERNAL-IP must be populated and reachable on UDP/1194
nc -zvu <EXTERNAL-IP> 1194
```

### 5.2 Admin UI (HTTPS via Ingress + cert-manager)

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/auth-type: basic
    nginx.ingress.kubernetes.io/auth-secret: vpn/ovpn-admin-htpasswd
  hosts:
    - host: vpn-admin.<your-domain>
      paths: [ { path: /, pathType: Prefix } ]
  tls:
    - hosts: [ vpn-admin.<your-domain> ]
      secretName: ovpn-admin-tls
```

Verify:

```bash
kubectl -n vpn get ingress
kubectl -n vpn describe certificate ovpn-admin-tls
curl -I https://vpn-admin.<your-domain>/    # expect 401 (auth required)
```

---

## 6. Optional features

### 6.1 Data Channel Offload (DCO)

Requires the `ovpn-dco` kernel module on **every node** that may schedule the
openvpn pod. Verify on a node:

```bash
modprobe ovpn-dco && lsmod | grep ovpn_dco
```

Then enable in values:

```yaml
ovpnAdmin:
  dco:
    enabled: true
```

The chart will add a `nodeSelector` for nodes labelled with
`openvpn.dco/enabled=true`. Label the eligible nodes:

```bash
kubectl label node <node> openvpn.dco/enabled=true
```

### 6.2 Per-client firewall

Requires `NET_ADMIN` capability and `nf_tables` on the host (see
[`firewall-testing.md`](./firewall-testing.md)).

```yaml
ovpnAdmin:
  firewall:
    enabled: true
    chainName: OVPN_FW
    reconcileInterval: 5m

# Chart adds the capability automatically:
securityContext:
  capabilities:
    drop: ["ALL"]
    add:  ["NET_ADMIN"]
```

Note: adding `NET_ADMIN` makes the pod `baseline`-compatible but not strictly
`restricted`. If your namespace enforces `restricted`, relabel:

```bash
kubectl label ns vpn pod-security.kubernetes.io/enforce=baseline --overwrite
```

---

## 7. Troubleshooting

### 7.1 PodSecurity admission rejecting the pod

```bash
kubectl -n vpn describe rs -l app.kubernetes.io/name=ovpn-admin | tail -40
```

Look for `violates PodSecurity "restricted:latest"`. Either:

- raise the chart's `securityContext` to match (`runAsNonRoot`, capability
  drops, `seccompProfile`), or
- downgrade the namespace label to `baseline` if you legitimately need
  `NET_ADMIN`.

### 7.2 PVC stuck `Pending`

```bash
kubectl -n vpn get pvc
kubectl -n vpn describe pvc <name>
```

Common causes: no default StorageClass, wrong `storageClassName` in values,
provisioner CRD missing. Set:

```yaml
persistence:
  storageClassName: <storage-class>
  size: 1Gi
```

### 7.3 VPN port unreachable from the internet

1. `kubectl -n vpn get svc openvpn` — is `EXTERNAL-IP` set?
2. If `<pending>`: your cluster has no LoadBalancer controller. Install
   MetalLB / cloud-provider-cloud-controller-manager, or change to
   `type: NodePort` and point a host firewall at the NodePort.
3. If set but unreachable: check cloud security group / firewall rules allow
   `UDP/1194` inbound. AWS NLB requires explicit `UDP` listener.
4. Test from inside the cluster first:
   ```bash
   kubectl run -it --rm dnsutils --image=busybox --restart=Never -- \
       nc -zvu openvpn.vpn.svc.cluster.local 1194
   ```

---

## 8. Backup and disaster recovery

The PKI lives in **Kubernetes Secrets** by default — there are no PVs to
snapshot unless you opted into persistence.

Relevant Secrets created by the chart:

| Secret | Contents |
|--------|----------|
| `openvpn-pki-<serial>` | Single client certificate + key (one per user) |
| `openvpn-pki-<serial>` `.data.ccd` | Per-client CCD overrides |
| `openvpn-server-config` | `server.conf`, `ta.key`, DH params |
| `openvpn-common-routes` | Cluster-wide pushed routes |
| `openvpn-ca` | CA cert + key, CRL |

### 8.1 Recommended: Velero

```bash
# Install Velero (cluster-wide), then:
velero backup create ovpn-admin-backup \
    --include-namespaces vpn \
    --include-resources secrets,configmaps,deployments,services,ingresses,pvc,pv

# Restore on a fresh cluster:
velero restore create --from-backup ovpn-admin-backup
```

### 8.2 Minimal manual backup

```bash
kubectl -n vpn get secret -o yaml \
    | kubectl neat \
    > vpn-secrets-$(date +%F).yaml

gpg --symmetric --cipher-algo AES256 vpn-secrets-*.yaml
```

Store the encrypted dump off-cluster (S3 with object lock, GCS with
retention, etc.).

### 8.3 Restore drill

Schedule a quarterly drill: restore the backup into a scratch cluster, spin
up one ovpn-admin pod, connect a known client, verify auth and routing. A
backup you have never restored is a backup you do not have.

---

## 9. References

- Chart source: `charts/openvpn-admin/`
- Chart values reference: `charts/openvpn-admin/values.yaml`
- Firewall feature runbook: [`firewall-testing.md`](./firewall-testing.md)
- Release process: [`release-and-publish.md`](./release-and-publish.md)
- DR for the optional Postgres backend:
  `docs/superpowers/specs/_pending/disaster-recovery-postgres.md`

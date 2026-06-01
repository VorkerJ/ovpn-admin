# Pre-Production Deployment Checklist

> **Audience:** SRE / DevOps preparing to deploy `ovpn-admin` to production.
>
> Tick every box. Anything left unchecked is a deployment blocker until justified
> in writing and signed off by the on-call lead.

---

## 1. Secrets & Configuration

- [ ] `OVPN_MASTER_TOKEN` set to a strong random value: `openssl rand -hex 32`
      (fail-fast in `app.go` rejects empty / default tokens — verify the container starts).
- [ ] `ADMIN_HTPASSWD_FILE` points to a file with **real** admin accounts
      (no auto-generated `admin:admin` carry-over from dev).
- [ ] Bcrypt cost factor for htpasswd entries is **≥ 12**.
      `htpasswd -B` defaults to cost 5 — always use `-C 12`:
      ```bash
      htpasswd -B -C 12 -c /etc/ovpn-admin/htpasswd alice
      htpasswd -B -C 12    /etc/ovpn-admin/htpasswd bob
      ```
- [ ] `OVPN_TRUSTED_PROXIES` set to the CIDR of the reverse proxy
      (required for accurate `X-Forwarded-For` handling; empty = nobody trusted).
- [ ] `OVPN_INSECURE_COOKIES` **NOT** set / explicitly `false` in prod
      (Secure flag on session cookie depends on this).
- [ ] `OVPN_MFA=true` (default — confirm it was not overridden).
- [ ] `OVPN_MFA_REQUIRED=true` (default — every admin must enrol TOTP/Telegram).
- [ ] `OVPN_FIREWALL=true` (default in `docker-compose.yaml`; only disable on
      Docker Desktop where iptables/nft is unavailable).
- [ ] No default passwords, sample tokens, or example credentials remain in
      `docker-compose.yaml`, `values.yaml`, `.env`, or any committed config.
- [ ] `.env` is in `.gitignore`; only `.env.example` is committed and it
      contains **placeholders only** (`CHANGE_ME`, `<generate-me>`).
- [ ] Session signing key (`session_signing_key`) is auto-generated on first
      boot and persisted on the data volume — confirm it exists and has
      mode `0600`.

---

## 2. Network & TLS

- [ ] Admin UI is behind a TLS-terminating reverse proxy
      (nginx / Caddy / Traefik / cloud LB). **Never** expose plain HTTP.
- [ ] `OVPN_ADMIN_BIND=127.0.0.1` (or the proxy network) in compose so the
      admin UI is reachable only through the proxy.
- [ ] HSTS header set at the proxy:
      `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.
- [ ] TLS certificate auto-renewal in place (cert-manager / certbot / ACME).
      Cert expiry monitored (alert ≥ 14 days before).
- [ ] OpenVPN public port (`1194/UDP` by default) opened on the host firewall
      and routed to the openvpn container.
- [ ] Admin UI port (`8080/TCP`) **NOT** exposed to the public internet
      (only the proxy talks to it).
- [ ] OpenVPN management interface (`8989/TCP`) **NOT** exposed externally —
      verify with `nmap` from outside the host.
- [ ] Kubernetes `NetworkPolicy` restricts ingress to ovpn-admin pods to the
      proxy / ingress controller only (if running on K8s).
- [ ] Outbound egress allow-list configured (Telegram MFA API, metrics
      remote-write, image registry) — no unbounded egress.

---

## 3. Storage & Backups

- [ ] PKI directory (`easyrsa/`) lives on a **persistent volume**.
      Losing this = total VPN compromise + reissue of every client.
- [ ] CCD directory (`ccd/`) lives on a persistent volume.
- [ ] `htpasswd`, `mfa_secrets.json`, `session_signing_key` live on a
      persistent volume with mode `0600`.
- [ ] **Backup schedule** for the above: daily minimum, retained off-host.
- [ ] Backups encrypted at rest (age / gpg / cloud KMS).
- [ ] Restore procedure **rehearsed at least once** end-to-end —
      see `docs/runbooks/k8s-helm-deployment.md`.
- [ ] Retention policy defined and enforced (e.g., 30 days rolling +
      monthly snapshot for 1 year).
- [ ] Backup integrity checks (checksum / test-restore) run weekly.

---

## 4. Monitoring & Observability

- [ ] Prometheus scrapes `/metrics` using the metrics auth token.
- [ ] Alerts configured for:
  - [ ] High login failure rate (`auth_failures_total` rate)
  - [ ] Firewall reconcile errors (`firewall_reconcile_errors_total`)
  - [ ] Server config reload failures
  - [ ] OpenVPN management interface unreachable (`ovpn_mgmt_up == 0`)
  - [ ] Disk usage on PKI / CCD volume > 80%
  - [ ] Certificate expiry < 30 days (any cert in PKI)
- [ ] Log aggregation in place (Loki / CloudWatch / centralized syslog).
- [ ] Log retention policy: ≥ 90 days for audit logs.
- [ ] Error tracking (Sentry or equivalent) wired in.
- [ ] Dashboard published: connected clients, throughput (rx/tx bytes),
      auth errors, firewall state, container restarts.
- [ ] On-call rotation defined; pager routes tested with a synthetic alert.

---

## 5. Resource Limits

- [ ] CPU / memory limits set in `docker-compose.yaml` or K8s
      (suggested baseline: 500m CPU / 256Mi RAM per pod, tune from load test).
- [ ] PVC sized for growth: PKI grows ~5 KB per client + CRL grows over time.
- [ ] `max-clients` configured in `openvpn.conf` appropriate for org size.
- [ ] Rate-limit thresholds in `app.go` reviewed for production load
      (login attempts / IP, API requests / token).
- [ ] Docker log rotation configured (`max-size`, `max-file`) so logs
      don't fill the host disk.

---

## 6. Access Control

- [ ] Each admin has a **unique** htpasswd entry — no shared "admin" account.
- [ ] Every admin has enrolled MFA before first prod login
      (enforced by `OVPN_MFA_REQUIRED=true`).
- [ ] `htpasswd` file mode is `0600`, owned by the ovpn-admin runtime user.
- [ ] `mfa_secrets.json` mode `0600`, same owner.
- [ ] Root SSH disabled on the host (`PermitRootLogin no`).
- [ ] SSH access via bastion / jump host only (cloud) or hardware key (on-prem).
- [ ] All admin actions are audit-logged with actor identity.

---

## 7. Documentation & Runbooks

- [ ] `README.md` reflects the production setup (env vars, volume mounts,
      proxy config).
- [ ] `CHANGELOG.md` updated to the version being deployed (tag + date).
- [ ] Incident response runbook present and linked from the alert channel.
- [ ] Disaster recovery runbook present
      (see `docs/superpowers/specs/_pending/disaster-recovery-postgres.md`).
- [ ] User onboarding guide (how to issue / revoke a client) handed to support.
- [ ] Firewall testing procedure run-through completed
      (`docs/runbooks/firewall-testing.md`).
- [ ] K8s / Helm deployment runbook reviewed
      (`docs/runbooks/k8s-helm-deployment.md`).
- [ ] Release process runbook understood by the deploying engineer
      (`docs/runbooks/release-process.md`).

---

## 8. Testing

- [ ] Full Go test suite passes with race detector:
      ```bash
      go test -race ./...
      ```
- [ ] Frontend E2E suite passes:
      ```bash
      cd frontend && npx playwright test
      ```
- [ ] Manual smoke test executed on staging:
      login → MFA → create user → download .ovpn → connect → revoke.
- [ ] Load test simulating expected peak concurrent VPN clients
      (e.g., `ovpn-load` / custom harness). Latency / CPU stay within budget.
- [ ] Failover test: kill the openvpn container, verify restart and that
      existing clients reconnect.
- [ ] Upgrade rollback procedure rehearsed: deploy N+1, downgrade to N,
      confirm data compatibility.

---

## 9. Security

- [ ] All findings from the latest OWASP / internal security audit fixed
      (or risk-accepted in writing).
- [ ] Container runs as **non-root** — verify `USER ovpnadmin` (UID ≠ 0) in
      the final image stage of `Dockerfile`.
- [ ] iptables / nft rules are applied via the firewall feature
      (`OVPN_FIREWALL=true`) and reconciled on every change.
- [ ] **No** `--privileged` mode anywhere. Required capabilities only
      (`NET_ADMIN` for openvpn, nothing for ovpn-admin itself).
- [ ] Helm chart `securityContext` set: `runAsNonRoot: true`,
      `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true` where
      feasible, `capabilities.drop: [ALL]`, seccomp profile `RuntimeDefault`.
- [ ] Image scanning (Trivy / Snyk / Grype) passes with **no High/Critical
      CVEs** on the deployed tag.
- [ ] SBOM generated (`syft` / `trivy sbom`) and stored with the release.
- [ ] Container images signed with `cosign` and verified on pull
      (admission controller / `cosign verify` in CI).
- [ ] Dependency versions pinned; `go.sum` and `package-lock.json` committed.

---

## 10. Operational Readiness

- [ ] Healthcheck endpoint `/ping` exposed and wired into
      compose `healthcheck:` and K8s probes.
- [ ] Graceful shutdown verified — `SIGTERM` drains in-flight HTTP requests
      before exit (no 502s during rollout).
- [ ] K8s liveness probe: `/ping` every 10s; readiness probe: `/ping`
      every 5s with `initialDelaySeconds` tuned to actual startup.
- [ ] Container restart policy: `unless-stopped` (compose) or `Always` (K8s).
- [ ] Image pull secrets configured if pulling from a private registry.
- [ ] Image tag is **pinned** (`:v2.0.0` or a digest) — **never** `:latest`.
- [ ] Deployment strategy: `RollingUpdate` with `maxUnavailable: 0`
      (K8s) so admin UI stays up during upgrades.
- [ ] PodDisruptionBudget configured if running multiple replicas.

---

## 11. Compliance

- [ ] Inventory of PII / customer data stored (usernames, emails, TG IDs,
      certificates, IP addresses in logs).
- [ ] GDPR / data residency requirements satisfied (region of hosting,
      processor agreements).
- [ ] Audit log retention meets policy (≥ 1 year for security events).
- [ ] Right-to-be-forgotten flow documented: revoke user → delete cert →
      purge from `mfa_secrets.json` → scrub from logs after retention.
- [ ] External penetration test scheduled within the first 30 days of go-live.
- [ ] Privacy notice updated to reflect VPN admin processing.

---

## Quick verification commands

Run these from the deployer's workstation (or the host) post-deploy.
Each command's expected output is described in the comment.

```bash
# 1. Verify master sync token is not the default sample
docker compose exec ovpn-admin sh -c 'echo $OVPN_MASTER_TOKEN' | grep -v VerySecureToken
#    -> prints the actual token (not VerySecureToken), or nothing if unset (BAD)

# 2. Verify MFA is enforced (requires an authenticated request in real prod)
curl -s http://127.0.0.1:8080/api/server/settings | jq '.adminMfaRequired'
#    -> true

# 3. Verify HSTS / HTTPS at the public edge
curl -sI https://your-domain.example/ | grep -i "strict-transport-security"
#    -> Strict-Transport-Security: max-age=...

# 4. Verify the container does NOT run as root
docker compose exec ovpn-admin id | grep -v "uid=0"
#    -> uid=<non-zero>(ovpnadmin) gid=<non-zero>(ovpnadmin)

# 5. Verify admin UI is not exposed publicly
nc -zv your-public-ip 8080 < /dev/null
#    -> Connection refused / timeout (GOOD)

# 6. Verify management interface is not exposed publicly
nc -zv your-public-ip 8989 < /dev/null
#    -> Connection refused / timeout (GOOD)

# 7. Verify OpenVPN UDP port is reachable
nc -zvu your-public-ip 1194
#    -> succeeded / open

# 8. Verify image tag is pinned (not :latest)
docker compose config | grep -E 'image:.*ovpn-admin' | grep -v ':latest'
#    -> image: .../ovpn-admin:vX.Y.Z

# 9. Verify firewall rules are present on the host
sudo iptables -S | grep -i ovpn || sudo nft list ruleset | grep -i ovpn
#    -> rules for the VPN subnet exist

# 10. Verify backups ran in the last 24h
ls -lh /backup/ovpn-admin/ | head
#    -> a file dated today / yesterday

# 11. Verify healthcheck
curl -fsS http://127.0.0.1:8080/ping && echo OK
#    -> OK

# 12. Verify metrics endpoint requires auth
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/metrics
#    -> 401 (unauthenticated)
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $METRICS_TOKEN" \
     http://127.0.0.1:8080/metrics
#    -> 200

# 13. Verify TLS cert expiry > 30 days
echo | openssl s_client -servername your-domain.example -connect your-domain.example:443 2>/dev/null \
  | openssl x509 -noout -enddate
#    -> notAfter=<date at least 30 days in the future>
```

---

## Sign-off

| Role           | Name | Date       | Signature |
| -------------- | ---- | ---------- | --------- |
| Deploying SRE  |      | YYYY-MM-DD |           |
| Security lead  |      | YYYY-MM-DD |           |
| On-call lead   |      | YYYY-MM-DD |           |
| Product owner  |      | YYYY-MM-DD |           |

> No production traffic is cut over until all four signatures are present and
> every box above is either ticked or has a written risk acceptance attached.

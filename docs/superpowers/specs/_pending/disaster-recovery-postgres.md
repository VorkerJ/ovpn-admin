# Disaster Recovery via external Postgres (stub)

**Status:** parked — to be brainstormed when prioritized
**Trigger to start:** user explicitly requests "let's do DR" or accidental helm uninstall incident

## Why

Current persistence options (filesystem with PVC, kubernetes.secrets) all lose data on:
- `helm uninstall` of the release (Secrets deleted)
- Full K8s cluster loss (etcd gone)
- `kubectl delete namespace`

Mitigations in place:
- `helm.sh/resource-policy: keep` annotation on critical Secrets (survives `helm uninstall`)
- Master/slave replication for cross-cluster redundancy

But neither solves catastrophic K8s loss. External DB does.

## Sketch

- Add `--storage.backend=postgres` as third option
- New `db.go` with connection pool (`pgx/v5`)
- Schema: `users`, `ccd`, `common_routes`, `pki_secrets` (4-5 tables)
- Migrations via `golang-migrate` (simple `up.sql` files)
- Helm chart references external DSN Secret (managed Postgres expected: RDS / Cloud SQL / Neon / Supabase)
- ~400-600 lines of code + chart updates

## Open questions

- Migration tooling: in-Go (golang-migrate as library) or external init-job?
- Connection management: pool sizing, retries
- How to migrate existing installations from kubernetes.secrets to postgres
- Tested with which Postgres versions

See brainstorming context: `docs/superpowers/specs/2026-05-23-firewall-enforcement-design.md` (DR discussion).

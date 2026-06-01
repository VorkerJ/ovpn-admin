# Runbook: Cutting a Release and Publishing Images

This runbook walks through the full release process for `ovpn-admin`:
versioning, pre-flight checks, multi-architecture image builds, Helm chart
publishing, GitHub release, and optional signing / SBOM.

> Placeholders called out explicitly: `<org>`, `<username>`, `<region>`,
> `<account>`. The example version below is `2.0.0` — replace with the
> version you are cutting.

---

## 1. Versioning

The project follows **Semantic Versioning** (`MAJOR.MINOR.PATCH`).

Bump the version in two places (they must match):

1. `main.go`:
   ```go
   version = "2.0.0"
   ```
2. `charts/openvpn-admin/Chart.yaml`:
   ```yaml
   version: 2.0.0       # chart version
   appVersion: "2.0.0"  # app version (must match main.go)
   ```

Update `CHANGELOG.md`: move everything under `## [Unreleased]` to a new
section `## [2.0.0] - 2026-06-01` and start a fresh empty `Unreleased`
section.

Commit:

```bash
git checkout -b release/2.0.0
git add main.go charts/openvpn-admin/Chart.yaml CHANGELOG.md
git commit -m "chore(release): 2.0.0"
```

---

## 2. Pre-release checklist

Run every item. Do not skip. If any fail, stop and fix on a separate branch
before resuming.

- [ ] Unit + integration tests pass:
  ```bash
  go test -count=1 -race ./...
  ```
- [ ] Static analysis clean:
  ```bash
  go vet ./...
  helm lint charts/openvpn-admin/
  ```
- [ ] Frontend builds:
  ```bash
  cd frontend && npm ci && npm run build && cd ..
  ```
- [ ] E2E tests pass:
  ```bash
  cd frontend && npx playwright install --with-deps && npx playwright test && cd ..
  ```
- [ ] `CHANGELOG.md` reflects the diff since the previous tag.
- [ ] `main.go` and `Chart.yaml` carry the new version.
- [ ] Working tree clean (`git status` shows nothing).
- [ ] You are on the release branch and up to date with `origin/master`.

---

## 3. Build and push multi-arch Docker images

We publish `linux/amd64` and `linux/arm64`. Use `docker buildx` so both arches
are pushed under a single manifest tag.

```bash
# One-time per workstation
docker buildx create --use --name ovpn-builder --driver docker-container
docker buildx inspect --bootstrap

# Authenticate to the target registry (see section 4)

# ovpn-admin image
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/<org>/ovpn-admin:2.0.0 \
  -t ghcr.io/<org>/ovpn-admin:latest \
  -f Dockerfile.ovpn-admin \
  --push .

# openvpn image
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/<org>/openvpn:2.0.0 \
  -t ghcr.io/<org>/openvpn:latest \
  -f Dockerfile.openvpn \
  --push .
```

> Build flags above explicitly do NOT use `--no-cache`. That rule from
> `CLAUDE.md` applies to local docker-compose builds where stale caches
> silently miss packr2-embedded frontend assets. Buildx for release uses a
> fresh remote builder context and does not have that pitfall.

Verify the manifest list has both arches:

```bash
docker buildx imagetools inspect ghcr.io/<org>/ovpn-admin:2.0.0
# Expect:
# Manifests:
#   ... linux/amd64
#   ... linux/arm64
```

---

## 4. Registry authentication

Pick the registry you are publishing to.

### 4.1 GitHub Container Registry (recommended for OSS)

```bash
# Create a classic PAT with write:packages, read:packages
echo "$GITHUB_TOKEN" | docker login ghcr.io -u <username> --password-stdin
```

### 4.2 Docker Hub

```bash
docker login -u <username>
# Use an access token, not your password
```

### 4.3 AWS ECR

```bash
aws ecr get-login-password --region <region> \
  | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com

# Repos must exist before push:
aws ecr create-repository --repository-name ovpn-admin --region <region>
aws ecr create-repository --repository-name openvpn    --region <region>
```

For ECR change the image tags above to
`<account>.dkr.ecr.<region>.amazonaws.com/ovpn-admin:2.0.0`.

---

## 5. Publish the Helm chart

Pick **one** of the two distribution methods. OCI is preferred for new
deployments; gh-pages remains for backward compatibility with older clients.

### 5.1 OCI registry (preferred)

```bash
helm package charts/openvpn-admin/
# Produces openvpn-admin-2.0.0.tgz

helm registry login ghcr.io -u <username> --password-stdin <<< "$GITHUB_TOKEN"
helm push openvpn-admin-2.0.0.tgz oci://ghcr.io/<org>/charts
```

Users install with:

```bash
helm install ovpn oci://ghcr.io/<org>/charts/openvpn-admin --version 2.0.0
```

### 5.2 GitHub Pages (legacy index.yaml)

```bash
helm package charts/openvpn-admin/

git fetch origin gh-pages
git worktree add /tmp/ovpn-ghpages gh-pages

cp openvpn-admin-2.0.0.tgz /tmp/ovpn-ghpages/
cd /tmp/ovpn-ghpages
helm repo index . --url https://<org>.github.io/ovpn-admin --merge index.yaml

git add openvpn-admin-2.0.0.tgz index.yaml
git commit -m "release 2.0.0"
git push origin gh-pages

cd -
git worktree remove /tmp/ovpn-ghpages
```

---

## 6. Cut the GitHub release

```bash
# Tag from the release commit
git checkout master
git merge --ff-only release/2.0.0    # or merge via PR
git tag -a v2.0.0 -m "v2.0.0"
git push origin master
git push origin v2.0.0

# Extract the section for this version from CHANGELOG.md into release notes
sed -n '/^## \[2.0.0\]/,/^## \[/p' CHANGELOG.md | sed '$d' > /tmp/release-notes.md

gh release create v2.0.0 \
  --title "v2.0.0" \
  --notes-file /tmp/release-notes.md \
  openvpn-admin-2.0.0.tgz
```

Attach any other artefacts (SBOMs, signatures, checksums) to the same
release.

---

## 7. Image signing (optional but recommended)

Uses [cosign](https://github.com/sigstore/cosign) keyless signing with the
GitHub OIDC provider. Run from CI ideally; local also works.

```bash
# Install cosign first: brew install cosign / dnf install cosign / ...
COSIGN_EXPERIMENTAL=1 cosign sign ghcr.io/<org>/ovpn-admin:2.0.0
COSIGN_EXPERIMENTAL=1 cosign sign ghcr.io/<org>/openvpn:2.0.0

# Verify:
cosign verify ghcr.io/<org>/ovpn-admin:2.0.0 \
  --certificate-identity-regexp 'https://github.com/<org>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Publish the public verification command in the release notes.

---

## 8. SBOM generation

```bash
# Install syft first: brew install syft / curl -sSfL ... | sh

syft ghcr.io/<org>/ovpn-admin:2.0.0 -o spdx-json \
  > ovpn-admin-2.0.0.sbom.json
syft ghcr.io/<org>/openvpn:2.0.0 -o spdx-json \
  > openvpn-2.0.0.sbom.json

# Attach to the GitHub release
gh release upload v2.0.0 \
  ovpn-admin-2.0.0.sbom.json \
  openvpn-2.0.0.sbom.json

# Optionally attest the SBOM with cosign
cosign attest --predicate ovpn-admin-2.0.0.sbom.json \
  --type spdxjson ghcr.io/<org>/ovpn-admin:2.0.0
```

---

## 9. Post-release

- [ ] Update `README.md` so the install snippet references `2.0.0` (not
      `latest`).
- [ ] Update example values / quick-start commands if any flags or env vars
      changed.
- [ ] Announce in project channels (Slack / Telegram / GitHub Discussions).
      Highlight breaking changes and migration steps.
- [ ] Open a `chore: post-2.0.0` PR that bumps `main.go` and `Chart.yaml` to
      `2.1.0-dev` to make sure subsequent dev builds are distinguishable.
- [ ] Monitor GitHub issues for upgrade pain points for at least 72 hours.
- [ ] If a regression surfaces, prefer a fast `2.0.1` patch over reverting
      the tag — never delete a published tag once Helm / Docker have
      cached it.

---

## 10. Rollback

If you must withdraw a release:

```bash
# Docker — push the previous SHA back under :latest (do not delete tags)
docker buildx imagetools create \
  -t ghcr.io/<org>/ovpn-admin:latest \
  ghcr.io/<org>/ovpn-admin:1.9.4

# Helm OCI — there is no "delete"; publish 2.0.1 that reverts the change
# Helm gh-pages — remove the bad row from index.yaml, re-commit
```

Document the rollback in `CHANGELOG.md` under a new patch version so the
audit trail stays clear.

---

## 11. References

- Dockerfiles: `Dockerfile.ovpn-admin`, `Dockerfile.openvpn`
- Chart: `charts/openvpn-admin/`
- Version constant: `main.go` line ~118
- Changelog format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
- Image signing: [cosign docs](https://docs.sigstore.dev/cosign/overview/)
- SBOM tooling: [syft docs](https://github.com/anchore/syft)

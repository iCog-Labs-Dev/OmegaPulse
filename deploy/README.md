# Omega Pulse Deployment & Release Guide

Omega Pulse runs as its own Docker container (`oma-monitor-live`) behind Caddy (`oma-pulse-caddy`) and watches the `omega` container without modifying or restarting it.

Images are built once in CI, pushed to GitHub Container Registry (`ghcr.io/icog-labs-dev/omega-pulse`), verified on `staging`, and promoted by tag to `production` without rebuilding.

---

## Versioning

Pulse uses [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`) starting at `0.1.0`. Git tags (`vMAJOR.MINOR.PATCH`) are the single source of truth; there is no `VERSION` file.

- `deploy/version.sh` outputs `1.2.0` on a tagged commit, or `1.2.1-dev.4+<sha>` for unreleased commits after `v1.2.0`.
- **MAJOR**: Breaking config changes (`OMA_MONITOR_*` renames/removals), database migrations, or new required mounts.
- **MINOR**: Backward-compatible features (new panels, Falco rules, optional settings).
- **PATCH**: Bug fixes, dependency updates, copy changes.

---

## How to Cut a Release

1. **Ensure `main` is green and verified on staging**:
   Check `https://<staging-host>:8443/healthz` (or the dashboard footer) to confirm the `sha-` build is running cleanly on staging.
2. **Update `CHANGELOG.md`**:
   Move items from `## [Unreleased]` into a new `## [X.Y.Z] - YYYY-MM-DD` section (Keep a Changelog format), commit, and merge to `main`.
   > The release workflow will fail if `CHANGELOG.md` has no non-empty section for `X.Y.Z`.
3. **Tag the commit on `main` and push the tag**:
   ```bash
   git checkout main
   git pull --ff-only origin main
   git tag -a v0.1.0 -m "Release v0.1.0"
   git push origin v0.1.0
   ```
4. **Approve the production deploy**:
   - `pulse-release.yml` validates the tag, verifies the commit is on `main`, checks `CHANGELOG.md`, confirms the version tag does not already exist in GHCR, promotes the existing `sha-` image to `X.Y.Z`, `X.Y`, and `X` via `docker buildx imagetools create`, and creates the GitHub Release.
   - Open the **Pulse release** run in GitHub Actions and approve the `production` environment deployment.

---

## How to Roll Back

### Automatic Rollback
During any deploy (`deploy/deploy.sh`), the new container is checked at `GET http://127.0.0.1:8765/healthz` for up to 30 seconds. If it does not return `{"status":"ok","version":"<expected>"}`, `deploy.sh` automatically removes the broken container, renames the previous backup container back to `oma-monitor-live`, restarts it, and exits non-zero.

### Manual Rollback (GitHub Actions)
1. Go to **Actions → Pulse rollback / manual deploy → Run workflow**.
2. Select:
   - **environment**: `staging` or `production`
   - **version**: Target version tag (e.g. `0.1.0`) or commit tag (e.g. `sha-3c22662`).
3. Click **Run workflow** (and approve if targeting `production`).
4. Check `~/omega-pulse/deploys.log` on the server or `GET /healthz` to confirm the active version.

---

## Secrets & Environment Configuration

All deploy credentials live in GitHub **Environments** (`staging` and `production`) — never in the repository or workflow logs.

| Name | Type | Scope | Purpose |
| :--- | :--- | :--- | :--- |
| `DEPLOY_SSH_KEY` | Secret | Per environment (`staging`, `production`) | Dedicated deploy-only SSH private key |
| `DEPLOY_HOST` | Variable | Per environment (`staging`, `production`) | Target server IP or hostname |
| `DEPLOY_USER` | Variable | Per environment (`staging`, `production`) | SSH username on target server |
| `DEPLOY_KNOWN_HOSTS` | Variable | Per environment (`staging`, `production`) | Pinned SSH host public key (`StrictHostKeyChecking=yes`) |
| GHCR pull credentials | Server-side | Staging & Production hosts | If the GHCR package is private, run `docker login ghcr.io` once on each server with a read-only (`read:packages`) token |

---

## Operational Safety Rules

- **Never touch `omega`**: Pulse only watches the `omega` container; deploys never stop, restart, or recreate it.
- **Preserve `monitor/.local/auth/`**: Operator accounts and MFA secrets live here and are bind-mounted into `/auth`.
- **Never disable SSH host key checking**: Always pin `DEPLOY_KNOWN_HOSTS`.
- **Logs**: Every deploy appends a record (`timestamp`, `version`, `image`, `digest`, `triggered_by`) to `~/omega-pulse/deploys.log`.


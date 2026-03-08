# Patchwork Runbook

## Service Startup

1. Build:

```bash
make build-patchwork
make build-extensions
```

Extension build prerequisites:

- `make`, `gcc`/`clang`
- Rust + rustup (for `cr-sqlite`)
- `rustup toolchain install nightly-2023-10-05`

Optional ICU-enabled build (requires ICU dev headers/libs on the build host):

```bash
make build-patchwork \
  GO_BUILD_TAGS="sqlite_fts5 sqlite_preupdate_hook sqlite_vtable sqlite_icu" \
  SQLITE_LDFLAGS="-licuuc -licui18n"
```

2. Configure environment (see `ops/env.example`).
3. Start service:

```bash
./build/patchwork
```

## Health and Status

- Liveness: `GET /healthz`
- Runtime status: `GET /status`
- Prometheus metrics: `GET /metrics`

Quick check:

```bash
curl -sS http://127.0.0.1:8080/healthz
curl -sS http://127.0.0.1:8080/status
```

## Data Layout

Default `PATCHWORK_DATA_DIR` layout:

- `service.db` (global metadata)
- `documents/*.sqlite3` (per-db documents)
- `blobs/` (finalized blob objects)
- `blob-staging/` (staging uploads)

## First-Deploy Smoke Suite

Run a full end-to-end smoke check against a local server:

```bash
make smoke-first-deploy
```

What it verifies:

- token minting
- DB open/query/watch
- durable message publish + replay subscribe
- streams queue + req/res
- webhook ingest persistence
- lease acquire/renew/release
- blob upload/finalize/publish/public read

Use an already running server instead:

```bash
PATCHWORK_SMOKE_START_SERVER=0 \
PATCHWORK_SMOKE_BASE_URL=https://patch.example.com \
PATCHWORK_SMOKE_ADMIN_TOKEN=<admin-token> \
ops/scripts/smoke-first-deploy.sh
```

Optional OIDC login redirect check (when OIDC is configured):

```bash
PATCHWORK_SMOKE_CHECK_OIDC_LOGIN=1 make smoke-first-deploy
```

OIDC login + token minting smoke (test-harness provider):

```bash
make smoke-first-deploy-oidc
```

## Backup and Restore

- Back up `PATCHWORK_DATA_DIR` atomically where possible.
- `service.db` and `documents/*.sqlite3` should be included together.
- Blob directories (`blobs/`, `blob-staging/`) must be backed up with DB metadata for consistency.

Create a timestamped snapshot:

```bash
make backup BACKUP_DATA_DIR=/var/lib/patchwork BACKUP_OUT_DIR=/var/backups/patchwork
```

Restore a snapshot:

```bash
make restore \
  RESTORE_SNAPSHOT=/var/backups/patchwork/20260301T020000Z \
  RESTORE_DATA_DIR=/var/lib/patchwork-restore
```

Run a measured backup/restore drill (prints RTO/RPO summary):

```bash
make backup-restore-drill BACKUP_DATA_DIR=/var/lib/patchwork BACKUP_OUT_DIR=/var/backups/patchwork
```

Systemd units for scheduled backups are provided:

- `ops/systemd/patchwork-backup.service`
- `ops/systemd/patchwork-backup.timer`

Install and enable:

```bash
sudo cp ops/systemd/patchwork-backup.service /etc/systemd/system/
sudo cp ops/systemd/patchwork-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now patchwork-backup.timer
```

## Production Profile

Use `ops/PRODUCTION_PROFILE.md` to lock deployment-specific values before release:

- OIDC issuer/client/redirect/admin subjects
- bootstrap admin-token lifecycle
- blob signing key and URL TTL
- rate-limit values
- SQLite extension paths and required compile options
- backup/restore and alert routing details

## Release Cut Discipline

- Changelog: `CHANGELOG.md`
- Process doc: `ops/RELEASE.md`
- Release checks:

```bash
ops/scripts/release-check.sh
```

- Tag creation (after changelog version section is added):

```bash
ops/scripts/release-tag.sh <version>
```

## Operational Controls

Rate limits:

- `PATCHWORK_RATE_LIMIT_GLOBAL_RPS`
- `PATCHWORK_RATE_LIMIT_GLOBAL_BURST`
- `PATCHWORK_RATE_LIMIT_TOKEN_RPS`
- `PATCHWORK_RATE_LIMIT_TOKEN_BURST`

Blob GC:

- `PATCHWORK_BLOB_GC_INTERVAL`
- `PATCHWORK_BLOB_GC_GRACE_PERIOD`

Blob signed URLs (optional):

- `PATCHWORK_BLOB_SIGNING_KEY`
- `PATCHWORK_BLOB_SIGNED_URL_TTL`

OIDC web login (optional):

- `PATCHWORK_OIDC_ISSUER`
- `PATCHWORK_OIDC_CLIENT_ID`
- `PATCHWORK_OIDC_CLIENT_SECRET`
- `PATCHWORK_OIDC_REDIRECT_URL`
- `PATCHWORK_OIDC_SCOPES`
- `PATCHWORK_OIDC_ADMIN_SUBJECTS`
- `PATCHWORK_WEB_SESSION_TTL`

SQLite extensions + compile checks:

- `PATCHWORK_SQLITE_EXTENSION_CRSQLITE`
- `PATCHWORK_SQLITE_EXTENSION_CRSQLITE_ENTRYPOINT`
- `PATCHWORK_SQLITE_EXTENSION_VEC`
- `PATCHWORK_SQLITE_EXTENSION_VEC_ENTRYPOINT`
- `PATCHWORK_SQLITE_EXTENSION_SQLEAN`
- `PATCHWORK_SQLITE_EXTENSION_SQLEAN_ENTRYPOINT`
- `PATCHWORK_SQLITE_EXTENSION_SQLEAN_DIR`
- `PATCHWORK_SQLITE_EXTENSIONS`
- `PATCHWORK_SQLITE_WARN_MISSING_COMPILE_OPTIONS`
- `PATCHWORK_SQLITE_WARN_MISSING_EXTENSIONS`
- `PATCHWORK_SQLITE_REQUIRED_COMPILE_OPTIONS`
- `PATCHWORK_SQLITE_RECOMMENDED_COMPILE_OPTIONS`

## Monitoring Baseline

- Patchwork alerts: `ops/monitoring/prometheus-rules.yml`
- Monitoring notes: `ops/monitoring/README.md`

Recommended scrape/probe targets:

- `GET /metrics`
- `GET /healthz`
- host/node metrics (disk usage)

Blob GC failures currently surface as logs (`blob gc sweep failed`). Add a log alert rule for that message until dedicated GC Prometheus metrics are added.

## Edge Hardening Checklist

- Run Patchwork behind a TLS reverse proxy.
- Restrict direct service bind/network exposure to trusted internal networks.
- Verify forwarded headers (`X-Forwarded-*`) and secure-cookie behavior for OIDC flows.
- Keep OIDC redirect URL aligned with external HTTPS origin.
- Reference Nginx config: `ops/nginx/patchwork.conf`
- Validate deployment settings with:

```bash
make edge-hardening-check
```

Enable runtime listener verification against active `patchwork` sockets:

```bash
PATCHWORK_EDGE_RUNTIME_CHECK=true make edge-hardening-check
```

- For installed environments:

```bash
ops/scripts/edge-hardening-check.sh /etc/patchwork/patchwork.env /opt/patchwork/ops/nginx/patchwork.conf
```

## Common Troubleshooting

`401/403`:

- Verify token is present in `Authorization: Bearer ...`
- Verify token scopes match `db_id` and action
- If OIDC is enabled, verify browser has a valid `patchwork_session` cookie
- For OIDC web sessions, verify subject is listed in `PATCHWORK_OIDC_ADMIN_SUBJECTS` when admin access is required

`429`:

- Increase rate-limit values or spread request load

Blob finalize hash mismatch:

- Ensure uploaded bytes hash equals the declared blob hash in `complete-upload`

Lease conflicts:

- Expected when another owner holds the resource
- Use `renew` for current owner, not repeated `acquire`

SQLite compile-option warnings at startup:

- The server checks `PRAGMA compile_options` once on first SQLite connection.
- Missing recommended options are logged only when `PATCHWORK_SQLITE_WARN_MISSING_COMPILE_OPTIONS=true`.
- Set `PATCHWORK_SQLITE_REQUIRED_COMPILE_OPTIONS` to fail if required options are missing.

Extensions not loading:

- If `PATCHWORK_SQLITE_EXTENSION_*` is explicitly set, load failures are treated as errors.
- Without explicit paths, Patchwork tries default candidates (`crsqlite`, `vec0`, `sqlean`).
- Missing optional extension candidates are logged only when `PATCHWORK_SQLITE_WARN_MISSING_EXTENSIONS=true`.

Web UI entry points:

- `GET /` and `GET /ui`: main multi-feature console
- `GET /ui/tokens`: token admin UI
- `GET /ui/blobs`: blob manager UI
- Theme selector on each page: `system` (default), `light`, `dark`
- If OIDC is configured:
  - `/`, `/ui`, `/ui/blobs` redirect to OIDC login when session is missing
  - `/ui/tokens` requires admin subject

Containerized build/run:

- Build image: `docker build -f Containerfile -t patchwork:dev .`
- The image includes:
  - `/opt/patchwork/patchwork`
  - `/opt/patchwork/extensions/{crsqlite,vec0,sqlean,...}`

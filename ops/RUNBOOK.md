# Patchwork Runbook

## Service Startup

1. Build:

```bash
CGO_ENABLED=1 \
CGO_CFLAGS="-DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_SNAPSHOT -DSQLITE_ENABLE_RBU -DSQLITE_ENABLE_GEOPOLY -DSQLITE_ENABLE_RTREE" \
go build -tags "sqlite_fts5 sqlite_preupdate_hook sqlite_vtable" -o patchwork ./cmd/patchwork
```

Optional ICU-enabled build (requires ICU dev headers/libs on the build host):

```bash
CGO_ENABLED=1 \
CGO_CFLAGS="-DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_SNAPSHOT -DSQLITE_ENABLE_RBU -DSQLITE_ENABLE_GEOPOLY -DSQLITE_ENABLE_RTREE" \
CGO_LDFLAGS="-licuuc -licui18n" \
go build -tags "sqlite_fts5 sqlite_preupdate_hook sqlite_vtable sqlite_icu" -o patchwork ./cmd/patchwork
```

2. Configure environment (see `ops/env.example`).
3. Start service:

```bash
./patchwork
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

## Backup Notes

- Back up `PATCHWORK_DATA_DIR` atomically where possible.
- `service.db` and `documents/*.sqlite3` should be included together.
- Blob directories (`blobs/`, `blob-staging/`) must be backed up with DB metadata for consistency.

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
- `PATCHWORK_SQLITE_REQUIRED_COMPILE_OPTIONS`
- `PATCHWORK_SQLITE_RECOMMENDED_COMPILE_OPTIONS`

## Common Troubleshooting

`401/403`:

- Verify token is present in `Authorization: Bearer ...`
- Verify token scopes match `db_id` and action

`429`:

- Increase rate-limit values or spread request load

Blob finalize hash mismatch:

- Ensure uploaded bytes hash equals the declared blob hash in `complete-upload`

Lease conflicts:

- Expected when another owner holds the resource
- Use `renew` for current owner, not repeated `acquire`

SQLite compile-option warnings at startup:

- The server checks `PRAGMA compile_options` once on first SQLite connection.
- Missing recommended options are logged as warnings.
- Set `PATCHWORK_SQLITE_REQUIRED_COMPILE_OPTIONS` to fail if required options are missing.

Extensions not loading:

- If `PATCHWORK_SQLITE_EXTENSION_*` is explicitly set, load failures are treated as errors.
- Without explicit paths, Patchwork tries default candidates (`crsqlite`, `vec0`, `sqlean`) and logs one-time warnings if nothing is loadable.

# Patchwork Runbook

## Service Startup

1. Build:

```bash
go build -o patchwork ./cmd/patchwork
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

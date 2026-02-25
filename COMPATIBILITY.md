# Legacy Compatibility Matrix

This matrix tracks current compatibility status against old patchwork behavior.

Legend:

- `kept`: behavior/path supported with close parity
- `changed`: supported with a compatibility shim or intentional semantic changes
- `dropped`: intentionally not included in current implementation
- `deferred`: planned but not implemented yet

## Streams and Paths

| Legacy Surface | Status | Notes |
| --- | --- | --- |
| `/public/queue/*` | kept | Mapped to DB-scoped stream queue with blocking rendezvous semantics |
| `/p/queue/*` | kept | Alias to `/public/queue/*` |
| `/u/{user}/queue/*` | changed | User namespace maps to `db_id={user}` |
| `/public/pubsub/*` and `?pubsub=true` | changed | Uses non-blocking broadcast mode in stream layer |
| `/public/req/*` and `/public/res/*` | kept | Request/responder implemented with switch mode |
| `Patch-H-*` passthrough | kept | Supported for stream request/responder flows |
| `Patch-Status` | kept | Supported for stream response status override |
| `?switch=true` on responder | kept | Supported (dynamic handoff channel) |

## Webhooks

| Legacy Surface | Status | Notes |
| --- | --- | --- |
| `/h/*` secret hooks | dropped | Replaced by DB-scoped webhook ingest + token auth |
| `/r/*` reverse hooks | dropped | Replaced by DB-scoped stream and webhook surfaces |
| Webhook proxy behavior | deferred | Explicitly deferred pending further design |

## Auth and ACL

| Legacy Surface | Status | Notes |
| --- | --- | --- |
| Forgejo `.patchwork/config.yaml` ACL loading | dropped | Service uses native DB-scoped token ACLs |
| Query-param token fallback | changed | Primary auth is `Authorization` header bearer tokens |

## Messaging

| Legacy Surface | Status | Notes |
| --- | --- | --- |
| Durable message publish | changed | New DB-scoped `/messages` API with `1 MiB` payload limit |
| SSE replay cursors | changed | Per-DB replay via `since_id`/`tail` in `/events/stream` |
| MQTT adapter | deferred | Listed as post-MVP work |

## Other Capabilities

| Legacy Surface | Status | Notes |
| --- | --- | --- |
| Lease/fencing API | changed | New DB-scoped lease endpoints (`acquire`,`renew`,`release`) |
| Blob control plane | changed | Implemented DB-scoped blob upload/finalize/read/claim/release + keep-set metadata and public publish/unpublish |
| OIDC web login flow | changed | Implemented OIDC login/callback/logout and web-session-backed admin token management |

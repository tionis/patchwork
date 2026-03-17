# Future Considerations

This file tracks important design/implementation decisions intentionally deferred during early prototype work.

## Resolved Decisions (2026-02-15)

1. **No legacy ACL compatibility**
   - Do not support Forgejo `.patchwork/config.yaml` ACL loading in this service.
   - Use native DB-scoped service tokens.

2. **SSE replay scope**
   - Replay/subscription is per `db_id`.
   - No cross-DB replay cursor in v1.

3. **Lease authority storage**
   - Lease/fence authority is local SQLite state for the service deployment.

4. **Blob finalize integrity**
   - `complete-upload` must verify uploaded object hash matches the declared blob hash.

5. **Messaging split**
   - Old patchwork channel behavior is treated as `streams` (bytestream relay/proxy).
   - Message pubsub is separate, with strict payload limits, durability, wildcard subscriptions, and MQTT last-will support.

6. **Message/stream limits and retention defaults**
   - Message payload limit in v1 is 1 MiB.
   - Streams have no fixed application payload cap in v1 (rate limiting still applies).
   - No default TTL for retained/persistent message data; DB operators can define policy.

7. **Webhook ingest model**
   - Webhooks are DB-scoped and persist deliveries to a DB table (`webhook_inbox` pattern).
   - v1 does not include a dedicated webhook-consumer API; users consume via query access.
   - Ingest writes must use explicit column lists so added table columns do not break inserts.

8. **Legacy stream hooks**
   - Dedicated `/h` and `/r` secret-hook behavior is not required in v1.
   - Equivalent control should come from DB-scoped auth on stream/webhook endpoints.

9. **No legacy route aliases**
   - Legacy stream aliases (`/public/*`, `/p/*`, `/u/{user}/*`) are intentionally removed.
   - Canonical DB-scoped routes are the only supported API surface.

9. **Webhook auth model**
   - Webhook ingress uses standard `Authorization` header auth with DB-scoped tokens.
   - No plaintext webhook secret storage is required in MVP.

## Deferred for Later

1. **V1 invariants list**
   - Minimal rules that should not drift during implementation.

2. **Event envelope contract**
   - Exact payload shapes for SSE (`snapshot`, `update`, `heartbeat`, `error`) and pubsub events.

3. **Idempotency semantics**
   - `dedupe_key` scope, retention window, and duplicate behavior.

4. **Blob GC defaults**
   - Default GC grace period and delete safety checks.

5. **DB lifecycle policy**
   - DB creation/deletion authority and naming constraints.

6. **Secrets model**
   - Storage/rotation/access model for `token_ref` and upstream credentials.

7. **Backpressure and limits**
   - Watch limits, connection limits, outbox limits, and overload behavior.

8. **Test strategy**
   - Concurrency/fencing tests, reactive query correctness, blob GC race coverage, and API contract tests.

10. **Legacy webhook proxy feature**
   - Decide keep / change / drop.
   - If kept, decide whether to implement inside stream capability or as a separate adapter.

11. **Webhook HMAC validation**
   - Provider-style request signature validation (for example GitHub HMAC) is deferred.
   - If added later, define per-endpoint config and failure behavior.

12. **Optional Automerge integration (DB-scoped)**
   - Consider supporting Automerge documents inside each `db_id` as an additive capability.
   - Keep it DB-scoped and optional; do not replace the SQLite-first runtime/query model.

13. **`ws4sqlite`-inspired operator ergonomics**
   - Evaluate a DB-scoped stored-statement catalog (server-side named SQL) and an optional strict mode that only allows named statements.
   - Evaluate batch statement execution (`valuesBatch`) for high-throughput insert/update use cases.
   - Evaluate scheduled DB maintenance tasks (vacuum, backup rotation, startup tasks) in the service runtime.
   - Keep these additive and DB-scoped; do not weaken existing token/OIDC auth model.

14. **DB-scoped WebDAV endpoint**
   - Evaluate adding WebDAV routes under DB scope (for example `/api/v1/db/:db_id/dav/...`).
   - Likely storage model: DB-scoped metadata table + blob-backed content objects with path/version metadata.
   - Consider a hybrid strategy for efficiency (small files inline in SQLite, larger files in blob storage).
   - Define auth scopes for read/write/list operations consistent with existing DB-scoped ACL patterns.

15. **Recorder endpoint mode (OwnTracks-inspired ingest)**
   - Evaluate a DB-scoped recorder endpoint for append-only telemetry/event capture.
   - Consider HTTP ingest compatibility patterns documented by OwnTracks:
     - https://owntracks.org/booklet/tech/http/
   - Also evaluate MQTT-based integration path:
     - https://owntracks.org/booklet/tech/mqtt/
   - Decide whether this should be a dedicated API surface or built on existing message/webhook pathways.

16. **DB-scoped notification adapter endpoint**
   - Evaluate a DB-scoped notification API that fans out to notification backends.
   - Candidate backend integrations: Apprise or Shoutrrr.
   - Define backend credential/secret model, delivery retry policy, and failure visibility/metrics.
   - Keep this additive and DB-scoped, without weakening existing auth boundaries.

17. **Git LFS server endpoint**
   - Evaluate adding Git LFS-compatible API support (especially the batch API) as an optional Patchwork capability.
   - Prefer DB-scoped auth/control while reusing global blob dedup and publication/storage primitives.
   - Define LFS-specific scope model (upload/download/verify), object lifetime, and interoperability constraints with common Git clients/forges.

## Notes

- These items are intentionally deferred to keep prototype velocity high.
- Add concrete decisions here (or move them into `DESIGN.md`) when implementation pressure requires them.

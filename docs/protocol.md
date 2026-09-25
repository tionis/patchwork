# HTTP protocol plan v1

The [system overview](unified-design.md) owns typed object formats; this document owns HTTP conventions and the operation inventory. Request shapes are logical until validated in OpenAPI and fixtures. Only implemented routes are exposed; see [status](implementation-status.md).

This document defines the intended first-release wire behavior; OpenAPI 3.1 and fixtures are generated from it. All paths below are relative to `/v1`, except `/hooks/{hook_id}` and health endpoints. API versioning is independent of database schema and snapshot-format versions.

## Conventions

- HTTPS; bearer credentials via `Authorization: Bearer …`. No query tokens on the general API. Hook URLs may contain opaque revocable credentials by explicit configuration.
- JSON uses UTF-8. Positions, revisions, counters, and byte counts are decimal strings to avoid JavaScript precision loss. Timestamps are RFC 3339 UTC. IDs are opaque strings.
- Lists use `{items: [...], next_cursor: null|string}`; default limit 100, maximum 1000. Page cursors bind filters and sort order, are opaque, and never grant access. Reauthorize each page.
- JSON mutation bodies reject unknown fields. New optional response fields are additive. Never silently coerce an invalid position, duplicate security-sensitive JSON field, or unsupported enum.
- Config and metadata GETs return a quoted opaque `ETag`. Their PUTs require `If-Match`; absence is 428, stale value 412. Explicit create uses its own endpoint and unique-name conflict handling.
- Errors use `application/problem+json` with `type`, `title`, `status`, stable `code`, `request_id`, and safe details. 400 invalid request; 401 invalid/expired credential; 403 forbidden; 404 absent or concealed resource; 409 state/config conflict; 410 history lost; 413 too large; 422 validation failure; 429 quota; 503 transient storage/overload, including `recovery_coverage_exceeded` when a stream's [recovery lag budget](storage.md#recovery-requirement-lag-budgets) blocks writes. Responses never suggest a storage failure was accepted.
- Atomic mutation timeout after submission may have an unknown outcome. Clients retry retained append with an idempotency key or inspect state. Cancellation cannot undo a transaction already committed.

Example error:

```json
{"type":"urn:patchwork:error:history-lost","title":"Requested history is no longer retained","status":410,"code":"history_lost","request_id":"req_1","stream_id":"str_1","requested":"80","head":"100","tail":"180"}
```

Return head/tail or snapshot descriptors only if the caller has the relevant read permissions. Problem details must not bypass authorization.

## Endpoint inventory

| Method and path | Body/query | Result / permission |
| --- | --- | --- |
| `POST /streams` | `{name, config?, metadata?}` | 201 descriptor; `stream.create` |
| `GET /streams` | `prefix`, page | Authorized descriptors; `stream.list` and per-item visibility |
| `GET /streams/resolve?name=…` | Canonical name | Descriptor; `stream.inspect` |
| `POST /streams/append?name=…` | Raw bytes | Optional auto-create; create + append authority |
| `GET /streams/{sid}` | — | Descriptor; `stream.inspect` |
| `DELETE /streams/{sid}` | `If-Match` config ETag | 204 logical deletion; `stream.delete` |
| `GET, PUT /streams/{sid}/config` | Complete config replacement | Config + ETag; `stream.config.read/write` |
| `GET, PUT /streams/{sid}/metadata` | `{value: object, object_refs: []}` | Metadata + ETag; `metadata.read/write` |
| `POST /streams/{sid}/records` | Raw bytes | Append receipt; `record.append` |
| `GET /streams/{sid}/records` | `from`, `limit`, `max_bytes` | JSON replay page; `record.read` |
| `GET /streams/{sid}/records/{position}` | — | Raw bytes; `record.read` |
| `GET /streams/{sid}/follow` | `from` | Retained record SSE; `record.read` |
| `GET /streams/{sid}/live` | — | Zero-retention record SSE; `record.subscribe` |
| `POST /watch` | Explicit stream IDs, or one prefix | Coalesced update SSE; `stream.watch` |
| `POST /objects/bytes` | Raw bytes; optional digest/profile | Typed descriptor and upload lease; `object.create` |
| `GET, HEAD /objects/{oid}/bytes` | Authorized root context; optional `Range` | Exact bytes; `object.read` |
| `GET /objects/{oid}` | Authorized context | Typed descriptor; `object.read` |
| `POST /objects/bytes/compose` | Authorized source ranges/new bytes | New leased root or job; create + source read/link |
| `POST /objects/maps` | Profile and entries | New leased map; `object.create` |
| `POST /objects/directories` | Profile and entries | New leased directory; `object.create` |
| `GET /objects/{oid}/entries` | Map bounds or directory path, page | Root-bound entries; `object.read` |
| `POST /objects/{oid}/edits` | Kind-specific bounded batch | New leased root; read/create/link |
| `GET /objects/{oid}/resolve` | Path components, follow-links opt-in | Confined directory lookup; `object.read` |
| `POST /object-diffs` | Two roots, kind/profile, bounds | Bounded diff pages; read both roots |
| `POST /object-pins` | `{object, expires_at?}` | Retention; `object.pin` + link |
| `DELETE /object-pins/{pin_id}` | — | 204; pin ownership/admin |
| `GET, POST /refs` | Authorized `prefix`, page / canonical name, fixed kind, root | Bounded name-ordered descriptors / create; `ref.list/create` + link on create |
| `GET /refs/resolve?name=…` | Exact canonical hierarchical name | Authorized descriptor with stable ID/revision; `ref.read` |
| `GET, DELETE /refs/{rid}` | CAS for delete | Descriptor or deletion; `ref.read/delete` |
| `POST /refs/{rid}/publish` | Expected revision, root, optional record | Atomic ref + zero/one record; publish + link/append |
| `GET /streams/{sid}/snapshots` | `type`, `at_or_before`, page | Descriptors; `snapshot.list` |
| `POST /streams/{sid}/snapshot-jobs` | `{adapter_id, position}` | 202 job; `snapshot.create` |
| `GET /jobs/{job_id}` | — | Common job status; scoped `job.read` |
| `POST /jobs/{job_id}/cancel` | — | Cancellation fence/committed outcome; `job.cancel` |
| `POST /streams/{sid}/snapshots` | Client/adapter descriptor | 201; `snapshot.publish` + link |
| `POST /streams/{sid}/snapshots/{snap_id}/accept` | Requirement and expected policy revision | Acceptance receipt; `snapshot.accept` |
| `POST /streams/{sid}/source-leases` | Seed, `[from,through)`, bounded lifetime | Scoped `lease.create` + source reads |
| `POST /leases/{lease_id}/renew` | Bounded lifetime | Reauthorized renewal; `lease.renew` |
| `DELETE /leases/{lease_id}` | — | Release authorized lease; `lease.release` |
| `DELETE /streams/{sid}/snapshots/{snap_id}` | — | 204 or 409 if recovery-protected; `snapshot.delete` |
| `GET, POST /streams/{sid}/attachments` | List / attachment config | Inspect or create; `attachment.read/write` |
| `PUT, DELETE /streams/{sid}/attachments/{aid}` | CAS revision | Update/remove; `attachment.write` |
| `POST /streams/{sid}/attachments/{aid}/rebuild` | `{snapshot_id?}` | 202 recover job; `consumer.rebuild` |
| `POST /streams/{sid}/attachments/{aid}/skip` | `{position, reason}`; position must equal the stalled applied position | Audited skip of one poison record; `consumer.skip` |
| `GET /streams/{sid}/kv/{aid}/items` | Key-prefix, page | KV page with applied position; `kv.read` |
| `GET, PUT, DELETE /streams/{sid}/kv/{aid}/items/{key}` | Bytes for PUT; condition headers | KV contract below; `kv.read/write` |
| `GET, POST /hooks` | List / hook specification | Administrative hook API; `hook.manage` |
| `GET, PUT, DELETE /hooks/{hid}` | CAS for PUT | Config, counters, secret rotation; `hook.manage` |
| `POST /hooks/{hid}` (unversioned) | Provider request | Configured ingress response |
| `POST /auth/challenges` | `{public_key}` | SSH authentication challenge |
| `POST /auth/exchange` | `{challenge_id, signature}` | Short-lived bearer credential |
| `GET, POST /auth/credentials` | List / requested scope and expiry | Credential records / mint result |
| `DELETE /auth/credentials/{cid}` | — | 204 revoke; ownership/admin |
| `GET, POST /admin/principals` | List / principal | Principal administration |
| `PUT /admin/principals/{pid}` | CAS; enabled, keys, grants | Principal update |
| `GET, PUT /admin/policy` | CAS; validated server policy | Instance authorization policy |
| `GET, PUT /admin/creation-rules` | CAS; defaults and rules | Instance creation templates |
| `GET /admin/status` | — | Storage, worker, backup health |

Administrative schemas must be finalized with authorization fixtures. Core endpoints permit neither arbitrary SQL nor implicit execution of uploaded bytes. App/function routes are defined in [Functions](functions-design.md) and [apps](reference-apps.md); grants are approved separately. Snapshot/rebuild/object jobs all use `/jobs/{job_id}`. Recovery requirement changes are CAS-protected stream config/attachment operations. Lease permissions neither grant reads nor release another owner's protection. No unrestricted generic transaction endpoint exists.

## Stream descriptor and configuration

```json
{
  "id":"str_1", "name":"events/git/project", "revision":"1",
  "mode":"retained", "head":"0", "tail":"0",
  "created_at":"2026-09-22T12:00:00Z"
}
```

Config shape:

```json
{
  "retention":{"mode":"bounded","max_age_seconds":"604800","max_bytes":"1073741824"},
  "max_record_bytes":"1048576",
  "filters":[], "validators":[]
}
```

Retention mode is `infinite`, `bounded`, or `none`; bounded requires at least one positive bound. Attachments are managed separately but changes advance the stream config revision for GC concurrency control. A descriptor for mode `none` omits head/tail. Mode `none` permits stateless ingress filters/validators and live subscribers, but rejects durable KV, replay consumers, snapshot producers, snapshot publication and recovery requirements: none has a durable position or replay suffix. Reject incompatible create/configuration requests, including create-on-append templates, rather than silently ignoring attachments. Pipeline entries select a pinned built-in or approved function deployment, config and permitted `on_error` mapping. Recovery requirements specify format/config plus server producer or external acceptance policy; changes advance the stream config revision.

## Raw append and retries

`Content-Type` describes candidate payload bytes; default `application/octet-stream`. `Patchwork-Object-Refs` is a JSON array of typed object IDs, bounded to 64 entries and 8 KiB of header bytes. Body content never implicitly creates references. Clients must possess link authority for each referenced object. This header is optional and not needed for simple curl use.

Optional `Idempotency-Key` is 1–128 printable ASCII bytes. Scope is `(stream_id, principal ID, endpoint class, key)`; delegated service/hook grants use the grant ID in place of the principal. Scoping by principal rather than credential lets a script re-authenticate (new session or token) and still retry safely; the receipt only returns a position, and current authorization is rechecked before it is returned. Store a canonical digest over original body, content type, explicit references, and ingress fields affecting processing, before transformations. Do not include authorization-header bytes. Replay with identical digest returns the saved result; changed input returns 409. Current authorization is still required. Stored results survive stream trimming until expiry. Proposed deduplication window: 24 hours, advertised in the receipt. A pipeline config change does not alter a previously saved result. After expiry a retry may create a new record.

Retained success: 201 with

```json
{"outcome":"appended","stream_id":"str_1","position":"42","next_position":"43","deduplicated":false,"idempotency_expires_at":"2026-09-23T12:00:00Z"}
```

Fields about idempotency are omitted if no key was supplied. Deduplicated replay returns 200 with `deduplicated:true`. A receipt's position may subsequently be trimmed; the receipt does not pin its record.

Drop: 200 `{ "outcome":"dropped", "stream_id":"str_1" }`, no position. Retained drops with a key store the deduplication result; creation-on-append drops create no stream and therefore no stream deduplication row. Hook endpoints can hide the outcome and return a fixed 204 for both pass and drop.

Zero retention: 202 `{ "outcome":"published", "stream_id":"str_2", "epoch":"…", "sequence":"7" }`. Accept means processing passed and live distribution was attempted; no subscriber receipt or replay guarantee. Reject `Idempotency-Key` on zero-retention streams in v1 rather than implying durable delivery deduplication.

```bash
curl --fail-with-body -H "Authorization: Bearer $PATCHWORK_TOKEN" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: job-20260922-1' \
  --data-binary @event.json https://patch.example/v1/streams/str_1/records
```

## Replay and record follow

Replay requires explicit `from`. If `from < head`, return 410; if `from > tail`, return 409 `position_ahead`. `from == tail` returns an empty page. Sample page:

```json
{"stream_id":"str_1","head":"0","tail":"43","records":[{"position":"42","accepted_at":"2026-09-22T12:00:00Z","content_type":"text/plain","data_base64":"aGVsbG8=","object_refs":[]}],"next_position":"43"}
```

Default replay budget is 100 records / 4 MiB payload, maximum 1000 / 16 MiB. To avoid zero-progress pagination, an individually valid record larger than a requested page budget is returned alone. Limits are payload limits; base64 adds transport overhead. A single raw record GET returns original bytes, content type, and position header. Readers do not receive raw ingress headers or authentication context.

Retained follow uses `text/event-stream`. Each `record` event contains one replay record with ID `<stream_id>:<next_position>`. On reconnect, `Last-Event-ID` is a resume cursor; a conflicting `from` is 400. An SSE ID is never authority. A `ready` event gives stream/head/tail after the subscription race is closed. Heartbeats are SSE comments. No database transaction remains open while waiting or sending.

If history is trimmed during follow before the client catches up, emit `history_lost` and close. A slow client whose network queue is full gets `lagged` where possible, then closure; reconnection/replay is required. On an abrupt disconnect, clients must assume the last event might be repeated. Initial errors use HTTP status; errors after headers use typed SSE events and closure.

Replay pages are materialized under a bounded, short SQLite read view and sent only after that view closes; follow uses new bounded reads after each wakeup. A retained record's explicit object references are not its payload: record permission alone does not authorize object download. Object GET/HEAD and hosted asset delivery acquire authorized graph protection before a root can disappear, retain it through the transfer, and release it on completion or cancellation. Neither a socket send nor a slow client holds a SQLite read transaction open. See [storage lifetime](storage.md).

## Live records and coalesced watches

`/live` is only for mode `none`. `ready` contains epoch and current sequence; `record` contains sequence, content type, base64 bytes, references. No events before readiness are promised. Queue overflow closes with `lagged`; reconnect cannot repair loss.

`POST /watch` accepts exactly one of `{stream_ids:[...]}` or `{prefix:"events/"}`. Explicit lists fail as a whole if any stream is unauthorized. Prefix watch requires explicit authority over the complete selector; do not feed many resources into one existential token check. Dynamic created/deleted streams are included only within the authorized selector.

Events: `ready {watch_id, revision}`, `changed {stream_id, kinds:["records"|"metadata"|"snapshots"|"config"]}`, `created`, `deleted`, and `resync_required`. These are hints; they contain no record bytes, object IDs, metadata values, or tail unless separately authorized. Coalescing may collapse repeated changes. Watch revision is process-local and not a replay cursor. Disconnect/restart requires resynchronizing authorized resources. Clients needing record history maintain per-stream cursors through the read APIs.

To avoid missed wakeups: establish watch and receive ready, read current authorized state, then react to queued hints. Server registers interest before readiness and buffers changes during initial state assembly. Client readiness means only subscription establishment, not a data update. Prefix watching does not itself grant enumeration/read rights.

## Objects and snapshots

Byte upload streams through canonical chunking and validates durable closure before success. Response 201: `{object, size, verified_digest?, upload_lease_id, expires_at}`; a raw digest is not the object ID. Default upload lease: one hour. Internal deduplication must not disclose another principal's content. Expired unlinked uploads may be collected.

Linking requires an owner-scoped upload lease or explicit `object.link` authority in a validated access context. Knowing a root/hash alone is insufficient. Byte GET supports one range with 206/416 and a strong representation ETag. Map/directory edits do not mutate their inputs; publication is a separate reference command. The server verifies root context and descendant membership, not merely a client-supplied parent ID. Pinning controls lifetime, not visibility.

References follow the [reference contract](unified-design.md#publication-streams-and-snapshots). On the wire: exact resolution and prefix listing are metadata operations, not content reads; list pages are ordered by canonical name, bind prefix and caller context, and recheck visibility on every page. Clients mutate by ID plus expected revision. `POST /refs/{rid}/publish` requires the current revision, the fixed target kind and link authority; the destination root is durably prepared before commit, and a failed CAS transfers no root ownership. No implicit reference creation on resolve/read and no public hash lookup. Public redirect routes are not part of this API; see [later integrations](later-integrations.md#redirect-serving-bindings-g-redirect-r-09).

Snapshot descriptor:

```json
{"id":"snap_1","stream_id":"str_1","type":"patchwork/kv/v1","position":"100","object":"<typed-root>","dependencies":[],"producer":{"kind":"adapter","id":"att_1","version":"1"},"semantic_config_hash":"sha256:…","created_at":"2026-09-22T12:00:00Z"}
```

IDs/root above are illustrative; producer identity is host-derived. Client producers use client provenance, not an adapter ID. Dependencies declare opaque references; typed closure is traversed from registered edges.

Ad-hoc job position must be `head <= P <= tail` and have compatible seed plus contiguous history to P, or genesis history when no seed exists. Creation at a historical P is allowed. Failure is explicit `snapshot_source_missing`. Listing newest type at or before P does not certify that the suffix to P is still available; include `replay_available_to_requested_position` when requested, computed under a consistent storage view. Snapshot descriptor access and snapshot payload download are separate permissions.

External snapshot publication is privileged: the server cannot verify arbitrary opaque state semantically. It must validate stream ID, boundary, durable dependencies, type, and producer provenance. Clients may publish without a server adapter, including encrypted payloads; see [client-produced snapshots](external-snapshots.md). Publication alone does not satisfy a recovery requirement or authorize trimming. `snapshot.accept` separately authorizes acceptance under the stream's revisioned trust/compatibility policy; existing adapters must explicitly accept compatibility before using external state. The ordinary append credential cannot publish or accept recovery state. Source-lease and acceptance schemas/receipts are frozen with M2-06 fixtures before exposure.

## KV wire contract

Key is a single base64url-without-padding path component encoding 1–1024 UTF-8 bytes; values are opaque bytes with a content type of 1–255 printable ASCII bytes. The proposed maximum value for a stream with the default 1 MiB record limit is 720 KiB; the exact accepted maximum is also constrained by the size of the fully serialized canonical KV event under that stream's configured record limit. An oversize PUT returns 413 without appending. GET returns bytes, ETag derived from the key revision, and `Patchwork-Applied-Position`. A missing key is 404. Listing returns keys, revisions, and pagination; it does not imply access to backing record history.

PUT supports `If-Match` for existing value revision or `If-None-Match: *` for create-if-absent. DELETE supports optional `If-Match`. Conditions are checked against authoritative materialization in the same transaction that accepts the event. Failed conditions return 412 with no appended event. Unconditional DELETE of a missing key returns 204 without appending. Successful PUT returns 200 or 201 and `{revision, position, applied_position}`; DELETE returns 204 with revision/position headers when an event was appended. A matching KV read sees at least that committed position when success is returned; later writes may already have changed the value. Generic append still promises only generic append semantics.

Raw append to a KV-enabled stream must use the [canonical KV event format](processing.md). Arbitrary bytes fail mandatory validation. KV adapter writes require `kv.write` and use a server-internal scoped append operation; they do not grant the caller raw `record.append`. KV mutations accept the shared `Idempotency-Key` contract, scoped to stream/attachment, principal and operation. A matching currently authorized receipt returns before reevaluating the original condition, even if the key has since changed. Without a key or after expiry, conditions reevaluate and may fail after an unobserved success.

## Provisional resource limits

| Limit | Proposed initial value |
| --- | --- |
| Record / metadata / byte-object upload | 1 MiB / 64 KiB / 1 GiB |
| Watch explicit streams | 256 |
| Record subscriber queue | 256 records and 8 MiB, whichever first |
| SSE heartbeat / authorization refresh | 15 seconds / at most 5 seconds |
| HTTP body read idle timeout | 30 seconds |
| Credential byte length / attenuation blocks | 16 KiB / 32 |
| Pipeline stage input/output/time | Record limit / record limit / 100 ms |
| Snapshot job runtime | Configurable 5 minutes default, streamed input |

These are operational defaults, not measured capacity claims. A documented instance configuration may lower/raise them within tested bounds. The implementation must reject oversized input before unbounded allocation.

# Processing and built-in adapters

## Execution contracts

Built-ins establish working behavior. Approved uploaded code uses [Functions](functions-design.md) after runtime, host, authority and recovery gates pass. Both use the common command boundary; neither receives arbitrary SQL, filesystem paths, credentials or ambient authority.

| Profile | Contract |
| --- | --- |
| Filter | Immutable ingress context and candidate -> pass, drop or reject |
| Validator | Final candidate and fixed validation context -> accept or fail closed |
| Consumer | Committed input and scoped state -> state delta/checkpoint, committed atomically |
| Snapshot producer | Compatible seed, exact `[Q,P)` records and semantic config -> durable typed snapshot at P |
| Endpoint/webhook/job | Approved input and capabilities -> existing commands and bounded results |

These are logical contracts, not placeholder Rust traits. Bind types and streaming interfaces to implemented behavior.

Ingress context holds immutable original bytes/selected headers, host-verified identity/evidence, endpoint kind, request ID and fixed acceptance-time context. Candidate records carry current bytes, content type and explicit `object_refs`. Filters cannot change principal, target stream or original authentication.

Execution failure is distinct from intentional rejection/drop. Default is reject; only designated ingress filter stages can explicitly map execution failure to silent drop with internal metrics. Authentication, mandatory validators and storage failures cannot be hidden. Filters cannot append independently and then reject. Prepared objects remain request/job-leased on failure.

## Built-in KV

One transactional `patchwork/kv/v1` materializer per stream establishes authoritative values and revisions. Its matching snapshot producer is an independent attachment. An unbypassable final validator ensures every generic/adapter append is a canonical KV operation. Adapter-request key, operation and condition must survive filters unchanged; explicitly approved value transforms are reflected in returned semantics.

Canonical event is bounded UTF-8 JSON with no unknown fields. For a default 1 MiB record limit, a PUT value is provisionally capped at 720 KiB (737,280 bytes): base64 then consumes 983,040 bytes, leaving room for the bounded key, content type, condition and JSON envelope. Content type is 1–255 printable ASCII bytes, matching the record limit. The complete serialized event must also fit the stream's configured record limit, which may be smaller; reject an oversize adapter PUT or generic append before commit. Freeze exact encoding and boundary fixtures with M3-02; a value limit never bypasses the serialized-record check:

```json
{"version":1,"op":"put","key":"theme","value_base64":"ZGFyaw==","content_type":"text/plain","condition":{"kind":"absent"}}
```

Delete contains key and optional condition, not value/content type. Conditions are unconditional, absent (PUT only), or existing-value revision. Revision is the last successful mutation record position, encoded as decimal; position zero is valid, absence is separate. Preserve deleted-key versions to prevent ABA and deterministic-recovery ambiguity.

In the append transaction validate conditions, apply the operation and advance state/checkpoint. Generic append shares this path; conditional writes never decide against stale state. Replay applies accepted operations without re-deciding admission conditions against an unrelated cache.

Initially enable KV only on an empty retained stream or a compatible snapshot plus valid suffix, otherwise return conflict. Mode `none` has no durable positions and cannot host KV or a KV snapshot producer. A future online installation can build a shadow materialization and switch under a fence; it must never skip incompatible events.

## KV snapshot format

The descriptor binds stream, type, boundary P and semantic config. Every KV snapshot format encodes, per key in exact UTF-8 byte order, either live bytes/content type/last revision or a tombstone/last revision. Restore preserves values, key revisions and tombstones.

Two formats are planned, so KV recovery does not wait on the ordered-map engine (G-PROLLY):

| Type | Payload | Available |
| --- | --- | --- |
| `patchwork/kv-snapshot/v1` | One `bytes/v1` object (fixed-chunk profile) holding sorted, length-prefixed canonical entries | Objects-and-recovery release (M3-03) |
| `patchwork/kv-map-snapshot/v1` | `map/v1` ordered-map root; large values as typed byte-object references | After O-04 adopts the map engine; adds structural sharing between snapshots |

The byte-stream format is produced and restored by a single streaming pass. It shares no structure between snapshots, so each snapshot costs its full logical size; measure that before relying on frequent snapshots of large KV state. Entry encoding and fixtures are frozen with M3-03; the map format with O-04.

Reject duplicate/out-of-order keys, revisions >= P, wrong stream/type/config, malformed entries and unavailable dependencies. A generic byte object or map is not a KV snapshot until validated against its format.

The producer derives state from a compatible seed plus `[Q,P)` using a streaming merge, leased immutable map edits or bounded disposable scratch indexing. Scratch state is not a second authoritative database or a source of live-state truth. No separate mandatory export format is required for recovery.

## Optional CRDT-backed consumers (later)

Automerge is a scoped later integration over retained streams, objects and accepted snapshots, not a new Patchwork data primitive or built-in KV replacement. A durable record receipt proves accepted bytes, not completion by an asynchronous CRDT consumer; expose its applied position, pending/stalled state and a separately defined incorporation acknowledgement. Mode `none` cannot host it.

The [Automerge document contract](reference-apps.md) owns its peer protocol and causal snapshot rules. The server may validate and retain document changes, but must not treat session sync frames as immutable changes or a rendered JSON projection as a recoverable snapshot. An encrypted client-only document remains opaque and uses external snapshot acceptance.

A cr-sqlite derived consumer is deferred (F-05); its constraints are preserved in [later integrations](later-integrations.md#cr-sqlite-derived-consumer-g-crsql-deferred-under-f-05).

## Forge webhook ingress

Implement one provider with original-byte signature fixtures first: GitHub-style HMAC-SHA256 push events. Verify official provider contracts before claiming compatibility with other providers.

Order: bound body -> verify original bytes -> identify event -> bounded parsing/predicate -> minimal transform/drop -> common stream pipeline/final validator -> authorized commit -> safe response. Responses support 200 with fixed safe body or 204 for successful pass/drop; auth/mandatory validation/storage failures remain errors. No arbitrary header/redirect templates.

Provider delivery ID uses the common retained receipt machinery under hook identity, after authentication. It is not proof of authenticity. Zero-retention retries can duplicate wakeups. A wakeup consumer fetches its authoritative source and tolerates duplicates/coalescing. Counters expose accepted/dropped/rejected/errors without retaining secret raw requests.

Custom verifier/handler profiles reuse this ingress contract; the host binds verified evidence to original bytes, target and pinned verifier identity. Handler code cannot forge that evidence.

## Application state and recovery

Use KV for small independently updated values, or immutable map batch edits plus one reference CAS for multi-key state/invariants. Add indexes as scoped stream materializations only where measured query needs justify them. Consumer state/checkpoint commits atomically; external effects use the shared outbox job kind and are disabled during rebuild. Do not add a general collection database or query language merely for example apps.

Transforms do not preserve a signature over changed bytes. Retain original signed content only when authorized and required. Encrypted records and snapshots remain opaque: semantic processing runs in clients or other explicitly trusted endpoints holding plaintext keys.

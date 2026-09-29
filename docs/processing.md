# Processing and built-in adapters

## Execution contracts

Built-ins establish working behavior. User code execution is a non-goal (see [design](design.md#non-goals)). Built-ins use the common command boundary and receive no arbitrary SQL, filesystem paths, credentials or ambient authority.

| Profile | Contract |
| --- | --- |
| Filter | Immutable ingress context and candidate -> pass, drop or reject |
| Validator | Final candidate and fixed validation context -> accept or fail closed |
| Consumer | Committed input and scoped state -> state delta/checkpoint, committed atomically |
| Endpoint/webhook/job | Approved input and capabilities -> existing commands and bounded results |

These are logical contracts, not placeholder Rust traits. Bind types and streaming interfaces to implemented behavior.

Ingress context holds immutable original bytes/selected headers, host-verified identity/evidence, endpoint kind, request ID and fixed acceptance-time context. Candidate records carry current bytes, content type and explicit `object_refs`. Filters cannot change principal, target stream or original authentication.

Execution failure is distinct from intentional rejection/drop. Default is reject; only designated ingress filter stages can explicitly map execution failure to silent drop with internal metrics. Authentication, mandatory validators and storage failures cannot be hidden. Filters cannot append independently and then reject. Prepared objects remain request/job-leased on failure.

## Built-in KV

One transactional `patchwork/kv/v1` materializer per stream establishes authoritative values and revisions. An unbypassable final validator ensures every generic/adapter append is a canonical KV operation. Adapter-request key, operation and condition must survive filters unchanged; explicitly approved value transforms are reflected in returned semantics.

Canonical event is bounded UTF-8 JSON with no unknown fields. For a default 1 MiB record limit, a PUT value is provisionally capped at 720 KiB (737,280 bytes): base64 then consumes 983,040 bytes, leaving room for the bounded key, content type, condition and JSON envelope. Content type is 1–255 printable ASCII bytes, matching the record limit. The complete serialized event must also fit the stream's configured record limit, which may be smaller; reject an oversize adapter PUT or generic append before commit. Freeze exact encoding and boundary fixtures with M3-02; a value limit never bypasses the serialized-record check:

```json
{"version":1,"op":"put","key":"theme","value_base64":"ZGFyaw==","content_type":"text/plain","condition":{"kind":"absent"}}
```

Delete contains key and optional condition, not value/content type. Conditions are unconditional, absent (PUT only), or existing-value revision. Revision is the last successful mutation record position, encoded as decimal; position zero is valid, absence is separate. Preserve deleted-key versions to prevent ABA and deterministic-recovery ambiguity.

In the append transaction validate conditions, apply the operation and advance state/checkpoint. Generic append shares this path; conditional writes never decide against stale state. Replay applies accepted operations without re-deciding admission conditions against an unrelated cache.

Enable KV only on an empty retained stream, otherwise return conflict. Mode `none` has no durable positions and cannot host KV.

## Forge webhook ingress

Implement one provider with original-byte signature fixtures first: GitHub-style HMAC-SHA256 push events. Verify official provider contracts before claiming compatibility with other providers.

Order: bound body -> verify original bytes -> identify event -> bounded parsing/predicate -> minimal transform/drop -> common stream pipeline/final validator -> authorized commit -> safe response. Responses support 200 with fixed safe body or 204 for successful pass/drop; auth/mandatory validation/storage failures remain errors. No arbitrary header/redirect templates.

Provider delivery ID uses the common retained receipt machinery under hook identity, after authentication. It is not proof of authenticity. Zero-retention retries can duplicate wakeups. A wakeup consumer fetches its authoritative source and tolerates duplicates/coalescing. Counters expose accepted/dropped/rejected/errors without retaining secret raw requests.

Custom verifier/handler profiles reuse this ingress contract; the host binds verified evidence to original bytes, target and pinned verifier identity. Handler code cannot forge that evidence.

## Application state

Use a keyspace for keyed mutable state and a document for collaborative state (see [design](design.md)). Stream-derived KV remains until keyspaces supersede it (D35). Consumer state and checkpoints commit atomically with what they apply. External effects use a durable delivery job with stable identity and are never replayed by a rebuild.

Transforms do not preserve a signature over changed bytes. Retain original signed content only when authorized and required. Encrypted records remain opaque: semantic processing runs in clients that hold the keys.

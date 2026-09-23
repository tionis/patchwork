# Architecture and invariants

The [system overview](unified-design.md) defines the three data primitives and their composition. This document owns stream semantics and shared invariants; runtime availability is in [implementation status](implementation-status.md).

## Resource model

| Resource | Identity | State |
| --- | --- | --- |
| Stream | Random stable ID; unique canonical name | Concrete config, metadata, head, tail, records |
| Object | Versioned typed content root | Immutable bytes/map/directory descriptor and required block graph |
| Reference | Random stable ID; unique canonical hierarchical name | One typed object root, fixed target-kind constraint, lifecycle and monotonic revision |
| Snapshot | Random snapshot ID | Stream ID, type, position, object root, declared opaque dependencies, producer provenance |
| Recovery requirement | Stream-scoped stable ID | Format/config and acceptance policy; optional server producer; protected anchors |
| Attachment | Stream ID and attachment ID | Kind, pinned implementation version, config revision, status |
| Principal | Stable principal ID | Registered SSH keys, enabled state, grants |
| Credential | Server credential ID | Issuer/key reference, expiry ceiling, revocation state, issuance scope |
| Hook | Random hook ID | Target stream, provider authentication, pipeline, response mapping |

Names are an ergonomic lookup mechanism, including hierarchical reference namespaces; they do not create parent resources or imply directory ACLs. IDs are the durable identity used in cursors, attachments, and exact-resource grants. Deleting and recreating a name creates a new ID. Rename is deferred to reduce first-release lifecycle complexity.

Proposed name grammar: 1–240 UTF-8 bytes, restricted initially to ASCII path components `[A-Za-z0-9][A-Za-z0-9._-]*`, separated by `/`. Reject empty, `.` and `..` components, leading/trailing slash, backslash, NUL, and noncanonical encodings. Names are case-sensitive. A rule for `foo/` matches descendants such as `foo/bar`, never `foobar`; exact `foo` is a separate selector.

## Positions and retention

Retained record positions start at 0 and increase by one per committed record. Positions/tails are in `[0, 2^63-1]`, encoded as decimal strings. The final appendable position is `2^63-2`, since its next tail must remain representable. Exhaustion is a hard error; never wrap.

`tail` is the next append position. `head` is the first readable position. Retained records occupy `[head, tail)` with no holes. Trimming never renumbers records. Snapshot at P means state after records `[0, P)` under that snapshot type's semantics. Restore resumes at P.

Positions are stream-local. A cursor consists of both stream ID and position. Do not compare positions across streams. Failed and dropped writes do not allocate positions. Revisions are separate checked counters; revision zero is valid.

Zero-retention streams have no durable record cursor. They expose a live epoch and process-local increasing sequence for gap detection only. Restart changes epoch; replay is unavailable. Stream configuration and metadata are durable even for zero-retention streams. They may run stateless ingress filters/validators and live delivery, but cannot attach durable KV, replay consumers, snapshot producers or recovery requirements, or publish position-bound snapshots.

Retention modes are `infinite`, `bounded`, and `none`. Mode switching between `none` and retained modes is deferred. Bounded retention may constrain age, logical retained bytes, or both. Snapshot and pinned-blob bytes are separately accounted; bounded log retention cannot guarantee bounded total disk usage.

## Append path

1. Resolve canonical resource and authenticate the request. Check permission and input-size limits.
2. Verify ingress authentication, including provider signature where applicable, against immutable original bytes and selected headers.
3. For an existing retained stream and supplied idempotency key, check the original-input digest and saved result after authentication (including provider signature). An authorized matching replay returns the saved result without rerunning filters. Otherwise produce one candidate record. Run endpoint-specific ingress filters, then mandatory stream filters, in configured order. Each returns `Pass(record)`, `Drop`, or `Reject(error)`.
4. Validate the final record and its explicit object references. Enforce size limits again after each transformation.
5. Recheck stream/config/policy revision at commit. A change forces a fresh authorized evaluation or a retryable conflict; do not commit using stale validation.
6. For retained streams, commit record, tail advance, references, and optional deduplication result atomically. Then signal readers. For zero-retention streams, enqueue best-effort live delivery within bounded queues.
7. Return the operation-specific receipt. Slow readers never hold the storage transaction open.

Filter code is not run while holding a SQLite write transaction. Built-in stateful KV conditional validation is a separate bounded in-transaction step. Stream pipelines cannot route records to a different stream in v1; that would require a new authorization decision.

Drop is intentional successful ingestion with no append. Runtime failure is separate: administrators may configure a particular ingress filter to map an execution failure to silent drop. Authentication failures, mandatory validators, authorization, and storage failures cannot be hidden by that setting. Record drop/error metrics internally without retaining secret raw payloads.

## Consumers and adapters

Consumers have type/version/config, consistent materialized state and applied position, health, and optionally an HTTP API. A consumer failure leaves a visible stalled position. It never silently advances past a poison record. A retained append receipt is not an asynchronous consumer-incorporation acknowledgement; callers that need one wait for a separately committed applied position or receive explicit pending/stalled state.

Consumer recovery may use a compatible accepted snapshot. Once trim overtakes a consumer, restore or fail with `recovery_required`. Consumers do not automatically pin history. All-event processing uses infinite retention; an explicitly admitted bounded source lease protects a finite catch-up range, not an indefinite delivery guarantee.

Snapshot producers are independent of consumers. Every configured recovery requirement needs accepted compatible coverage before trim, supplied by a server producer or external client. An already accepted anchor beyond a proposed cutoff can satisfy it without recomputation. Publishing an ad-hoc snapshot does not automatically accept it for recovery. The [storage algorithm](storage.md) defines coverage and source protection.

External effects use the common durable delivery-job/outbox contract with stable IDs and at-least-once retries. Rebuilding a materialization MUST NOT enqueue or replay those effects.

## Creation and configuration

Instance defaults plus the longest matching prefix rule select a creation template. Each rule is a complete override of the instance template, not a merge through an arbitrary ancestor chain. Creation materializes concrete config in the stream. Editing a rule does not mutate existing streams.

Proposed defaults: explicit creation; infinite retention; create-on-append opt-in by prefix; no create-on-read in v1. Auto-creation requires both stream creation authority for the name and append authority under the proposed configuration. An invalid, rejected, or dropped first request does not leave a newly created stream. Race concurrent creation under a unique-name transaction; a loser reloads and revalidates against the winning configuration.

Privileged config includes retention, recovery requirements, pipeline, attachments, limits and access policy references, with its own revision/CAS API. Application metadata is bounded JSON with a separate revision/CAS API. Metadata cannot set privileges, pipelines or retention. Explicit `object_refs` establish roots only after authorized linking; arbitrary hash strings do not.

## Core invariants

- I01: An acknowledged retained append is committed durably; notifications follow commit.
- I02: Records are immutable, uniquely positioned, contiguous over `[head, tail)`.
- I03: All append paths apply the configured stream pipeline and validators.
- I04: Trim never advances head past accepted coverage of any current recovery requirement or through protected source ranges.
- I05: Snapshot descriptors never refer to nondurable or collectable dependencies.
- I06: Consumer state and applied position change atomically.
- I07: Names, content hashes, and notification access do not independently grant data access.
- I08: All delegated authority is bounded by issuance scope, current server policy, expiry, and attenuation.
- I09: Slow clients and extension failures cannot cause unbounded memory growth.
- I10: Deletion/recreation cannot rebind old exact-resource credentials or cursors.
- I11: Configuration/policy changes cannot bypass validation or authorize a stale commit.
- I12: A filtered drop is distinguishable internally from committed data, even when an ingress hides that distinction externally.

## Operations

Health includes readiness, migration state, disk pressure, writer queue, WAL size, oldest uncheckpointed transaction, stream head/tail, per-consumer lag, snapshot failures, and auth/pipeline rejection counts. Avoid resource IDs as unbounded metric labels; detailed per-stream state belongs in the API/UI.

Use structured logs with request ID and safe error code. Never log bearer tokens, hook secrets, signatures, raw record content, or query credentials by default. Keep HTTP public access behind TLS. Trust forwarded headers only from configured proxies.

The operational UI uses the same authorized APIs as CLI and other clients. Minimum screens: streams/records; metadata/config; consumer/snapshot status; hooks/counters; credentials; storage/backup health. It uses the shared browser session mechanism on the trusted identity/operations origin: a one-use CLI-assisted SSH handoff establishes a short-lived, host-only Secure HttpOnly cookie. Hosted app sessions use the same mechanism with their own origins, audiences and binding ceilings. App origins never receive operational sessions or SSH private keys. Credential minting from the operational UI requires a fresh SSH-authenticated session with unattenuated provenance and current mint authority; an app/guest/API-token exchange cannot acquire it.

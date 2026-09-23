# Storage, snapshots, and garbage collection

## Chosen starting point

One SQLite database owns mutable authoritative state. Local content-addressed files hold shared chunks and typed nodes; [object formats](unified-design.md) define their identities and edges. Logical segments group SQLite records, not physical log files. Do not add a second authoritative database or independent tree-library collector. A later CRDT integration may use a separate, disposable derived SQLite sidecar only if its state and applied position commit together there and can be reconstructed from an accepted snapshot plus protected retained suffix; cross-file WAL commits are not a correctness boundary. See [processing](processing.md).

Use WAL, `synchronous=FULL`, foreign keys on every connection, bounded busy handling/write admission and short transactions. SQLite has a single WAL writer; long readers can delay checkpoints. The deployment needs a supported local filesystem and tested synchronization behavior. [SQLite WAL](https://www.sqlite.org/wal.html), [synchronous setting](https://www.sqlite.org/pragma.html#pragma_synchronous).

An acknowledgement means the configured durable commit completed, not merely that bytes reached a process buffer. Graceful reopen, hard-kill recovery and hardware power loss require distinct evidence.

## Logical storage responsibilities

These are schema responsibilities, not ready migrations. Use checked IDs/counters, foreign keys and explicit lifecycle constraints.

| State | Identity and contents |
| --- | --- |
| Streams/records/segments | Stable stream ID; live name; config/metadata revisions; head/tail; immutable positioned bytes; logical byte/time summaries |
| Blocks/objects/edges | Block hash and lifecycle; typed descriptor/root/profile; validated direct required edges and optional history links |
| References | Stable ID/name; target-kind constraint; object root; monotonic revision and lifecycle |
| Roots/leases | Owning resource and object root; or bounded owner-scoped object/source-range protection with expiry/generation |
| Snapshots | Immutable stream/type/boundary/object root; producer/format/config provenance and declared opaque dependencies |
| Recovery requirements/acceptances | Stream-scoped format/config; producer/trust policy revision; selected accepted anchors and approving identity |
| Attachments/checkpoints | Stream-scoped implementation/config; materialized state; next input position; worker generation |
| KV/index state | Scoped keys/values and mutation/tombstone revisions; namespace revision for coarse predicate tracking |
| Receipts | Stable resource/lineage/operation/key; canonical input digest; pinned execution identity; saved result and expiry |
| Jobs | Kind; owner/capability scope; pinned inputs/config; state, retries, generation, progress/output roots and safe error |
| Principals/credentials/grants | Current and issued rights, ownership, expiry, revocation and revisions |
| Platform config | Creation rules, hooks, app bindings/domains, approved function installations and secret references |
| Usage ledger | Scoped reservations/charges for storage, invocation and served bytes; durable settlement identity |

Use the same root/lease machinery for uploads, readers, snapshots, app assets, transfers and jobs. Source-range protection additionally blocks logical trim. A lease protects lifetime, not authority. Keep typed purpose-specific constraints; shared machinery does not imply arbitrary public access to internal tables.

Persist positions/revisions as nonnegative signed 64-bit integers with checked increments. Tail may reach `i64::MAX`; the last appendable position is `i64::MAX - 1`. Never order records by wall-clock time.

## Command transaction

Authenticate and perform bounded preflight/pipeline evaluation outside a write transaction. In the short commit transaction recheck lifecycle, complete read dependencies, config/policy revisions, quotas, required object durability/link rights and receipt uniqueness. A retained append inserts at tail, establishes roots, advances tail/segment summaries and saves the receipt atomically. Notify only after commit.

One command appends zero or one record to one stream. The supported coupled command publishes one reference and one truthful record atomically. Built-in KV additionally validates conditions and updates state/checkpoint in that same transaction. Private consumer state and checkpoint updates in the main database use the same coordinator; they are not arbitrary user-table writes. An optional derived sidecar commits its own state/checkpoint locally and recovers by idempotent replay, not by a cross-file WAL transaction. [Functions](functions-design.md) uses these commands, not another transaction engine.

A matching authorized receipt bypasses reexecution, not current authentication. Concurrent matching requests serialize on receipt identity. A lost response may mean a committed operation; retry resolves that only within the advertised receipt window. Receipts do not pin original records.

## Logical segmentation and retention planning

Initial segment target: 8 MiB payload or 10,000 records. Seal/split at a required cutoff. Every segment is a contiguous interval `[start,end)`. Age uses server acceptance timestamps; an age-eligible prefix contains only expired records. Clock rollback cannot cause an unexpired earlier record to be skipped. Byte retention chooses the shortest old prefix meeting the logical retained-byte target. Summaries accelerate planning; they do not authorize trimming extra records merely to match a segment.

Retention limits are targets subject to source leases and recovery safety, not a bound on total physical storage. Snapshot/ref/pin/dependency bytes are separately accounted. A stalled requirement may exceed the target. Under disk pressure reject writes visibly before discarding promised state.

### SQLite layout and physical costs

The baseline is one immutable SQLite row per retained record, keyed by `(stream_id, position)` in a `WITHOUT ROWID` B-tree; the current migration permits up to 1 MiB of inline payload. Ordered reads are key-range scans and a new position lands near the end of its stream's range. This is not an append-only file or a constant-time guarantee: interleaved streams, page splits, large-value overflow pages, the single WAL writer and commit synchronization affect cost. The row, tail, record roots, receipt and segment summary must commit together. Large application data should use an explicit linked object, not an implicit promotion of record bytes. [SQLite file format](https://www.sqlite.org/fileformat.html), [`WITHOUT ROWID`](https://www.sqlite.org/withoutrowid.html), [WAL](https://www.sqlite.org/wal.html).

Logical segments are **internal summaries**, not packed rows, physical log files or public replay boundaries. They can accelerate cutoff planning and counts; they do not make deletion of many individual rows one physical operation. A segment can be skipped for age retention only when all its records are eligible, even with clock rollback/out-of-order acceptance timestamps. The 8 MiB/10,000-record target and summary schema are defaults to validate, not throughput claims.

Prefix trim removes rows and their object-root associations in a bounded atomic cutoff step. Freed SQLite pages are normally reused via its freelist, while the database file need not shrink; partially occupied B-tree pages may remain. No `auto_vacuum` or `VACUUM` policy is selected. Long read transactions can prevent WAL checkpoints from completing: finish database reads before network sends, object streaming, guest execution and subscription waits. Observe database page/freelist counts, WAL size/checkpoint progress, block files, temporary work and free disk separately. Logical retained-byte limits do not cap physical disk usage. [SQLite auto-vacuum/freelist](https://www.sqlite.org/pragma.html#pragma_auto_vacuum), [WAL checkpointing](https://www.sqlite.org/wal.html).

A single growing SQLite BLOB per segment is not an assumed optimization: incremental BLOB I/O cannot resize it, so appending requires a different update/active-tail scheme. Immutable packed segments, rowid plus index, or physical logs require measured benefit and a new recovery/transaction design. Benchmark the baseline under interleaved streams, small/maximum records, prefix trims and active readers; record p95/p99 append latency, trim duration, WAL growth, checkpoint delay, page reuse and reopen correctness before choosing a different layout. [SQLite incremental BLOB I/O](https://www.sqlite.org/c3ref/blob_open.html).

### Data lifetime across components

| Data | Authority/lifetime | Consequence |
| --- | --- | --- |
| Retained record bytes | SQLite row until head trim; positions never renumber/reuse. | Short, bounded replay reads; delete rows and their object links atomically. Receipts may outlive rows. |
| Record/metadata links | SQLite roots while owner exists. | Payload bytes do not imply links; removing one root does not remove shared blocks. Acquire reader protection before releasing the database view. |
| Bytes, maps, directories, app assets | Immutable blocks reached via typed edges from roots or live leases. | Finalize before publication. A range read/asset response protects blocks through delivery without holding a long SQLite read transaction. |
| Snapshots and recovery anchors | SQLite descriptors, acceptances and roots. | Trim cannot discard required recovery coverage; accepted roots/dependencies survive record deletion. Encrypted dependencies remain declared. |
| KV/indexes and consumer state | SQLite materialization fenced by stream position. | Synchronous state commits with append; asynchronous lag is explicit and missing history is never empty state. |
| Receipts, jobs and usage ledgers | Separate bounded SQLite operational state. | Stream trim does not erase retry or charge identities; external effects and physical cleanup are separate. |
| Live/media traffic | No retained row or permanent root from publication alone. | Queue/transport limits differ from retention; recording/sharing persists via explicit roots. |

Logical ownership quotas and physically allocated SQLite/WAL/block/temp bytes are distinct. Deduplication or successful logical trim does not promise immediate free disk space. See [objects](unified-design.md), [protocol](protocol.md) and [tests](conformance.md).

## Safe snapshot-and-trim algorithm

Let current head be H and proposed cutoff P, with `H <= P <= tail`. A recovery requirement is stream configuration, optionally attached to a server snapshot producer, not a new storage engine. An external producer uses the [client snapshot contract](external-snapshots.md).

1. Serialize trim planning per stream. Capture config/lifecycle/requirement revisions and establish bounded source/output leases. Source leases held by other admitted work constrain the cutoff. Appends beyond P may continue.
2. For every requirement select an accepted compatible anchor Q with `P <= Q <= tail`, or, for a server-managed producer lacking such an anchor, plan an advance to P. To advance, choose a seed at q <= P with complete protected `[q,P)`; without a seed require genesis history. A seed below head with a gap is unusable. External requirements lacking coverage stall or lower the cutoff; the server cannot compute encrypted state on their behalf.
3. Run each necessary server producer outside the transaction over exactly `[q,P)`. Inputs are the compatible seed and pinned semantic config, not an unverified live materialization. Bound work and finalize output objects/dependencies under leases.
4. In one short SQLite transaction recheck head, lifecycle, complete requirement/policy set, acceptance and worker generations, source/output leases and durable root closure. Each requirement must have a usable accepted anchor at or beyond P with contiguous retained suffix to current tail. Insert new snapshots/acceptances/roots, remove record roots and rows `<P`, advance head to P and update summaries atomically. Any failed check leaves the old head intact.
5. Release job protection. Unreachable blocks become physical-collection candidates; collection is a separate maintenance operation, not required for logical trim success.

Bound each cutoff step so transactions remain short. Existing anchors need not be regenerated just to trim to an earlier position. A consumer restoring an anchor at Q > head starts replay at Q; it must not replay earlier retained records into that state.

With no recovery requirements, ordinary retention can trim under the same lifecycle/revision/source-lease checks. Attaching a requirement after history disappeared requires a compatible accepted seed plus available suffix, or explicit failure. Never treat missing history as empty state.

## Snapshot compatibility and lifetime

Snapshots are immutable; multiple types, boundaries and provenances coexist. Format version and semantic-config compatibility are separate from producer implementation version. Type equality alone is insufficient. Descriptors carry client or adapter provenance without pretending a client ran a server adapter.

Publishing a snapshot establishes a root; it does not accept recovery correctness. Acceptance uses a separate authorized policy decision. Server producers can publish/accept under their approved requirement. External opaque state is a trusted assertion, not a server-verified replay proof. Ad-hoc snapshots need not satisfy all requirements but use the same durability and protection rules.

Protect at least one selected usable anchor for every current requirement. Reject deletion of a protected anchor or its dependencies. Default cleanup keeps the latest two managed snapshots per requirement and explicitly retained ad-hoc snapshots; quotas and expiry of nonprotected roots remain explicit. Removing a requirement needs config-write authority and acknowledgement of the lost guarantee. A policy/format change cannot silently invalidate the last anchor after history is gone.

Typed object nodes declare direct required edges once. Snapshot roots traverse that graph; do not flatten and duplicate an entire directory closure per snapshot. Opaque payloads must explicitly declare dependencies hidden in their bytes, including previous incremental objects. The server checks declared closure and rejects malformed typed graphs; it cannot discover undeclared encrypted references. Retaining an old snapshot does not reconstruct an arbitrary later boundary without a contiguous suffix.

## Block finalization and graph collection

1. Stream bounded uploads through the canonical chunker into server-generated temporary paths on the block-store filesystem. Reserve quota; verify cryptographic hashes, sizes and typed structure.
2. Synchronize each block, install atomically at its internal hash-derived location and synchronize directories as required by the platform.
3. Register durable blocks/edges and upload/job protection before publishing a descriptor/root. Full required closure must be validated and protected. Interrupted work may leave conservative orphans, never a successful dangling root.
4. Initial graph GC enters maintenance: pause/drain graph mutations and new root/lease acquisition, preserve admitted reader protection, mark from durable roots and live leases, then sweep only unreachable blocks. Do not treat “no direct root” as “unreachable”: a child can be required through many shared parents.
5. Mark candidates deleting, unlink/synchronize, then remove catalog entries. Interrupted deletion is reconciled on restart. Reupload/link cannot succeed against a path scheduled for deletion; maintenance admission serializes it. Online GC requires its own proven barrier/epoch protocol.

Startup reconciles deleting entries, temporary files, conservative orphan grace periods and expired jobs/leases. A block is never removed merely because an in-memory cache is empty. A crash may leak storage until reconciliation; it may not lose an acknowledged root.

Roots include references, retained record/metadata links, snapshots, app/function artifacts retained by active deployments or the bounded superseded-frontend window, checkpoints, pins and admitted work leases. App promotion reserves the previous frontend's protection before channel CAS; expiry removes that logical availability even if physical GC has not yet run. Zero-retention publication creates no permanent root. A consumer merely observing bytes does not retain them automatically. Optional commit history follows explicit history retention, distinct from required content edges.

## Durable work and external effects

Snapshot generation, rebuilds, object composition, derivative processing and function work use one durable job lifecycle: queued/running/retry-wait/succeeded/failed/cancelled, bounded attempts, lease generations, current authority checks and protected inputs/outputs. User-facing domain states such as recording/finalizing are application state, not a second scheduler.

An outbox is the durable job kind for external delivery. Commit its intent with local state/checkpoint; dispatch afterward with stable effect identity. Send-before-ack crashes may duplicate delivery, so downstream idempotency remains necessary. Rebuild cannot enqueue effects. Cancellation fences future publication but cannot recall committed effects. Full sandbox egress details are in [Functions](functions-design.md).

## Deletion, migrations and backup

Deletion tombstones identity, removes the live name, fences workers and closes subscriptions before bounded cleanup. Recreating a name produces a new ID, never inherited grants/cursors/receipts.

Migrations run under exclusive startup coordination before readiness. Refuse foreign/newer schemas and silent downgrades. Back up before destructive upgrades; no automatic conversion of another deployment.

Initial backup enters maintenance, drains mutations/jobs, stops collection, uses SQLite's supported backup mechanism and copies the complete required block closure, retained history, config and necessary key material into a checksummed manifest. Keep mutations paused until complete. Restore into a fresh directory; verify closure, positions, revisions, checkpoints and revocations before traffic. Never copy only the main DB file while an active WAL may hold commits. Secret backups require operator-controlled access. Backups complement, not replace, snapshot retention.

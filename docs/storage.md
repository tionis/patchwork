# Storage, retention and backup

One SQLite database owns all mutable authoritative state: the control plane, stream records, keyspaces, document chunks and change sets. Large immutable content (later, the blob store) lives in local block files that SQLite catalogs. There is no second authoritative database. [Design](design.md) defines the kinds; this page defines how they persist.

## SQLite configuration

WAL, `synchronous=FULL`, foreign keys on every connection, bounded busy handling, bounded write admission and short transactions. SQLite has one WAL writer; long readers can delay checkpoints, so finish database reads before any network send, subscription wait or long computation. The deployment needs a supported local filesystem. [SQLite WAL](https://www.sqlite.org/wal.html), [synchronous](https://www.sqlite.org/pragma.html#pragma_synchronous).

An acknowledgement means the configured durable commit completed. Graceful reopen, hard-kill recovery and hardware power loss are distinct claims and need distinct evidence.

Positions and revisions are non-negative signed 64-bit integers with checked increments. The tail may reach `i64::MAX`; the last appendable position is `i64::MAX - 1`. Records are never ordered by wall-clock time.

## Responsibilities

| State | Contents |
| --- | --- |
| Streams and records | Stable ID; live name; config and metadata revisions; head and tail; immutable positioned bytes; logical byte and time summaries |
| Keyspaces (planned) | Key, value, content type, revision, expiry, last access; per-namespace byte and entry counters |
| Documents (planned) | Per-document incremental change chunks, compacted base, heads, size counters |
| Change sets (planned) | Per-database site ID, version and encoded changes, if the cr-sqlite spike succeeds |
| Blocks and objects (later) | Block hash, size and lifecycle; raw-digest index; roots and references |
| Principals, credentials, grants, links | Rights, ownership, expiry, revocation, hashed link secrets, revisions |
| Receipts | Resource, principal or grant, operation, key, canonical input digest, saved result, expiry |
| Hooks and platform config | Creation rules, hook definitions, provider verifiers |
| Usage counters | Per-tenant storage, request and connection charges |

## Command transaction

Authenticate and run bounded preflight and pipeline work outside a write transaction. In the short commit transaction, recheck lifecycle, revisions, quotas and receipt uniqueness. A retained append inserts at the tail, advances the tail and segment summary, and saves the receipt atomically. Notify only after commit. One command appends zero or one record to one stream.

A matching authorized receipt bypasses re-execution, not current authentication. Concurrent matching requests serialize on receipt identity. Receipts do not pin records.

## Stream layout and retention

The baseline is one immutable SQLite row per record, keyed by `(stream_id, position)` in a `WITHOUT ROWID` table. Ordered reads are key-range scans and new positions land near the end of the stream's range. This is not an append-only file, and interleaved streams, page splits, overflow pages, the single writer and commit synchronization all affect cost. Large data should be an explicit linked object, not an implicit promotion of a record. [File format](https://www.sqlite.org/fileformat.html), [`WITHOUT ROWID`](https://www.sqlite.org/withoutrowid.html).

Logical segments are internal summaries (target 8 MiB payload or 10,000 records), not packed rows or public replay boundaries. They speed retention planning. A segment can be skipped for age retention only when all its records are eligible, even with clock rollback.

Retention is `infinite`, `bounded` (age, bytes or both) or `none`. Age uses server acceptance timestamps and an age-eligible prefix contains only expired records. Byte retention removes the shortest old prefix that meets the target. Retention limits are targets for logical bytes, not a bound on physical disk. Trim removes rows in bounded steps and never renumbers. Freed pages return to SQLite's freelist and the file does not shrink; no `auto_vacuum` or `VACUUM` policy is selected. Under disk pressure, reject writes visibly instead of discarding data.

Mode `none` has no durable position; it exposes a process epoch and increasing sequence for gap detection only.

Planned additions: keyed compaction (keep the newest record per key) and absence detection, defined in [design](design.md#stream).

### Measurements owed

Before choosing another layout, record p95/p99 append latency, trim duration, WAL growth, checkpoint delay, page reuse and reopen correctness under interleaved streams, small and maximum records, prefix trims and active readers. `examples/` should hold the benchmark harness. No throughput figure is a product promise.

## Keyspaces and documents (planned)

Keyspace and document storage follow the same transaction rules. Cache-mode keyspaces evict by least-recent access under a per-namespace byte cap, in bounded batches outside the request path. Documents append incremental chunks and compact into a new base in one transaction, never leaving a reader with a partial view. Both count logical bytes per tenant. Details are settled with each kind's design, not here.

## Deletion, migrations and backup

Deletion tombstones identity, removes the live name, fences workers and closes subscriptions before bounded cleanup. Recreating a name produces a new ID, never inherited grants, cursors or receipts.

Migrations run under exclusive startup coordination before readiness. Refuse foreign or newer schemas and silent downgrades. Until the first release, schema changes edit migration 0001 in place and development directories are recreated (D29).

Backup is online: SQLite's backup API produces a consistent standalone database, and a checksummed manifest binds instance identity, origin and counts. Restore goes into a fresh directory and verifies the manifest, identity, positions and revocations before traffic. Never copy only the main file while a WAL may hold commits. When the blob store exists, the manifest also covers the block closure while sweeps are excluded. Backups need operator-controlled storage because they contain credential material.

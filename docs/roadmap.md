# Roadmap

Rewritten 2026-09-29 from [use cases](use-cases.md) and [design](design.md). Status words: **done** means implemented and verified against the acceptance column; **partial** is an explicit subset; **todo** is unavailable. A task is done only with executed evidence, and a milestone is not done because its tasks are. Tasks appended later never renumber existing IDs. Ordering follows your priority: Vulcan is in active use, so it goes first, and the kinds other projects can wait on come after it.

## M0. Baseline (built)

| ID | Status | Delivered | Missing evidence |
| --- | --- | --- | --- |
| B-01 | partial | SSH login, Biscuit credentials, offline attenuation, principal and policy administration, revocation, login admission | Longer fuzz campaign, deployment review (G-AUTH, G-SSH) |
| B-02 | partial | Retained and live streams, idempotent append, pipelines, bounded retention, creation rules, follow, live, watch | Append and trim benchmark, fault matrix (G-DURABILITY, G-LIMITS) |
| B-03 | partial | Stream-derived KV with conditional writes | Superseded by M3; no further work |
| B-04 | partial | HMAC-signed GitHub webhook ingress with receipts | G-PROVIDER fixtures from official documentation |
| B-05 | partial | Online SQLite backup and identity-preserving restore | Fault injection, large-data drill |

## M1. Vulcan wake-up relay in production

Use case U1. Exit: Vulcan's daemon runs against a public Patchwork instance for at least one week, and the older relay is retired.

| ID | Status | Deliverable | Acceptance |
| --- | --- | --- | --- |
| V-01 | todo | URL-transport credentials: `url_transport` mint flag with scope restrictions, `?token=` acceptance, query-string redaction, `Referrer-Policy` and `Cache-Control` headers, list, revoke and rotate through API and CLI (G-URLCRED) | A session token or administrative credential in a URL is refused; a valid narrow credential works; a revoked or wrong token gives the same 401; query strings never appear in logs; a token in both places is rejected |
| V-02 | todo | Publish and subscribe on the ordinary stream routes with URL-transport credentials; long-poll delivery `GET /v1/streams/{id}/wait` | A publish reaches every connected subscriber once; an idle timeout returns 408, never 2xx (D34); a publish credential cannot read and a subscribe credential cannot publish |
| V-03 | todo | Provider verifiers attach to publish credentials; existing hooks migrate onto them | Signed and unsigned senders reach the same stream; original-byte HMAC still enforced where configured |
| V-04 | todo | Idle-connection cost: per-stream subscriber cap, no thread per subscriber, measured at 1,000 and 10,000 idle long-polls | Memory and CPU per idle subscriber reported on named hardware; cap enforced; slow subscribers never grow memory |
| V-05 | todo | Deployment: container and reverse-proxy runbook with HTTP/2, scheduled backup and a restore drill, readiness and basic metrics, redacted logs, CI passing remotely | A fresh host follows the runbook; backup restores; no secret in logs |
| V-06 | todo | Vulcan integration: run the Vulcan daemon against the instance; use plain stream URLs with `?token=` (no compatibility route; update the example URLs in the Vulcan spec) | Forge webhook triggers a sync in Vulcan end to end; rotation via a new advertisement works; reconnect gap is covered by Vulcan's reconciliation |

## M2. Script toolkit

Use case U3, plus housekeeping owed from M0.

| ID | Status | Deliverable | Acceptance |
| --- | --- | --- | --- |
| S-01 | todo | Append and trim benchmark harness on the SQLite row layout, results recorded | p95 and p99 append, trim time, WAL growth, checkpoint delay on named hardware |
| S-02 | todo | OpenAPI descriptions for KV, attachments, hooks, URL-transport credentials and long-poll | Contract validates and matches routes |
| S-03 | todo | Latest-per-key reads and keyed compaction for streams | Newest record per key without a full replay; compaction never loses the newest per key |
| S-04 | todo | Absence detection: expected-interval rule that appends to an alert stream | A missing backup report fires once and recovers on the next record |
| S-05 | todo | Named server-side cursors | Stateless script resumes at its saved position; deletion and recreation do not inherit it |
| S-06 | todo | CLI ergonomics for pipes (`append` from stdin, `follow` to stdout, exit codes) | Documented shell examples run in a test |
| S-07 | todo | Per-tenant usage counters and quotas, readable by the operator | Counters survive restart and are enforced at admission |

## M3. Keyspaces

Use cases U4, U8, U12. Replaces stream KV (D35).

| ID | Status | Deliverable | Acceptance |
| --- | --- | --- | --- |
| K-01 | todo | Keyspace resource: get, put with `If-Match` and `If-None-Match`, delete, batch get, prefix list, increment | Concurrent conditional writes have one winner; revisions never repeat |
| K-02 | todo | Cache mode: TTL, byte cap, least-recently-used eviction in bounded background batches | Cap holds under load; eviction never blocks a request; hit counters batched |
| K-03 | todo | Record mode: put-if-absent with TTL for locks and leader election | Two contenders never both hold a lock; expiry releases it |
| K-04 | todo | Public read binding, optional redirect answer, batched click counters | Anonymous GET answers or redirects; creating and editing needs credentials; counters do not write per click |
| K-05 | todo | Migrate `embedding-proxy` to a keyspace; remove stream KV | Existing cache clients unchanged; spend limits are usage counters |

## M4. Documents (Automerge)

Use case U2. Start with a spike (G-AUTOMERGE); the tasks after it assume it passes.

| ID | Status | Deliverable | Acceptance |
| --- | --- | --- | --- |
| A-01 | todo | Spike: `automerge` crate and existing Rust Automerge Repo implementations against a pinned JS client; report on size, CPU and API fit | Written decision with fixtures; fails closed if interoperability is partial |
| A-02 | todo | Document storage: chunks plus compacted base in SQLite | Crash during compaction leaves a readable document |
| A-03 | todo | Automerge Repo WebSocket endpoint with credential in the first message and read-only enforcement | A stock client syncs; a read-only peer cannot change the document |
| A-04 | todo | Ephemeral relay for presence, and HTTP export and import | Presence never stored; export equals synced state |
| A-05 | todo | Optional server-side schema validation | An invalid merged state is rejected and reported to the sender only |
| A-06 | todo | Migrate the recipe site off S2; evaluate Smart Todos migration | Offline edits converge; compaction needs no client cooperation |

## M5. Database (cr-sqlite)

Use case U5. Gate G-CRSQL decides whether this ships.

| ID | Status | Deliverable | Acceptance |
| --- | --- | --- | --- |
| D-01 | todo | Spike: extension compatibility with the SQLite version in use, maintenance status, two-peer offline convergence, change-set size, server compaction, crash recovery | Go or no-go report with numbers |
| D-02 | todo | If go: change-set relay and archive, site registration, schema handling | Peers converge through the server; a stale peer catches up |
| D-03 | todo | If no-go: keyed last-writer-wins map with hybrid logical clocks as a keyspace mode | Two offline writers converge deterministically |

## M6. Blob store

Use cases U6, U7, U13. Design detail is written when M4 is under way.

| ID | Status | Deliverable | Acceptance |
| --- | --- | --- | --- |
| O-01 | todo | Content-defined chunking spike and chunk profile with canonical fixtures (G-BLOB) | Boundaries independent of HTTP framing; sparse-edit reuse measured |
| O-02 | todo | Chunk store, raw SHA-256 index, upload, range read, named references | Exact bytes and ranges; interrupted upload leaves nothing visible |
| O-03 | todo | Share links with expiry and byte limits (URL-transport credentials) | Concurrent final use never oversubscribes |
| O-04 | todo | Git LFS adapter: batch, verify, locks | Stock `git lfs` push and pull against the server |
| O-05 | todo | Garbage collection with race tests | No reachable block removed under concurrent publication |
| O-06 | later | Trees (prolly maps, directories), diff, client-assisted transfer | Decided after O-05 |

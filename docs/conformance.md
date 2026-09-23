# Acceptance, failure injection, and benchmark plan

This suite covers core protocol, processing, recovery and authority. [Object cases](object-conformance.md), [function cases](function-conformance.md), [client snapshot cases](external-snapshots.md) and [app cases](reference-apps.md) cover their specialized contracts. All use the same typed object, command and recovery model.

This is a test specification, not a claim that tests have run. Implement fixtures and executable tests alongside the server. Invariant IDs refer to [architecture](architecture.md).

## Harness

Use isolated temporary data directories, deterministic clocks and randomized operation sequences. Launch the server as a subprocess for crash tests. Inject failures at named transaction/block checkpoints; terminate with a hard process kill and reopen the same data directory. Use distinct credentials for admin, appender, history reader, watcher, KV reader, and unrelated principal. Never use only an administrator in API conformance tests.

Each test records initial state, actions, expected HTTP/status/events, and durable state after restart. A process-kill test does not establish arbitrary hardware power-loss behavior; filesystem fault injection and documented storage assumptions supplement it.

## Stream and protocol cases

| ID | Given / action | Required result |
| --- | --- | --- |
| P01 | Empty retained stream; append A then B | Positions 0,1; head 0/tail 2; exact byte replay |
| P02 | Concurrent appends | Unique contiguous positions; order equals commit serialization |
| P03 | Reject, drop, then append | Only append allocates position; distinct receipts |
| P04 | Ack received; hard-kill server | Record and tail survive restart (I01) |
| P05 | Kill after commit before acknowledgement; retry same key | One record; saved receipt returned |
| P06 | Same key, different bytes/content type/references | 409; no second append |
| P07 | Retry after original record trimmed but key unexpired | Saved receipt, no resurrection |
| P08 | Replay from below head / above tail / exactly tail | 410 / 409 / empty page |
| P09 | Binary bytes, zero-byte payload, maximum record | Byte-exact round trip; valid zero-byte event |
| P10 | Payload or transform exceeds limit | 413 or documented pipeline-limit error; no append |
| P11 | Two metadata CAS updates from same revision | One succeeds; one 412; roots match winner |
| P12 | Delete and recreate identical name | New ID; old cursor/token remains invalid |
| P13 | Zero-retention publish with no readers; restart | 202; no record replay; epoch changes |
| P14 | Auto-create races with differing templates/config | One winner; loser revalidates; no mixed config |
| P15 | Auto-create request drops/rejects | No empty stream left behind |
| P16 | Encoded separators, dot paths, malformed JSON, overflow positions | Reject consistently before lookup/authorization |
| P17 | Mutation canceled after submission | Either absent or committed; never partially applied; retry resolves when keyed |
| P18 | Idempotent retry after ACL removal | Denied despite saved receipt |
| P19 | Raw append while config changes during filter execution | Reevaluate or conflict; stale pipeline never commits |
| P20 | Read page budget below next record size | Return that single valid record; pagination advances |
| P21 | Matching retry after pipeline configuration changes | Current auth/signature still checked; original receipt returned without rerunning filters |

## Filters, consumers, and KV

| ID | Scenario | Required result |
| --- | --- | --- |
| E01 | Filter transforms payload; later validator checks transformed bytes | Only final bytes stored; invalid final candidate rejected |
| E02 | Earlier transform changes request bytes used by signature verifier | Verifier still receives immutable original context |
| E03 | Silent-drop configured on a failing filter | Successful ingress response, no append, internal failure metric |
| E04 | Same setting with failed authentication/validator/storage | Error; setting cannot suppress those failures |
| E05 | Generic append attempts invalid KV event | Rejected by mandatory validator (I03) |
| E06 | Concurrent KV CAS from revision R | Exactly one succeeds; other 412; one accepted mutation |
| E07 | Raw KV append races KV adapter CAS | Conditions checked in common transaction; no stale cache decision |
| E08 | Crash between KV state and checkpoint statements | Rollback or all committed; never divergent (I06) |
| E09 | Rebuild from snapshot plus suffix | Byte-equivalent values/revisions/tombstones to uninterrupted run |
| E10 | Slow/failing async consumer | Visible stalled checkpoint; no skipped record |
| E11 | Consumer behind new head | Explicit restore/recovery-required; no fabricated empty state |
| E12 | KV write filters change semantic key/condition | Reject; adapter cannot claim requested mutation succeeded |
| E13 | Delete/recreate key then retry old revision | Old condition fails; no ABA |
| E14 | Rebuild a materializer | No external HTTP requests or command execution |
| E15 | Retry committed conditional KV write with same key/digest after state changes | Current auth required; receipt returned before conditions reexecute; changed input conflicts |

## Snapshots and GC

| ID | Scenario | Required result |
| --- | --- | --- |
| G01 | Adapters A/B with seeds at different Q; trim to P | When neither already has accepted coverage, both advance exactly to P; head changes only after both succeed |
| G02 | A succeeds; B fails/timeouts | Head/record roots unchanged; orphan output eventually collected |
| G03 | Snapshot at P where P is in a logical segment | Correct `[0,P)` state; suffix starts at P |
| G04 | No compatible seed and head > 0 | Explicit source-missing failure; no trim |
| G05 | Seed Q < head with absent `[Q,head)` | Reject even if descriptor exists |
| G06 | Change producer, recovery requirement or acceptance policy during computation | Revision conflict prevents stale trim |
| G07 | Append while snapshot computes P | Append survives at >= P and is not included in snapshot |
| G08 | Kill before outputs durable | Head unchanged |
| G09 | Kill after outputs durable but before transaction | Head unchanged; output leased/orphan-safe |
| G10 | Kill during snapshot/head/record-root transaction | Entire old or entire new state, never mixed |
| G11 | Kill after trim commit before physical blob cleanup | New recovery anchors usable; leaked storage acceptable until GC |
| G12 | Snapshot references typed subtree and opaque incremental dependency | Required graph closure retained without per-owner flattening; unrelated blocks collectable |
| G13 | Delete last recovery-protected snapshot | 409; restore guarantee preserved |
| G14 | Different types/versions at same P | Coexist; incompatible adapter cannot silently consume wrong type |
| G15 | Plain stream with no recovery requirements | Eligible prefix trims subject to active source leases |
| G16 | Long-stalled adapter and disk pressure | Writes rejected visibly before unsafe loss |
| G17 | Expired GC lease / crashed worker | No stale job can publish/trim after lease invalidation |
| G18 | Stream deleted during snapshot job | Job cannot publish into deleted/recreated resource |

## SQLite layout and cross-component lifetime cases

| ID | Scenario | Required result |
| --- | --- | --- |
| G19 | Interleaved streams append and trim a prefix spanning/inside logical segments; reopen | Positions remain contiguous from the new head, exact surviving payloads/links remain, summaries equal rows, and no segment boundary changes public replay behavior. |
| G20 | Sustained append/trim with a long-lived reader and forced checkpoints | Report append/trim latency, WAL/checkpoint delay, page/freelist counts and actual file sizes; no claimed physical disk cap; short-read implementation permits eventual checkpoint completion. |
| G21 | Range-read an object through an expiring record link while trim and graph GC run | Either authorized protected bytes finish or admission fails before delivery; no missing block after acknowledged read admission and no SQLite read transaction held across network delivery. |

## Object/block races and recovery

| ID | Scenario | Required result |
| --- | --- | --- |
| B01 | Kill during temp upload | No visible half-blob; stale temp cleanup |
| B02 | Kill after file durability before catalog entry | Orphan cleanup; no dangling durable reference |
| B03 | Link a root whose child is reachable only through a shared subtree during collection | Maintenance admission serializes outcome; indirect reachability preserved, or new link fails/retries |
| B04 | Upload an object sharing a block marked `deleting` | Wait/retry/refinalize; never success to disappearing block |
| B05 | Expire upload lease with no other graph roots | Unreachable closure becomes eligible for collection |
| B06 | Zero-retention event references blob | Publication does not create permanent root |
| B07 | Guess hash uploaded by another principal | Download/link denied; no existence oracle via upload response |
| B08 | Metadata CAS loses after uploading blob | Losing value creates no durable metadata root |
| B09 | Byte range GET | Correct 206/416 and authorization on HEAD/GET |
| B10 | Filesystem ENOSPC at each finalize stage | No receipt implying durable bytes; catalog remains consistent |

## Authorization and subscription cases

| ID | Scenario | Required result |
| --- | --- | --- |
| A01 | Attenuated token asserts admin/principal/resource/time facts | Cannot widen authority or forge trusted ambient facts |
| A02 | Append-only token adds read check/right | Read still denied |
| A03 | Mint API called with attenuated/API token | Denied; cannot exchange away restrictions |
| A04 | Server adds broader ACL after token issuance | Issuance ceiling still limits old token |
| A05 | Server removes right/disables principal/revokes root | New requests denied; children invalidated |
| A06 | Wrong instance, invalid signature, expired SSH challenge, replay | Authentication fails; no token issued |
| A07 | Prefix `foo/` versus `foobar/x`, encoded names | No prefix bypass |
| A08 | Watch-only / KV-read-only / snapshot-list-only tokens | No raw records, unauthorized metadata, or blob bytes |
| A09 | Multi-stream watch with one unauthorized stream | Entire explicit request denied |
| A10 | Mixed resources in token-check environment | One allowed item cannot satisfy checks for another |
| A11 | Watch registration concurrent with append | Ready/resync/read pattern cannot permanently miss change |
| A12 | Revoke during follow/watch/download | Stop within five seconds; no new authorized batches after recheck |
| A13 | SSE queue exceeds byte or count bound | Bounded memory; lag closure; replay or explicit loss |
| A14 | Facts/iterations/token bytes/blocks exceed budget | Bounded fail-closed result, service remains responsive |
| A15 | Forged hook signature with matching delivery ID | Rejected before dedup/append success can be replayed |
| A16 | Permissive policy precedes explicit deny in supplied config | Validation/compiler enforces documented deny semantics |
| A17 | Policy revision changes while mutation prepares | Commit recheck prevents stale authorized write |
| A18 | Token body/signature/secret in error and logs | Redaction tests detect no secret leakage |

## Model/property tests

Model append/trim/snapshot/delete with a small in-memory reference state. Generate operation sequences and check I01–I12 after every restart. For each built-in snapshot adapter, property-test `fold(seed@Q, records[Q,P)) == full_fold(records[0,P))` when complete history is available. Restore output and compare semantic state, not nondeterministic file bytes.

Generate attenuation chains and sampled operations; each child allow-set must be a subset of its parent's for the same server policy/time. Mutation of untrusted block facts must never change a deny to allow. Fuzz parsers, HTTP framing, key/base64 decoding, snapshot restore, and token verification.

## End-to-end release exercises

1. Fresh install → SSH bootstrap/login → scoped token → curl append → CLI follow → UI inspection.
2. Signed webhook → transform/drop → zero-retention wakeup → no raw payload exposure.
3. KV write/CAS → snapshot → trim → kill → rebuild → same values and revisions.
4. Backup → restore in isolated instance data directory → verify state/revocations; explicitly handle intended instance identity and hostname binding.
5. Revoke child lineage's root while following → access stops within bound.

## Performance evidence

Report named CPU, RAM, storage, filesystem, OS, Rust/build profile, SQLite configuration, and data sizes. Benchmark 0 B/1 KiB/64 KiB/1 MiB records; 1/16/128 concurrent producers; 1/100/1000 subscribers where feasible; authorization enabled; filter/validator on/off; KV CAS; snapshot rebuild at 100 MiB/1 GiB and a larger operator-relevant dataset. Measure commit p50/p95/p99, throughput, memory, writer-queue depth, WAL/checkpoint behavior, restore time, and disk overhead.

These are measurement scenarios, not guaranteed capacities. Run a bounded disk-pressure/slow-reader soak and verify stable memory. Stop adding microbenchmarks once a concrete bottleneck or acceptance risk is resolved. Publish results and recommended limits before calling the release ready.

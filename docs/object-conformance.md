# Object system conformance plan

All cases below are **specified, not implemented or run**. They supplement the P/A/B/E/G cases in [core conformance](conformance.md). Use isolated directories, deterministic fixture profiles and fault injection. See [unified design](unified-design.md) for the proposed semantics; O-01 defines logical fixtures; O-02 freezes byte encodings with real-library evidence before persistent-format implementation.

| ID | Scenario | Required result |
| --- | --- | --- |
| OBJ-01 | Build equivalent objects with different edit orders, streaming buffers and process restarts | Same root for the same logical object/profile; exact encoded fixture/hash match |
| OBJ-02 | Unsupported profile/version, duplicate fields, bad hash/type/length, cyclic or excessively deep imported graph | Bounded explicit failure; no published root or guessed partial success |
| OBJ-03 | Empty/binary/large upload; vary incoming HTTP chunk sizes | Exact bytes/raw digest; canonical CDC chunks independent of transport framing; bounded memory |
| OBJ-04 | Repeated objects, prefix insertion, middle edits, repeated equal chunks | Reuse measured; sequence and multiplicity preserved; no fixed-offset suffix-key rewrite |
| OBJ-05 | Range read across chunk/node boundaries and at EOF | Exact slice; correct zero-length/invalid-range handling; bounded node/chunk fetches |
| OBJ-06 | Compose/splice existing authorized ranges versus upload resulting full bytes | Same bytes and root for the same canonical profile; rechunk work measured; no uncomputed raw digest claim |
| OBJ-07 | Batch map mutations, conditional failure, point/range/prefix reads | Atomic new root or unchanged base; deterministic byte-key ordering; root-bound pagination |
| OBJ-08 | Map/directory diff over mostly shared trees | Exact changes relative to reference model, bounded pages and measured skipped subtrees |
| OBJ-09 | Nested directory copy/move/edit and conflicting overlapping batch | Reuse unchanged subtrees; reject ambiguity/collisions/self-descendant moves; old root still readable |
| OBJ-10 | UTF-8 names, dot components, encoded separators, Unicode/case collisions on export | No silent normalization/path escape; exact ordering; unsupported host export names fail visibly |
| OBJ-11 | Symlink inspection, cycles, absolute/escaping paths and excessive chains | Inert by default; explicit resolution bounded and confined to supplied root, never host filesystem |
| OBJ-12 | Commit retained while unpinned ancestors collected | Root directory remains complete; unavailable parent history explicit; explicitly retained ancestry survives |
| OBJ-13 | Publication CAS races including A -> B -> A | Exactly one expected-revision winner; stale revision fails even if root matches again |
| OBJ-14 | Publish reference plus one stream event; reject/drop pipeline; change auth/config before commit | All reference/record/root/receipt changes commit or none; event describes actual root; notifications follow commit |
| OBJ-15 | Lost publication response and same/different idempotency input | One committed publication for matching retry; conflict for changed request; current authorization still required |
| OBJ-16 | Guess root/chunk hash, cross-principal reuse, unauthorized diff/transfer | No bytes/link authority or global existence response; permitted root context/session required |
| OBJ-17 | Revoke credential during read/transfer/job; reuse old cursor or GC pin | Delivery/admission stops within existing bound; pin/cursor does not preserve permission |
| OBJ-18 | GC with shared roots, leases, in-flight readers and an attempted publication | All required content retained; maintenance admissions gated; expired unrooted content eventually reclaimed |
| OBJ-19 | Kill/ENOSPC at block finalization, catalog/root publication and physical deletion | Previously acknowledged roots complete after restart; no dangling published dependencies; orphan cleanup safe |
| OBJ-20 | Snapshot tree at P, mixed recovery requirements, trim, restart and rebuild | Existing G01–G18 invariants hold; root does not substitute for position/provenance; revisions/tombstones preserved |
| OBJ-21 | Transfer malformed/missing blocks, cancelled session and resume | Root invisible until validated/durable; partial content leased; root-scoped resume without unauthorized probes |
| OBJ-22 | Backup/restore with shared nodes, commit-history policy, grants and revocations | Byte/structure/revision equivalence; complete required closure; explicit instance binding; no restored authority widening |
| OBJ-23 | Huge batch, pathological tree, chunk flood, compressed expansion and slow client | Work/bytes/depth/memory quotas fail closed; no runaway recursion, allocation or unbounded transaction |
| OBJ-24 | Library/profile upgrade and old-object read/export | Declared compatibility path tested; unsupported format rejected; no silent root reinterpretation |

The O-02 spike measures OBJ-01/03–08 subsets with real libraries; it does not complete public protocol, authorization, crash or GC cases. Keep measured results separate from planned cases and distinguish graceful reopen, hard process kill and filesystem/power-loss evidence.

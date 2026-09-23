# Requirements, defaults and validation gates

## Product requirements

Stable IDs identify requirements, not their implementation status. See [roadmap](roadmap.md) for evidence and progress.

| ID | Requirement |
| --- | --- |
| C01 | Rust, single-node implementation |
| C02 | Built-ins establish working behavior; approved user code uses a gated shared execution subsystem |
| C03 | Filters can transform before append and can drop or reject |
| C04 | Retained acknowledgement covers processing and commit, not asynchronous consumer completion |
| C05 | Adapter write endpoints specify their additional consistency guarantees |
| C06 | Typed snapshots carry exact positions; multiple types and positions coexist |
| C07 | Snapshots and recovery requirements are per-stream, independent of consumers |
| C08 | Server snapshot adapters advance compatible seeds over removed history; every configured recovery requirement must be satisfied before trim |
| C09 | Configuration is server-owned, not Git-owned |
| C10 | Expressive permissions and offline attenuation to narrower authority |
| C11 | Biscuit must pass an executable authorization prototype before production adoption |
| C12 | One authoritative SQLite database per instance and local content-addressed blocks |
| C13 | Initial service includes built-in KV, hooks, CLI and operational UI |
| C14 | Compatibility is optional and cannot constrain the model |
| C15 | Content-defined chunking supports economical storage of similar byte objects |
| C16 | Efficient persistent ordered-map operations are public capabilities |
| C17 | Directory formats and operations compose with the object/stream system |
| C18 | Shared sandbox execution supports consumers, endpoints, webhooks and application-specific enforcement |
| C19 | Clients can publish snapshots, including encrypted state; recovery acceptance is distinct from publication |

## Selected defaults

These are the current plan. Changes require rationale, affected contract updates and tests, not a parallel hidden production mode.

| ID | Default | Rationale |
| --- | --- | --- |
| D01 | Half-open boundaries; snapshot P covers records `<P` | Replay starts at P |
| D02 | Every configured recovery requirement blocks trim beyond its accepted coverage | No silent loss when a server adapter fails or external client is offline |
| D03 | Inline SQLite records with logical segments; large data in a shared chunk/node store | One authoritative transaction domain |
| D04 | Explicit creation, prefix opt-in create-on-append, no create-on-read | Reads cannot allocate durable resources |
| D05 | Longest matching prefix selects a complete creation template | No dynamic inherited config |
| D06 | Stable resource IDs; no stream rename or live/retained mode switch initially | Clear identity and cursor lifecycle |
| D07 | A command appends zero or one record to one stream | No implicit batch/fanout transaction contract |
| D08 | Built-in KV materializes inside the append transaction | CAS remains correct with generic append |
| D09 | Consumers do not implicitly pin history | All-event processing requires infinite retention or explicit bounded source protection |
| D10 | Immutable issuance ceiling intersected with current server policy | Neither stale grants nor unexpected widening |
| D11 | Fresh unattenuated SSH session required for general server credential minting | Avoid attenuation laundering |
| D12 | API tokens cannot mint general credentials; offline narrowing remains available | Scoped browser/share exchanges use explicit non-widening admission, not general minting |
| D13 | Typed nodes declare direct required edges; opaque payloads declare otherwise hidden dependencies | One graph collector, no per-snapshot flattened typed closure |
| D14 | Protect selected recovery anchors; retain latest two managed snapshots per requirement and explicitly retained ad-hoc snapshots | Bounded automatic history with explicit lifetime policy |
| D15 | No generic query-string credentials | Dedicated hook/share redemption is separately controlled |
| D16 | New authorization changes apply on admission/commit; active delivery refresh at most five seconds | Bounded revocation behavior |
| D17 | Maintenance-mode backup and physical graph GC initially | Prove coherent roots before online optimization |
| D18 | SSE JSON/base64 follow; raw GET for exact bytes | Simple inspectable transport |
| D19 | Retained retry receipts last 24 hours by default; none for live publication | Explicit bounded idempotency |

## Validation gates

| Gate | Evidence required | Blocks |
| --- | --- | --- |
| G-REPO | Repository, schema and data-format safety | Changes to deployment/data assumptions |
| G-AUTH | Trusted origins, issuance ceilings, adversarial delegation, budgets and benchmarks | Production policy integration |
| G-SSH | SSHSIG and ssh-agent Ed25519 interoperability | SSH login |
| G-PROVIDER | Official provider contract and original-byte signature fixtures | Provider compatibility claims |
| G-DURABILITY | Commit/finalization/trim/restart fault injection and target filesystem assumptions | Durable release claims |
| G-LIMITS | Load, restore, slow-client and admission measurements | Capacity guidance |
| G-FORMAT / G-CDC / G-PROLLY | Canonical fixtures, bounded chunking, real-library map/sequence tests | Persistent object format adoption |
| G-GRAPH / G-OBJECT-AUTH | Reachability/lease races, link and root-scoped access tests | Collection and public objects |
| G-APP / G-SHARE | Browser isolation/deployments, safe redemption and atomic usage accounting | Hosted apps and sharing |
| G-FUNCTIONS / G-FUNCTION-TX / G-FUNCTION-AUTH / G-FUNCTION-RECOVERY | Isolation, host command contracts, authority and replay/effect tests | Untrusted execution and its profiles |
| G-RTC / G-MEDIA / G-CRDT | Protocol interoperability, lifecycle/limits and recovery fixtures | P2P, recording and Automerge integrations |

Detailed evidence lives in [objects](unified-design.md), [authorization](authorization.md), [Functions](functions-design.md), [apps](reference-apps.md) and their conformance plans. A gate is closed only with executed evidence for its scope; a library feature list is insufficient.

## Choices reserved for prototypes

- Freeze object encodings after the CDC/prolly spike; pin versions and licenses before adoption.
- Select one initial sandbox runtime/ABI and measured OS isolation profile. Do not ship multiple engines merely because multiple candidates were evaluated.
- Choose TURN integration, media topology/container profiles and Automerge versions from executable interoperability fixtures.
- Keep third-party Biscuit blocks, independently revocable offline child tokens and multi-service offline verification outside the initial authorization contract.
- Improve packing, query concurrency, online backup/GC and physical log layout only for measured needs.

Failure of a gate blocks its dependent capability, not unrelated implementation. Replacing Biscuit or changing a product requirement requires an explicit decision. No fixed throughput, deduplication ratio or arbitrary power-loss guarantee is assumed.

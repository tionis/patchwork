# Patchwork Functions: shared execution with explicit capabilities

Design revision 2026-09-23. Functions are the shared execution subsystem for approved custom code. Built-ins establish behavior; uploaded code requires the runtime, authority and recovery gates below. Runtime selection is an implementation gate, not a choice exposed to production before validation.

Read with [system overview](unified-design.md), [apps](reference-apps.md), [roadmap](roadmap.md) and [shared invariants](architecture.md). Functions compose existing objects, references and streams; they do not introduce a separate application database, transaction engine or scheduler.

## Function resources and deployment

A Function has a stable resource ID, owner/app binding, immutable code bundle root, runtime/ABI profile, entrypoint and invocation profile. Its approved deployment also binds configuration revision, resource capabilities, secret handles, limits and allowed trigger registrations. The bundle is a directory object containing code and locked dependencies/artifacts; imports resolve only within that validated bundle or the versioned host API. Uploading a directory does not install or execute it. No on-demand package download or runtime shell build occurs in a request.

A manifest requests capabilities; an authorized server installation creates the actual grants. Publishing changed code is sensitive because it can use the deployment's existing authority. Expanding bindings, invocation modes, secrets, outbound destinations or limits requires corresponding administrative/delegation permission, not just code-upload permission. Opaque code content IDs prove identity/integrity, not trustworthiness.

An App deployment is an immutable descriptor pinning frontend directory, routes, function artifacts/config and requested binding revisions. Its channel is a normal revisioned reference; promotion validates separately approved grants and installs a coherent route/config generation atomically. Authoritative grants/secrets remain server-owned, not embedded bearer authority. An invocation pins code/config and its grant ceiling, while current revocation/disablement applies at host access and commit. Updates cannot widen old invocations. Code rollback does not revert data/schema, credentials or effects.

Store code/config roots for active deployments, pinned in-flight invocations, jobs, consumer rebuilds and retained recovery anchors. Superseded frontend roots remain protected for the [bounded app release window](reference-apps.md) and count against app quota; backend code/config is retained only while an explicit owner still needs it. Upgrading an attached filter/consumer/snapshot adapter advances its configuration revision and requires a state/format compatibility declaration. Keep old compatible code or an explicit migration path while it is needed for recovery; never silently replay old state using whatever code is currently on `main`.

## Shared engine, different invocation profiles

| Profile | Inputs and result | Host access and commit rules |
| --- | --- | --- |
| Filter | Immutable ingress context + candidate -> pass/drop/reject | Pure bounded computation; no independent writes/network; original signed bytes cannot be overwritten |
| Validator | Final candidate + fixed validation context -> accept/reject | No independent side effects; runtime failure fails closed |
| Consumer | Committed event/batch + attachment state -> new state/index mutations | Host commits scoped materialization and checkpoint atomically; external effects only through an explicitly enabled outbox |
| Snapshot adapter | Compatible seed + exact records `[Q,P)` + pinned semantic config -> typed snapshot output | Deterministic bounded computation and leased output-object construction; no clock/network/secrets/current materialization as authority |
| HTTP endpoint | Authenticated request/context -> response and optional mutation plan | Caller-bound or explicit delegated action; commit-before-success; initial bounded non-streaming response |
| Webhook verifier/handler | Original bounded request -> verification evidence, then command plan/response | Verification phase has no mutation authority; handler receives fixed provider/app grants only after verification |
| Job | Persisted input + scoped service authority -> progress/checkpoints/result | Bounded attempts, lease fencing, cancellation and explicit retry/effect policy; no ambient daemon privileges |

Profiles share artifact loading, isolation, host-call validation, metering, safe logs and diagnostics. They do not share a universal bag of capabilities. A module exports only entrypoints compatible with the profile it was installed for; an HTTP entrypoint cannot be invoked as a privileged snapshot worker. Built-ins may implement the same logical host contracts without being forced through a VM.

Snapshot and replayable materialization profiles receive deterministic input: fixed event/acceptance time and versioned configuration, with no ambient wall clock, random generator, arbitrary mutable reads or network. A deterministic seeded computation is distinct from a cryptographic entropy API. Endpoint/job profiles may request host time or randomness where approved; automatically retried plans must bind such inputs consistently or report conflict instead of rerunning transparently.

For v1, a user consumer observes committed events asynchronously. Its failure stalls its checkpoint; it does not retroactively reject an acknowledged append. Transactional built-in KV remains in the append transaction. Immediate domain invariants belong in a command/validator plus a host commit precondition, not in an eventual consumer. Future scripted synchronous materializers need a separately proven contract.

## Authority and host API

Two explicit endpoint authority modes:

- **Caller mode (default):** current caller authority intersected with deployment grants, approved bindings and invocation restrictions. Invoking code never expands the caller's rights.
- **Delegated action:** a narrowly registered operation executes under a bounded service grant after a declared admission policy (for example a verified webhook or guest form submission). It is not an ambient owner token. Administration approves its input surface, exact resource bindings and grant ceiling. The caller does not inherit those grants for generic API calls.

Both modes require `function.invoke` or their specific registered trigger admission rule. Jobs/consumers use scoped service identities, with current disablement/revocation checked at admission, host access and durable commit. Caller/deployment/trigger/resource identities are host-generated and cannot be supplied as trusted fields by guest code. Replay/administrative rebuild is a distinct invocation mode with side effects disabled.

Expose versioned capability handles rather than filesystem paths, raw DB handles or transferable backend tokens:

| Host capability | Semantics |
| --- | --- |
| Bound resource lookup | Resolves only installation-approved names; result bound to invocation/app/profile |
| Read object/range/map/directory | Authorized, bounded immutable traversal; acquired leases protect GC but confer no permission |
| Read mutable key/ref/index | Records host-owned revision dependencies; index state also exposes applied position |
| Prepare object/tree | Leased immutable output, quotas charged before work; not published or permanently retained yet |
| Submit mutation plan | Declarative scoped commands with host-owned preconditions; no raw SQL or alternate append path |
| Enqueue job/effect | Durable intent committed with state, subject to approved destinations and service grants |
| Verify/sign using secret handle | Explicit allowed algorithm/purpose/destination; no general signing oracle or automatic raw-secret export |
| Safe diagnostics | Structured bounded logs, invocation IDs and safe errors; request bodies/secrets excluded by default |

Every host call revalidates handle provenance, resource scope, byte/count budgets and applicable current policy. Guest numeric handles cannot be guessed or reused across invocations. Guest network headers and payload fields cannot select an arbitrary service identity. Handles and signing operations still enable misuse within granted authority; least privilege and deployment approval remain necessary even with perfect VM isolation.

Secrets are server-owned, versioned references outside the code directory and app downloads. Prefer provider verification/request-signing host operations. Raw secret access, if unavoidable for an integration, is a separate high-trust approval and invalidates any claim that the runtime can prevent that function from leaking it. Error/log sanitization alone cannot guarantee non-exfiltration for code allowed to read secrets and emit arbitrary responses.

## Optimistic application transactions

Never run guest code, await I/O or compile inside SQLite's write transaction. Submit an existing command: one KV operation, one stream append, or one reference CAS optionally coupled to one truthful stream record. A command may atomically include required object roots, receipt and scoped job intents. A consumer's private materialization/checkpoint update is a separate command profile. No arbitrary multi-reference/multi-stream write set, event batch or public SQL transaction is available.

For multi-key application invariants, prepare an immutable map batch against one root and CAS its reference. The host records all mutable source revisions used in the decision, including any source collection read while publishing a separate public projection. This supplies safe predicate decisions without a new collection database. Stream-backed materializations mutate only by accepted canonical events; consumer indexes are derived state, not independently writable application truth. Generic APIs cannot bypass a protected command: restrict direct write grants and enforce mandatory final validation.

Proposed execution protocol:

1. Admit and authenticate against a pinned deployment/config, limits and trigger policy. Reserve invocation work and establish required input leases.
2. Read through host capabilities. The host records **all** mutable read dependencies, including missing keys and ref/namespace revisions used by range/predicate reads; the guest cannot erase entries from the read set. Each read is short, not a long-lived SQLite snapshot across the whole invocation.
3. Compute a mutation plan and tentative response. Build large immutable outputs under leases. No visible reference/state mutation or network effect has occurred.
4. Prepare the optional single stream candidate through the common mandatory pipeline outside the write transaction. Include validator/pipeline read dependencies and final checks. Prohibit recursive endpoint/pipeline calls; the candidate follows each declared stage once.
5. In a short SQLite transaction, check all host-recorded read revisions and the command's bounded write preconditions, current authority/config, quotas, object durability/link rights and lifecycle. Execute the selected built-in command and its associated roots/jobs/checkpoint/receipt atomically. Guest-computed predicates are safe only if every authoritative input revision still matches.
6. Commit, then notify/return success. On conflict or validation failure, publish nothing. Prepared outputs remain leased for retry/expiry. A pipeline drop on a command requiring a publication record means no associated state/ref update; return an explicit non-publication result.

**Read consistency:** host-track monotonic reference or namespace revisions, including absence/creation/deletion, to prevent ABA. For “no reservation overlaps this interval,” read a bounded range from one immutable map root and require the reference revision unchanged at commit. Mutable built-in index queries use a coarse namespace revision initially. All pages share a bound root/revision; tracking only returned rows misses phantoms. Do not add a predicate compiler or new conditional opcode for each application rule. Unsupported/unbounded queries fail explicitly. Even read-only endpoints promising consistent multi-read results validate their dependencies before returning.

Asynchronous queries expose applied position. Waiting for `at_least_position` gives read-your-write progress, not proof of current absence. For an invariant based on a derived index, require its checkpoint to equal the captured authoritative stream tail and fence both tail and index revision at commit; otherwise read authoritative state or fail/retry. Snapshot/rebuild swaps also advance the namespace revision. A script cannot manufacture isolation from an unsupported query.

Conflicts normally return a typed retryable result. Host-managed retries are optional only for declared effect-free plans with fixed inputs and a finite budget. A function cannot safely retry an external request merely because its SQLite commit conflicted. A client disconnect cancels preparation best-effort; after commit starts the outcome may be unknown and must be resolved through receipt inspection/retry.

For mutating endpoint requests, scope idempotency to app/function resource, caller principal or delegated grant, endpoint class and key (D24). Use the shared receipt record to reserve input digest and initial deployment on first admitted execution, with a bounded lease/generation for in-progress work. Only a committed result is a success receipt; recovery fences stale executors and retains pinned artifacts. Route updates do not rerun matching completed requests under new code. Reauthenticate before receipt lookup, and recheck current access before returning any stored private response. Bound receipt size and retention; different input conflicts, expired receipts allow a new operation according to the advertised contract. No runtime exception may be converted into a fabricated successful receipt.

## HTTP and webhook registration

Register explicit methods and app-relative route templates in the deployment. Reserve identity, admin, core API, platform gateway and internal paths; app functions cannot override them. Reject ambiguous routes, encoded-path bypasses and unapproved hostnames. App domain verification and TLS remain platform responsibilities.

Initial endpoints use bounded buffered bodies and responses. Long work returns a durable job receipt after enqueue commit, with authorized status/cancel endpoints. Arbitrary streaming responses, WebSocket servers, user-defined listeners and unlimited request lifetimes are deferred. Response status/header policy disallows overriding platform session cookies, hop-by-hop headers or security boundaries; cache policy respects caller/private/shared data. Ordinary errors have stable safe codes and correlation IDs, not stack traces/secret-bearing guest errors.

Webhook processing has separate stages:

1. Bound immutable original bytes and an explicit header allowlist.
2. Authenticate using an installed verifier and secret capability, including timestamp/replay rules required by that provider. Use established crypto host operations. A custom verifier is itself approved security-sensitive code, not a generic handler returning an untrusted `authenticated: true` field.
3. The host issues invocation-bound verification evidence binding verifier/deployment, original body, selected headers, destination and validity. Only the registered verifier path can obtain this evidence; handler code cannot mint or copy it from another request.
4. Check current admission/delegated authority and deduplication only after verification. Normalize through the handler, then pass candidates through the common stream pipeline/final validators and commit fences.

A signature-valid delivery ID is a retry key, not independent proof of authenticity. Previously saved receipts do not make an invalid signature pass. Handler transform/drop is permitted; auth, mandatory validation, quota and storage failures cannot be hidden by a “silent success” setting. Custom parsing does not imply universal provider compatibility; fixtures are still required per provider.

## Consumers, jobs and external effects

Consumer progress is a next-record position, with pinned attachment/code/config identity and a lease generation. Prepare bounded state updates outside the write transaction; atomically commit materialization, explicit object roots, optional effect intents and checkpoint. Competing/stale workers fail the checkpoint/lease fence. Poison events produce visible stall/retry state, never silent skipping. Rebuild uses a shadow state or isolated target and cannot perform external effects.

External delivery uses the shared job runner's outbox kind. State/checkpoint and effect intent commit together; a scoped dispatcher sends afterward. Stable effect identity binds trigger (for example attachment + event position + effect slot), not attempt or latest code version. Retries are at-least-once; downstream idempotency suppresses send-before-ack duplicates where supported. Keep effect deduplication identities for the supported reprocessing window; rebuild mode never emits them. Intentional redelivery requires a separately audited run identity. Upgrades cannot silently resend old effects.

Outbound access is denied by default. Approved connectors/destinations enforce scheme/host/port, resolved-address and redirect checks, internal/metadata-network exclusions, bounded response bytes, deadlines and concurrency. Secrets are applied only to the approved request target, never forwarded through arbitrary redirects. Egress checks occur for every connection, including DNS changes. Durable callbacks and webhook retries use the same controls. Rebuild/snapshot profiles have no egress capability.

Functions use the same durable jobs and leases as snapshot/rebuild/object work, with pinned function artifacts and scoped authority. Long jobs are bounded invocations with checkpoints, not immortal scripts. Cancellation/expiry fences stale durable publication; effects already dispatched cannot be recalled. Disablement stops admission and not-yet-dispatched effects, interrupts guest work and is rechecked at commit. It cannot retract a network request already sent.

Function-triggered append/job chains can otherwise amplify recursively. Carry a host-owned lineage with hop, total-work, concurrency and fanout limits; each generation reauthorizes. Reject self-trigger storms visibly instead of allowing unlimited event/job recursion.

## Runtime isolation and operational limits

Select an engine through a bounded prototype, not by treating a language interpreter as the whole security boundary. Evaluate native QuickJS in OS-isolated workers against a Wasm execution profile, including a JS-in-Wasm option if useful. JavaScript/TypeScript authoring and the binary runtime ABI are separate choices. TypeScript is compiled ahead of execution; Node.js/npm/OS API compatibility is not promised.

Proposed production topology places untrusted execution in supervised worker processes separated from the storage coordinator. A narrowly scoped broker implements host capabilities; workers receive neither DB/file-store credentials nor general network access. The OS isolation profile, privilege model, filesystem exposure, process limits and broker protocol require tests. Worker crashes/traps terminate the invocation and release resources, not the authoritative server. Compiler/parser work is also isolated and budgeted. Fresh per-invocation guest state is the default; any pooling must prove no memory/global/handle/secret leakage between tenants.

Required limits: code/dependency/compiled size, compile time/cache space, guest CPU/fuel/instructions, wall time, memory/stack, body/response/log bytes, host calls/read/write bytes, query/page/predicate sizes, prepared-object storage, job attempts, queued work, per-user/app concurrency and invocation lineage. Guest CPU metering does not bound a blocked or expensive host call: the broker must enforce independent deadlines, cancellation and I/O budgets. Numeric defaults are measured at G-FUNCTIONS, not advertised capacities now. OOM/timeouts/unsupported ABI are explicit failures; validators fail closed and consumers/snapshot adapters stall safely.

Store artifact/runtime/ABI/compiler identity in cache keys. Accept source or verified portable modules; do not blindly deserialize user-supplied native/precompiled engine caches. Imported modules must not gain new host imports because a server upgrades its runtime. Capability/ABI revisions are explicit, and runtime security updates require compatibility fixtures and deployment rollback planning.

Diagnostics include invocation/deployment ID, profile, trigger ID, safe result code, durations, host-call/budget usage, attempt and committed position/receipt where authorized. Structured logs cap cardinality and redact credentials/original payloads by default. No public download of code, diagnostic dumps or module memory unless separately authorized. Record admission/permission changes and operational disablement in the audit trail without claiming application payloads are secret-safe merely because logs are redacted.

## Three initial end-to-end prototypes

1. **Quote publication endpoint:** caller-scoped lookup of quote/ownership and collection revision, omission of private fields, leased public tree preparation, atomic public-ref + publication-event + receipt commit. Race edit/delete against publication; private fields must never enter the shared tree. Illustrative route `POST /api/quotes/{id}/publish`, not a promised endpoint yet.
2. **Complex signed webhook:** isolated approved verifier over original bytes, provider timestamp/delivery ID, bounded custom normalization and conditional domain command; common validators cannot be bypassed. A forged request matching a saved delivery ID still fails. Use no raw general-purpose secret access in the first example.
3. **Replayable consumer:** derive an author/tag quote index from accepted commands and commit index/checkpoint together. Crash before/after commit, retry, upgrade compatibility and rebuild produce equivalent state. A separate effect-enabled mode demonstrates outbox retries; rebuild emits no deliveries.

Also test a two-request reservation race against a collection predicate. It proves that the host transaction model supports domain enforcement beyond existing built-ins rather than merely running JavaScript syntax.

## Gates, scope and implementation sequence

| Gate | Required evidence | Blocks |
| --- | --- | --- |
| G-FUNCTIONS | Runtime/ABI selection, license/dependency review, adversarial isolation/interrupt/host-call tests, measured limits | Any production untrusted code |
| G-FUNCTION-TX | Ref/namespace revision fences, core-command broker, pipeline integration and atomic receipts/checkpoints/outbox | Stateful custom commands/consumers |
| G-FUNCTION-AUTH | Caller vs delegated grants, handle/secret isolation, verifier evidence, revocation/egress, route protections | Public endpoints and privileged triggers |
| G-FUNCTION-RECOVERY | Artifact/state upgrade fixtures, deterministic replay/snapshots, stale-worker fences and effect recovery | Durable consumers/jobs/snapshot adapters |

Underlying G-AUTH/G-APP/G-DURABILITY/object gates also apply. Roadmap **S-01–S-07** starts with host ABI/profile/command fixtures, prototypes one selected runtime, then implements the broker and examples. Do not introduce selectable fake runtimes or placeholder endpoints.

Deferred: arbitrary shell/native binaries, ambient filesystem/network/WASI privileges, uploaded modules executed inside SQLite transactions, long-lived arbitrary servers, generic cross-stream transactions, undisclosed elevated endpoint authority, unrestricted synchronous egress and exactly-once external delivery. These limits still allow custom app endpoints, complex verified webhooks, user materializers and bounded background workflows.

Runtime implementation references: [Wasmtime security model](https://docs.wasmtime.dev/security.html), [execution interruption](https://docs.wasmtime.dev/examples-interrupting-wasm.html), [QuickJS embedding and limits](https://bellard.org/quickjs/quickjs.html). These document mechanisms, not validation of a Patchwork sandbox.

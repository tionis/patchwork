# Authorization, authentication, and delegation

The same policy model governs streams, objects, references, snapshots, app bindings and function invocations. Root/hash knowledge, GC pins and pagination cursors grant no authority. [Object access](unified-design.md) and [Functions](functions-design.md) define scoped host operations; they are not independent token systems.

## Status

Requirements: an expressive permission language and client-side attenuation. Biscuit for both token restrictions and server authorization is the preferred prototype, not yet an unconditional dependency choice. Most users will mint scoped tokens from the server rather than attenuate tokens manually.

Biscuit combines facts/checks with application allow/deny policies and tracks block provenance. Default authorizer trust does not let arbitrary attenuation-block facts grant rights; policy order is significant. The prototype must retain those guarantees. [Authorization policies](https://doc.biscuitsec.org/getting-started/authorization-policies), [specification](https://doc.biscuitsec.org/reference/specifications).

## Authority model

Use one model for normal API tokens, CLI/browser sessions, and hook grants:

**effective authority = current server authorization ∩ immutable issuance scope ∩ all attenuation checks ∩ credential validity.**

Use principal identity plus a stable server credential ID in the signed authority block. Store the issuance ceiling, owner, expiry, and revocation state in the server database. Token checks encode restrictions using the same authorizer vocabulary. This intentionally uses online server state; offline verification by other services is not a v1 goal. Attenuation can still be performed offline by clients.

ACL additions must not widen old scoped credentials beyond their issuance ceiling. ACL removal must remove access even from previously minted tokens. Session credentials may explicitly have a broader ceiling, with a short expiry, when that is intended. Avoid introducing a parallel perpetual-capability mode initially.

## Trust origins and evaluation

Only verified issuer authority blocks establish principal/credential identity. Only server-generated facts establish current resource/action, time, canonical name, current grants, resource ownership, and credential validity. Attenuation blocks may add checks, but facts they assert cannot impersonate those trusted origins.

Build authorizers with typed library APIs rather than string-interpolated Datalog. Keep reserved fact names and origin scopes in a versioned registry. No `trust previous/all blocks` shortcut in grant rules. Third-party blocks/discharge-like workflows are deferred.

Proposed vocabulary:

| Fact | Trusted origin | Purpose |
| --- | --- | --- |
| `principal(id)` | Issuer authority | Authenticated principal |
| `credential(id)` | Issuer authority | Server issuance/revocation record |
| `instance(id)` | Server plus issuer binding | Prevent cross-instance replay |
| `operation(action)` | Server | One exact operation under evaluation |
| `resource(kind,id)` | Server | Stable resource identity |
| `resource_name(name)` | Server | Canonical name for allowed prefix constraints |
| `time(timestamp)` | Server | Current time |
| `credential_valid(id)` | Server | Enabled, unexpired, unrevoked |
| `current_right(principal,action,kind,id)` | Server | Current policy-derived right |
| `issued_right(credential,action,kind,id)` | Server | Frozen issuance ceiling |

This is a vocabulary proposal, not verified Biscuit source syntax. The prototype must provide compilable policy files and golden vectors before integration. Policies must require matching values across principal, credential, operation, and resource—not independent existential facts that accidentally combine unrelated rights.

Load only relevant server facts, but prove that pruning preserves policy decisions. Arbitrary rules can depend on relations beyond the direct resource; a query planner that omits those relations is a correctness bug. Start with an explicit bounded supported server fact model and fetch its closure. Custom administrative rules are validated against that model.

Default deny. Explicit server prohibitions must be evaluated before permits or compiled into mandatory checks. Do not assume a policy engine automatically implements deny-overrides. Time/fact/iteration limits fail closed with safe error categories and metrics.

## Permission boundaries

Distinct actions include `stream.create/list/inspect/delete/watch`, `stream.config.read/write`, `metadata.read/write`, `record.append/read/subscribe`, `snapshot.list/read/create/publish/accept/delete`, `object.create/read/link/pin`, `ref.create/list/read/publish/delete`, `lease.create/renew/release`, `job.read/cancel`, `function.invoke`, `attachment.read/write`, `consumer.rebuild`, `kv.read/write`, `hook.manage`, `credential.mint/revoke`, and administrative policy/principal operations. `snapshot.accept` is scoped to a recovery requirement and distinct from publication; configuring trusted producers requires config-write authority. Redirect route/binding administration is a separate platform grant; `ref.publish`, `ref.read` or control of a matching name cannot expose a public route. See [client-produced snapshots](external-snapshots.md); these actions are not implemented APIs.

Snapshot `read` grants payload/dependency access through that authorized snapshot context; `list` grants descriptor access only. Reading a descriptor does not authorize a bare object lookup. Verify every permitted reference path and current resource policy; global existence never grants access. An owner-scoped upload lease permits access only under its current authenticated owner policy. Root-scoped grants cover required content descendants, not optional history or unrelated roots. Client-provided root context is verified, not trusted.

Derived-view read never implies raw-history read. Watch access never implies metadata, raw record, or object access. Content-addressed deduplication is not an access-control boundary. Control-plane operations cannot be hidden inside ordinary application metadata.

Exact ID scopes survive neither deletion/recreation nor reassignment. Prefix scopes intentionally apply to future resources matching the authorized canonical prefix; make that distinction visible in token creation UI. Prefix creation defaults do not grant prefix authority.

Reference namespace checks use the canonical name with component-boundary prefixes and the stable ID/current policy at admission and CAS commit. Prefix listing filters each item and reauthorizes each page; a cursor or guessed name grants neither descriptor visibility nor target bytes. Public redirect service has a separately approved domain/path binding and destination policy. It may reveal only the approved URL by redirect, not a private object descriptor, sibling names or a broader root; binding disablement and revocation fence new admissions. Never forward caller credentials to the destination.

## App, share and service admission

App bindings and shares are managed grants using the same current-policy/issuance-ceiling model. They do not mint ambient owner credentials. One browser session service issues host-only Secure HttpOnly cookies for the trusted operational origin and for app origins; each session binds principal or guest grant, origin/audience, approved operations, expiry, revocation lineage and issuance provenance. App sessions additionally bind approved app resources. Admission can only narrow an existing authenticated session or redeem an explicitly administered share grant. An attenuated caller cannot discard restrictions by exchanging for a cookie. Guest authority comes from the share grant, never an inferred account identity.

The operational UI obtains its session through a one-use handoff from a fresh SSH-authenticated CLI session. This preserves the original session kind, issuance ceiling and unattenuated provenance for the trusted origin; minting still requires current `credential.mint` and a fresh session. An API-token, app-session or guest exchange cannot acquire that provenance or mint general credentials. Background jobs/consumers receive explicit service grants bounded to fixed resources and operations. Deleting or disabling a binding/grant fences active work. App deployment permission allows code to use already approved capabilities; capability expansion needs separate administration. Secret URL redemption proves only possession of that grant and uses a dedicated leak-resistant exchange, never a global hash-based capability.

## SSH login

Proposed protocol uses OpenSSH-compatible detached signatures (SSHSIG), not an SSH transport server. Prototype the chosen Rust library and interoperation with `ssh-keygen -Y sign` and ssh-agent. Support Ed25519 first; additional key types are a documented gate, not a hand-rolled parser.

Server returns `{challenge_id, payload_base64, expires_at, namespace:"patchwork-auth-v1"}`. Payload is exact server-generated bytes binding protocol version, instance ID, intended API origin, public-key fingerprint, random 256-bit nonce, and expiry. The client signs exactly those bytes with that namespace. Store the challenge payload server-side; do not trust reconstructed client fields. Default lifetime 60 seconds, single successful redemption, bounded attempts/rate limits. Consume challenge atomically with session issuance.

Exchange returns a short-lived session token (proposed 15 minutes). Registered key must map to an enabled principal at exchange time. Unknown-key responses should not disclose account membership. TLS protects the exchange. Do not implement custom signature cryptography.

Local bootstrap: `patchwork admin bootstrap --ssh-public-key FILE` against the stopped/new instance, creates the first administrator once; no public default admin password. Subsequent key and principal changes require administration. Recovery uses an explicit local maintenance command with operator filesystem authority and audit output.

## Minting and offline attenuation

Server token creation accepts structured scope: explicit action list and exact resources or explicitly supported prefixes, requested expiry, and display name. It stores the approved ceiling and returns the secret token once. Listing credentials returns IDs/scopes/status, never bearer secrets.

General logical implication between arbitrary Datalog predicates is not the v1 minting algorithm. Require a **fresh, unattenuated SSH-authenticated session** for server issuance. The session must have `credential.mint`, and each requested scope must be within current server delegation policy. Broad prefix minting requires explicit prefix delegation authority; testing a handful of existing streams is insufficient proof.

An API token cannot mint another server credential merely because it carries a principal identity or a copied `credential.mint` fact. The verifier checks session kind, provenance, and absence of attenuation blocks. This prevents an attenuated caller from laundering restrictions through the issuer. Clients can always produce a narrower child locally by appending checks to the original token; no minting API call is needed.

The CLI provides named helpers such as `token attenuate --read-only --stream ID --expires-at TIME`. Preserve the original chain. Explain that possession of the original token still confers original authority; issuing a child does not revoke its parent. Do not promise confidential caveats—bearer holders can inspect token contents.

## Revocation and active work

Every request checks principal enabled state, server credential revocation, expiry, issuer-key acceptance, issuance scope, and current policy. Revoking the credential invalidates its offline descendants. Individual child-chain revocation is deferred; root credential revocation plus short expiries is sufficient for v1.

Authorization cache keys include credential/chain digest, resource, action, policy revision, principal revision, and relevant time boundary. No cache entry survives expiry or a revision invalidation. Current server-side changes apply to newly admitted operations immediately after commit.

Active watches/follows/live subscriptions and long downloads are rechecked at most every five seconds and before new batches. On denial, stop delivering bytes and close. Already transmitted data cannot be recalled. Operations already durably committed before revocation remain committed. A mutation authorizer revision must be rechecked at commit to avoid a long-running filter committing stale authority.

Hook provider secrets and optional opaque URL grants are independently revocable. A hook's internal append authority is limited to its fixed target and pipeline and checked against current configuration. A provider-valid request must not become an instance-wide append credential.

## Biscuit prototype gate

Produce a small Rust executable/test crate that uses the selected maintained library version and records its version/license. It must:

1. Verify SSH challenge exchange and issue an identity/session token.
2. Evaluate exact and prefix rights with current server facts and issuance ceilings.
3. Attenuate locally by action/resource/expiry and prove no widening with adversarial block facts.
4. Enforce token expiry, credential revocation, policy changes, and session-only minting.
5. Authorize multi-resource operations item-by-item; prefix watches need universal selector authority.
6. Bound parsing size, blocks, execution time, facts, and iterations; fuzz malformed tokens.
7. Measure single-request and sustained authorization overhead for 1/8/32 blocks and 10/100/1000 relevant facts on named hardware; report p50/p95/p99 and memory, not unqualified speed claims.
8. Produce examples understandable by an operator and compare feasibility against expected load.

Pass means security vectors pass, limits work, and overhead is acceptable for measured service workloads. Do not invent a fixed latency requirement without hardware context. On failure, document the concrete limitation and present CEL/macaroons or another alternative for a decision; do not silently substitute a home-grown token format.

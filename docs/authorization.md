# Authorization, authentication, and delegation

The same policy model governs every resource kind (streams, keyspaces, documents, databases, blobs) and URL-transport credentials. Knowing a name, hash or cursor grants no authority. See [design](design.md#shared-control-plane).

## Status

Requirements: scoped permissions and client-side offline attenuation (C10). Biscuit is the preferred **token format** for identity and attenuation (C11); it is not the server's policy language. Most users mint scoped tokens from the server rather than attenuate tokens manually.

Biscuit combines facts/checks with authorizer policies and tracks block provenance. Default authorizer trust does not let attenuation-block facts grant rights; the prototype must retain that guarantee. [Authorization policies](https://doc.biscuitsec.org/getting-started/authorization-policies), [specification](https://doc.biscuitsec.org/reference/specifications).

## Authority model

Use one model for normal API tokens, CLI/browser sessions, and hook grants:

**effective authority = current server grants ∩ immutable issuance scope ∩ all attenuation checks ∩ credential validity.**

The four terms are evaluated by two mechanisms:

| Term | Evaluated by | Source |
| --- | --- | --- |
| Current server grants | Typed Rust grant model | Principal/service grants in SQLite, current revision |
| Issuance scope | Same typed grant model | Frozen ceiling stored with the credential record |
| Credential validity | Rust | Principal enabled; credential unexpired and unrevoked; issuer key accepted; instance matches |
| Attenuation checks | Biscuit authorizer | Checks appended to the token by holders, evaluated against server-supplied request facts |

A request is allowed only when all four pass. This intentionally uses online server state; offline verification by other services is not a v1 goal. Attenuation can still be performed offline by clients.

ACL additions must not widen old scoped credentials beyond their issuance ceiling. ACL removal must remove access even from previously minted tokens. Session credentials may explicitly have a broader ceiling, with a short expiry, when that is intended. Avoid introducing a parallel perpetual-capability mode initially.

## Grant model (v1)

A grant is `(subject, action set, resource selector)`. The subject is a principal or a service/share grant. The selector is an exact stable resource ID of a named kind, or a canonical name prefix with component-boundary matching (`foo/` matches `foo/bar`, never `foobar`). Grants are allow-only; access is removed by deleting grants, disabling principals or revoking credentials. Evaluation is plain Rust over typed rows: no user-authored rules, no Datalog on the server-policy side, and no fact pruning to prove correct.

Explicit prohibitions (deny rules) and administrator-authored policy rules are deferred. If added later they must be evaluated before permits and come with a reference model and golden vectors.

## Trust origins and evaluation

Only verified issuer authority blocks establish principal/credential identity. Only the server supplies request facts: operation, resource identity, canonical name, time and instance. Attenuation blocks may add checks against those facts, but facts they assert cannot impersonate trusted origins.

Build Biscuit authorizers with typed library APIs rather than string-interpolated Datalog. Keep reserved fact names and origin scopes in a versioned registry. No `trust previous/all blocks` shortcut. Third-party blocks/discharge-like workflows are deferred.

Request-fact vocabulary for attenuation checks:

| Fact | Trusted origin | Purpose |
| --- | --- | --- |
| `principal(id)` | Issuer authority | Authenticated principal |
| `credential(id)` | Issuer authority | Server issuance/revocation record |
| `instance(id)` | Server plus issuer binding | Prevent cross-instance replay |
| `operation(action)` | Server | One exact operation under evaluation |
| `resource(kind,id)` | Server | Stable resource identity |
| `resource_name(name)` | Server | Canonical name for prefix checks |
| `time(timestamp)` | Server | Current time |

This is a vocabulary proposal, not verified Biscuit source syntax; the prototype provides compilable examples and golden vectors. Each evaluation covers exactly one operation on one resource, so a check cannot be satisfied by facts about an unrelated resource. Multi-resource operations authorize item by item.

Default deny. Budget limits (token bytes, blocks, facts, iterations, time) fail closed with safe error categories and metrics.

## Permission boundaries

Distinct actions include `stream.create/list/inspect/delete/watch`, `stream.config.read/write`, `metadata.read/write`, `record.append/read/subscribe`, `attachment.read/write`, `kv.read/write`, `hook.manage`, `credential.mint/revoke`, and administrative policy and principal operations. Planned kinds add `keyspace.*`, `doc.read/write`, `db.read/write`, `blob.*` and `link.create/revoke` in the same style, with publish, subscribe, read and write kept as separate actions.


Derived-view read never implies raw-history read. Watch access never implies metadata or raw record access. Control-plane operations cannot be hidden inside ordinary application metadata.

Exact ID scopes survive neither deletion/recreation nor reassignment. Prefix scopes intentionally apply to future resources matching the authorized canonical prefix; make that distinction visible in token creation UI. Prefix creation defaults do not grant prefix authority.


## Apps, links and delegation

Apps keep their own identity (D32). An app backend receives a credential for its own name prefix and narrows it offline per user, document or session, then hands the result to a browser. Patchwork checks it like any credential; per-user revocation is the app's job, so browser credentials use short expiries. A WebSocket cannot send headers, so its credential is a URL-transport credential in `?token=`.

URL-transport credentials (implemented, G-URLCRED open) serve clients that cannot send headers. Any credential minted with `url_transport` may be presented as `?token=…`; minting refuses that flag for session tokens and for any credential with administrative, mint or principal-wide authority, so only narrow, explicit-resource, non-administrative credentials can ride in a URL. Each is minted for one purpose, is revocable and expires like any credential, and is rechecked against current policy on use. The server logs only a fingerprint for requests that carry one, sets `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and rejects a token given both in the header and the query. See [design](design.md#shared-control-plane).

The operational session handoff and minting rules in [architecture](architecture.md#operations) still apply: an API token, app credential or link cannot acquire minting provenance.

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
2. Combine the typed Rust grant decision (current grants ∩ issuance ceiling, exact and prefix selectors) with Biscuit attenuation checks; show that no token content can change the grant decision.
3. Attenuate locally by action/resource/expiry and prove no widening with adversarial block facts.
4. Enforce token expiry, credential revocation, policy changes, and session-only minting.
5. Authorize multi-resource operations item-by-item; prefix watches need universal selector authority.
6. Bound parsing size, blocks, execution time, facts, and iterations; fuzz malformed tokens.
7. Measure single-request and sustained authorization overhead for 1/8/32 blocks and 10/100/1000 relevant facts on named hardware; report p50/p95/p99 and memory, not unqualified speed claims.
8. Produce examples understandable by an operator and compare feasibility against expected load.

Pass means security vectors pass, limits work, and overhead is acceptable for measured service workloads. Do not invent a fixed latency requirement without hardware context. On failure, document the concrete limitation and present CEL/macaroons or another alternative for a decision; do not silently substitute a home-grown token format.

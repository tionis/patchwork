# Function conformance plan

FN-01–FN-24 validate [Functions design](functions-design.md) using real selected runtimes and non-admin identities, isolated data, deterministic fixtures, controlled external test receivers and fault injection. Test the host/broker as well as the guest engine. Existing P/A/E/G and OBJ cases still apply.

| ID | Scenario | Required result |
| --- | --- | --- |
| FN-01 | Guest attempts raw filesystem/network/process/DB access or imports an unapproved host function | Denied by runtime/worker/broker boundaries; no host authority leaked |
| FN-02 | Infinite loop, recursion, allocation, compilation bomb and expensive/blocking host call | Each relevant limit enforced independently; supervisor remains responsive; bounded cleanup |
| FN-03 | Cross-tenant worker reuse, forged handles, stale handle after cancellation | No state/secret/handle leakage; broker checks invocation ownership and liveness |
| FN-04 | Manifest requests more privilege; code update changes grant/secret/destination/profile | No self-grant or ambient owner credential; only approved deployment capabilities usable |
| FN-05 | Caller endpoint attempts action caller lacks; delegated form endpoint probes other resources | Default intersection and explicit bounded delegation both enforced |
| FN-06 | Read absent key then racing insert/delete/recreate or A -> B -> A ref update | Revision/absence tracking rejects stale commit, including ABA |
| FN-07 | Two reservation commands both read no overlapping entries; concurrent phantom insert | Immutable-map/ref CAS or coarse namespace revision permits only a valid outcome; no app-specific predicate engine required |
| FN-08 | Guest omits read token, mixes paged revisions, or relies on lagging async index | Host-owned revisions enforced; invariant index must equal captured source tail and fence tail/revision at commit; stale input cannot authorize mutation |
| FN-09 | Guest computation waits while other writers commit; timeout during preparation | No SQLite write lock held for guest execution; timeout publishes nothing |
| FN-10 | Prepared objects followed by CAS/pipeline/auth failure or disk exhaustion | One supported command commits atomically with roots/receipt; no multi-stream or arbitrary-table write plan; failed outputs remain leased |
| FN-11 | Generic and custom append routes, transformed publication event, recursive pipeline invocation | Common mandatory validators/fences cannot be bypassed; at most one truthful record per command; no direct-write bypass of protected endpoint rules |
| FN-12 | Lost response, same/different retry input, deployment upgrade, then revocation | Matching completed receipt not reexecuted; pending lease/generation fences crash/upgrade retries; changed input conflicts; current auth before replay |
| FN-13 | Valid webhook vs changed original bytes/headers, expired signature, saved delivery-ID forgery | Bound verification evidence required before dedup; no handler-created authentication flag |
| FN-14 | Guest returns session cookies, reserved route, oversized body/response or secret-bearing error | Platform headers/routes protected; bounded safe response; no fake accepted mutation |
| FN-15 | Crash before/after materialization/checkpoint transaction; two consumer workers | Atomic state/checkpoint; one fenced commit; failure stalls rather than silently skipping |
| FN-16 | Rebuild/snapshot attempts clock/network/secret/current-cache read or external delivery | Profile denies; deterministic output from seed/range/config; no rebuilt side effects |
| FN-17 | Outbox dispatcher dies after send but before ack; upgrade consumer deployment | Stable effect identity and downstream idempotency; possible duplicate documented; no accidental new effect ID |
| FN-18 | Approved outbound hostname redirects/rebinds to private or metadata target; huge/slow response | Every connection/redirect checked; no secret forwarding; bounded failure |
| FN-19 | Cancel/expire/disable while job prepares output; stale worker resumes | Lease generation and current policy fence publication; already committed/effected outcome explicit |
| FN-20 | Script appends to its own trigger or recursively enqueues work | Host lineage/fanout/queue limits stop storm and expose diagnostic without starving other apps |
| FN-21 | Old app page, channel update/rollback, active invocation and permission removal | Code/config pinned per admission; revocation still current; data not rolled back implicitly |
| FN-22 | Runtime/ABI upgrade, malicious compiled-cache upload, old snapshot rebuild | Safe compilation/verified profile; no unchecked native deserialization; compatibility or explicit failure |
| FN-23 | Guest guesses secret handle, abuses signer, logs/returns errors with sensitive context | Handle purpose/scope enforced; diagnostics redacted; raw-secret privilege never silently granted |
| FN-24 | Quote publication, signed webhook and quote-index consumer with concurrent edits and replay | Correct public projection, verified ingress, atomic checkpoint, equivalent rebuild and no effect replay |

Gate mapping: G-FUNCTIONS = FN-01–03/09/20/22; G-FUNCTION-TX = FN-06–12/15/17; G-FUNCTION-AUTH = FN-03–05/11–14/18/19/21/23; G-FUNCTION-RECOVERY = FN-10/12/15–17/19/21/22/24. Passing one subset does not close the others. Publish selected runtime versions, OS isolation profile, test commands, measured budgets and remaining failures before enabling user code.

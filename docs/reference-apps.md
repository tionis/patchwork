# Reference apps and platform acceptance scenarios

Design revision 2026-09-23. These application contracts exercise the [system primitives](unified-design.md): expiring file shares/P2P, chat/media, Automerge todos and quotes, plus release, album and intake scenarios. They are specifications, not available apps. Per-user storage quotas and per-share usage limits are separate. Numeric limits, browser compatibility and integration versions require measured gates.

## Shared Apps contract to exercise

Each app has a stable policy identity, immutable deployment descriptors, production/preview channels implemented as ordinary references, verified domains and approved bindings. A deployment descriptor is an object referencing the frontend directory and pinned function/config artifacts; it is not another version store. A manifest requests bindings but cannot grant them. Preview resources are separate by default. Channel CAS pins a coherent asset/route generation; old tabs use version-pinned URLs. On promotion, keep each superseded production frontend root for seven days from its supersession, with a nonrenewable deadline. Charge that protection to app storage quota and fail promotion before changing the channel if it cannot be reserved. During the window, a pinned asset URL serves the same immutable bytes, subject to current authorization for private assets; explicit administrative disablement or domain removal may cut access sooner. After the deadline, a superseded release's versioned app-asset URLs return 410 with a reload indication even if another root retains the same blocks; an admitted transfer may finish under its lease. A release that becomes current again or is separately pinned remains available through that independent owner. This window guarantees pinned assets, not old API behavior: promotion must preserve gateway compatibility for old tabs or require a reload. Rollback makes the selected release current again but does not roll back data. Keep backend code/config artifacts private: public asset grants traverse only the frontend directory, not the entire deployment graph.

Users authenticate on the trusted identity origin. A one-use, short-lived, exact-origin callback exchange establishes a host-only app gateway session; never put bearer authority in asset URLs. Sessions expose only approved binding operations and preserve the authenticated credential's restrictions/lineage. Guest redemption uses an explicit managed grant. Neither exchange is general credential minting or an attenuation bypass; see [authorization](authorization.md).

App data has an explicit ownership scope: personal, shared workspace, or app-owned. User sessions intersect current rights with app approval and session restrictions. An invited/share guest receives a narrowly scoped grant through explicit redemption; they need not already have account-wide access. Background materializers/recorders have distinct scoped service identities. Neither frontend-supplied author fields nor claimed Automerge actor IDs establish identity.

The operational UI and hosted apps use the same browser session implementation, with distinct origin, audience and grant ceilings. Gateway/browser isolation requires executable tests: separate app origins and trusted admin/login site; host-only Secure HttpOnly cookies without cross-subdomain scope; Origin/CSRF checks; exact callback binding; no broadly privileged credentials in assets. Only a fresh, unattenuated SSH-authenticated handoff to the trusted operational origin can preserve general credential-mint provenance. Deploying new frontend code carries the app's approved access and is a sensitive permission. A malicious permitted app can misuse data legitimately exposed to it; origin isolation cannot make its own authorized code trustworthy.

[Functions](functions-design.md) supplies approved endpoints, consumers and jobs over existing host commands. All applications share receipt, admission, queue and recovery machinery. First runtime fixtures are quote publication, signed webhook and replayable quote index.

Domain bindings verify ownership before routing/TLS activation; exact Host/SNI dispatch and trusted-proxy configuration prevent cross-app routing. Releasing/rebinding a domain fences sessions and routes and handles stale caches/service workers; never transfer an active login session to the next owner. Disable unused origins. Untrusted uploads are downloads on an isolated content origin with safe MIME/disposition/nosniff rules, not executable assets on the admin/login origin. Public immutable assets may cache; private/expiring routes must reauthorize and cannot share an unauthenticated cache path.

## Application and primitive matrix

| App | Durable state and structure | Ephemeral work | New or stressed platform capability |
| --- | --- | --- | --- |
| File sharing | Byte/directory roots, share grants, leases and usage ledger | Direct transfer rendezvous, ICE and relay allocations | Expiry, redemption, logical quotas, scoped range sessions, resumable transfer |
| Chat | Per-room event stream, materialized messages, attachment roots, recording manifests | Presence, typing, call signaling and media | Membership, validated commands, reliable replay, media/session lifecycles |
| Todos | Stable document reference/stream ID, Automerge changes/heads, complete CRDT snapshots and attachment roots | Peer sync state and presence | Document-aware transport, offline merge, causal recovery and safe compaction |
| Quotes | Collection command stream, KV/prolly materialization, indexes and public projection | Coalesced update hints | Structured app commands, indexed pagination, CAS and safe publication |
| Release portal | Directory artifacts and revisioned release refs | Upload progress | Coherent deployment, subtree reuse and CAS rollback |
| Photo album | Originals, derivative roots, manifests and processing jobs | Upload progress | Scoped workers, bounded expensive processing and explicit roots |
| Intake form | Private submissions stream and owner materialization | Rate limiting | Submit-only guest permission without list/read access |

## 1. Expiring file sharing

### User journeys and records

1. Alice uploads a file or directory with resumable streaming. Admission reserves space against her account/workspace; completed object roots are held under upload leases.
2. She creates a share for an **immutable root** with expiry, optional invited recipients or secret-link access, permitted operations and redemption/egress bounds. Later directory edits do not silently change that share. Following a mutable reference would be a distinct, explicit share mode.
3. Bob opens the share page. Secret redemption returns a short-lived scoped download session after atomic expiry/revocation/usage checks. Only that root's authorized descendants are available; Bob cannot enumerate Alice's other objects or probe global hashes.
4. Bob downloads a file, browses a shared directory, or exports an archive. Range requests and retries remain tied to the session. Expiry stops new admissions and bounded subsequent delivery; Alice can revoke earlier.

Share records compose managed grants, immutable root links and the shared usage ledger. Logical fields: `Share(id, owner, root, expiry, access_mode, limits, revision, revoked)`, `Redemption(id, share, recipient_or_guest, expiry, reserved_uses)` and scoped usage reservations. These are server-enforced policy/accounting records, not a second capability or object-lifetime system. Secrets are stored as verifiers, redacted from logs and never placed in generic object query parameters. A dedicated share landing/exchange protocol must avoid referrer leakage; choosing exact link/cookie mechanics is part of the app-auth gate.

Bindings expose core object upload/read/directory operations plus share create/redeem/revoke and usage inspection. A hosted download session is a scoped grant + lease + byte reservations; do not introduce a new transfer protocol for an ordinary HTTP range read. Resumable upload and client-assisted block sync remain distinct optional optimizations, with bounded sessions; whole-byte upload works first. Share creation requires link/delegation rights and atomically establishes its retention root; UI state is not the authority.

### Quotas and expiry are precise contracts

- **Storage:** charge logical retained bytes under a documented ownership policy, separately from physically deduplicated disk usage. Count byte occurrences in directories, not just unique chunk hashes. Repeated links are not free by accident. The initial conservative policy may charge each owned retained top-level root separately; any credit for overlapping roots must be explicit and measured. Incomplete uploads consume reservations too.
- **Concurrent/final-use limits:** atomically reserve a share redemption, not a browser-reported completed download. One redemption can resume within a bounded lifetime and byte allowance. A “one-use link” means one admitted session, not proof that only one copy exists.
- **Served bytes:** reserve bounded delivery batches before sending, count retransmitted/range bytes, enforce aggregate limits across simultaneous requests, and record accounting durably. A crash may conservatively consume a reservation; do not promise exact bytes received by the peer or automatically refund possibly sent bytes.
- **Expiry:** sharing authority and retention are separate. Expiry removes this share's root when no valid session pins remain; another owner/ref/snapshot may still retain the data. Bytes already downloaded are not recalled, and physical disk is reclaimed asynchronously. Private downloads must not use an unauthenticated cache/CDN path that bypasses expiry or quota checks.

### P2P mode and relay fallback

Offer three clearly labeled transfer modes: hosted download (sender can be offline), direct transfer (sender/another authorized peer must be online), and relayed live transfer. Direct mode need not upload the full object first. The sender advertises an authenticated bounded manifest; the receiver checks chunks and final content against it. Resume identifies verified ranges/chunks for the same immutable source. A changed source creates a new transfer identity.

Patchwork authorizes rendezvous participants, exchanges short-lived signaling and issues constrained relay credentials. Browser peers use WebRTC data channels; ICE/STUN discovers connectivity and TURN supplies fallback when direct transport fails. A Patchwork-managed TURN component can provide this product feature, but a normal HTTP stream endpoint is not a TURN server. TURN implementation/deployment choice remains a gate; do not write a novel NAT traversal protocol. [WebRTC protocols](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Protocols), [TURN specification](https://www.rfc-editor.org/rfc/rfc8656.html).

Signaling uses an authorized short-retention stream per bounded call/transfer session, with position-based replay and a leased session/membership record; no separate rendezvous log engine. Expiry ends the session and cleans up signaling roots. If retention is overtaken, explicitly renegotiate rather than pretend delivery. Live events suffice only for replaceable hints with full resync. Never expose signaling publicly or retain network addresses indefinitely. UI must show whether peers connect directly or via relay; offer relay-only mode when peer IP exposure is undesirable.

**Enforcement limit:** Patchwork can meter and terminate server-served traffic and control admission/signaling. It cannot accurately meter or forcibly stop an established direct connection between cooperating/untrusted peers, nor prevent recipients copying bytes. If a share requires enforceable egress/use limits or bounded server-side termination, disallow direct mode and use a controlled transfer gateway. TURN bandwidth accounting is transport accounting, not proof of application file downloads; its credential-expiry and allocation-termination behavior must be tested. Expiry of a credential alone must not be assumed to kill an existing allocation.

Acceptance: FILE-01–FILE-05. Share admission/usage enforcement belongs in the trusted host, built from existing grants, leases and accounting; transport integration remains separate from storage.

## 2. Chat with video, recording and attachments

### Durable room state

A room is an application schema binding membership policy/revision to a retained command/event stream, scoped materialization and linked objects; the stream identity can serve as room identity. Do not add a core room storage primitive. Commands include send/edit/delete message and attach object, with stable command IDs. Server handlers derive sender identity, check room membership and edit ownership, validate payload, apply policy revision fences and append idempotently. The UI does not get arbitrary SQL or unrestricted room-stream append authority. Users initially share one room-history visibility policy; “only events after joining” requires extra range-aware authorization and is a separate feature.

Use an asynchronous message materializer initially, with visible applied position; do not introduce a new synchronous app-specific engine solely for immediate reads. In the latter case a client can request `at_least_position` with bounded waiting or display pending state. Message IDs, stream positions and materialization revisions are distinct. Edit/delete events affect the current view but do not erase previously retained events or recipients' copies; a stronger erasure contract needs explicit retention/redaction work.

Upload attachments under leases, then link them atomically when accepting the message. Message and attachment read rights are intentionally bound through room policy. Failed send leaves a leased upload, not a permanent hidden root. Removing a member denies new reads/download batches and room commands under the documented refresh bound.

### Ephemeral room state and media

Presence and typing use bounded live events with client TTLs; reconnect republishes current state. If querying online membership is necessary, use a small leased KV view rather than a presence engine. Call invitations/membership and recording lifecycle events may be durable; SDP/ICE signaling is short-lived and separately authorized. Media frames are not retained stream records or SSE events.

First media exercise is a one-to-one browser call with TURN fallback. Multi-party rooms require an explicit topology choice and measured participant limit; evaluate a scoped SFU service rather than assuming a full mesh scales. A broadcaster-to-many view similarly needs media distribution decisions. Group forwarding is distinct from TURN fallback. [WebRTC multi-party discussion](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Protocols).

### Recording is a durable job

Recording state is application data in a stream/KV or reference-backed manifest; processing reuses the shared job runner. Recordings have states `requested -> recording -> finalizing -> ready`, plus `failed`, `cancelled` and `partial`. Visible recording notice and explicit participant consent are product requirements for these examples, without claiming a universal legal compliance policy. Membership/consent changes must trigger the selected stop/reconsent behavior. A participant-operated browser recorder is the first experiment; a resilient server recorder is a separate scoped worker that must receive the media it records.

Store each uploaded recording piece durably with session/track identity, sequence, timestamps and codec/container configuration; append an idempotent manifest update only after durable storage. The final directory includes a recording manifest and track/segment objects. A disconnect preserves acknowledged pieces and marks an interrupted recording partial. Finalization validates ordering/gaps and produces a playable supported output before reporting ready.

Do not assume every `MediaRecorder` timeslice is independently playable or that separately recorded tracks/sessions can be concatenated into one valid file. The recording specification permits individual delivered blobs that are not playable alone; select/test a container strategy and use bounded remux/transcode jobs where necessary. Scheduled `timeslice` intervals are not an exact clock. [Recording specification](https://www.w3.org/TR/mediastream-recording/), [dataavailable behavior](https://developer.mozilla.org/en-US/docs/Web/API/MediaRecorder/dataavailable_event).

Start with ordinary WebRTC transport encryption, not a claim of application-level E2EE through all forwarding/recording components. If E2EE is offered, the app must specify which endpoints hold keys; a server that lacks them cannot produce a plaintext recording. Browser recording ends if that browser disappears; server recording has different availability and trust semantics. Storage/relay/recording quotas are separate, and CDC savings on compressed media must be measured rather than assumed.

Bindings: room commands/query/follow, presence lease, attachment upload/read, call join/signal/leave, recording request/upload/finalize/status. Test reconnects, retries, codec negotiation, slow upload and disk-full cases. Acceptance: CHAT-01–CHAT-05.

## 3. Local-first todo boards using Automerge

### Model and editing contract

Use one Automerge document per small board, with its stream ID as stable Patchwork document identity, board membership, schema version, task map keyed by stable task IDs and order list. Task fields include text, completion, optional assignee/due date and explicitly typed attachment references. Keep membership/grants/quotas outside the CRDT: an editor cannot make themselves an administrator by changing JSON. All editors may edit the whole board initially; per-task private fields require separate documents/authorization boundaries.

Browsers use Automerge Repo with local persistence, so offline edits survive reload and reconnect. Patchwork provides an authorized network adapter/server peer and durable document storage integration. Automerge Repo separates storage adapters from network adapters; these contracts should be tested against a pinned actual release rather than inventing a superficially similar wire protocol. [Automerge repositories](https://automerge.org/docs/reference/repositories/).

### Three identities and two kinds of traffic

Document ID identifies the collaboration resource. Automerge heads/change hashes identify causal state. Patchwork stream position identifies durable acceptance order. None replaces the others, and an object root is a snapshot representation rather than a mutable document identity.

The adapter processes actual Automerge sync exchanges and persists validated document changes with deduplication scoped to document/change hash, transactional checkpoint metadata and explicit attachment roots. Session-specific sync frames are not a replayable application log; persisting arbitrary network messages is insufficient. Changes with missing causal dependencies are bounded/pending or rejected with a retry protocol, never acknowledged as incorporated state prematurely. Original accepted change bytes must not be transformed by a generic payload filter. Document validation and resource limits use the common authorization/commit fences.

Reconnect merges causal changes; it must not replace the server document with a last-writer-wins JSON snapshot or force every offline edit through a single reference CAS. Conflicting task-field edits use Automerge's pinned-version semantics and can be surfaced in the UI. CRDT convergence does not automatically enforce business invariants such as a unique assignee or an immutable completed task; avoid those constraints initially or add a deliberate validated-command design.

### Snapshots and compaction

A server adapter or explicitly trusted client produces a complete compatible saved CRDT document at Patchwork boundary P, including the causal information needed for old peers to merge. Restoring only the rendered JSON is invalid. Seed+suffix must match the live document; retain explicit typed attachment dependencies even where the saved binary contains opaque references. A generic prolly map can index document chunks/objects, but it does not merge Automerge state. Automerge Repo's own incremental/snapshot storage model and compaction rules must be reconciled with Patchwork's trim boundary, not blindly emulated as one overwritable blob per document. [Automerge storage](https://automerge.org/docs/reference/under-the-hood/storage/).

A revoked offline editor retains their local copy, but new sync reads/writes are denied after revocation. Keep their unaccepted edits locally with an export/recovery choice; do not silently discard them or promise remote erasure. Login switching must not expose one user's local IndexedDB documents to another account through the app UI; client cache policy needs explicit tests and cannot defeat malicious same-origin code.

With client-side encryption the server stores opaque changes and cannot act as a plaintext-validating Automerge peer. Clients perform causal validation/merge and publish encrypted snapshots under the [external acceptance policy](external-snapshots.md). Attachment dependencies remain declared or self-contained. Do not claim the plaintext server-adapter interoperability gate proves encrypted-client correctness.

Acceptance: TODO-01–TODO-05 plus SNAP-03/10 for the encrypted variant. Automerge interoperability and compaction remain gated.

## 4. Quotes: personal collection and deliberate sharing

### Core workflow and structure

A collection uses a stream or reference identity, owner/editor membership and server-validated commands. A quote has a stable ID, text, attributed author, source title/URL, tags and optional private notes. Use bounded plain text initially; render markup only through a deliberate sanitizer. Use one transactional KV key per quote for independent edits. If a command needs an atomic multi-key invariant, use a reference-backed immutable map and one CAS instead of adding a collection database. Choose and document that collection's authoritative model. Add author/tag/creation indexes as bounded derived materializations only when query needs justify them. A generic `list(prefix)` is insufficient for arbitrary combined filters; expose only supported indexed query shapes with bounded pagination.

Users create/edit/delete with idempotent commands and expected revisions, search/filter their collection, and choose quotes for sharing. Commands cannot forge owner identity or write control-plane grants. This is a deliberately simple server-authoritative app that tests useful application behavior without CRDT/media complexity.

### Public projection, not private-root sharing

Publishing creates a separate immutable collection root containing approved public fields, optionally published under a collection reference. The default share pins a snapshot; a live collection share explicitly follows approved publications. Private notes, draft entries, private source attachments and editor metadata are omitted from that tree entirely. Do not grant recursive access to the private root and merely hide fields in the frontend. A “public view” materializer must have a tested schema for exactly what it publishes.

Unpublish/revoke prevents new platform access, but previously downloaded/publicly cached material cannot be recalled. Publishing should distinguish truly public cacheable assets from access-controlled/expiring shares. A collection editor cannot widen a share beyond the owner's approved delegation rights.

Derived indexes expose their applied position; transactional read-your-write is preferred for the small initial app. If an async consumer is used, expose pending/stalled state and bounded minimum-position reads. Custom commands may use approved Functions through host-enforced predicates/transactions; no unrestricted user-supplied SQL is exposed. Fetching titles/previews from arbitrary source URLs remains deferred until the function connector/egress policy is implemented and tested.

Bindings: collection create, quote commands, bounded queries, watch hints, public projection publish and share administration. Acceptance: QUOTE-01–QUOTE-05. This is the recommended first fully hosted reference app because it exercises identity, bindings, data commands, indexes, publication and sharing with relatively few moving parts.

## Additional useful examples

**Release portal / static site:** Upload a directory tree, preview it against test resources, promote production using expected revision, and roll back code. Verify that a page loads all assets from its pinned release, API permissions cannot expand via a new manifest, and stale preview code never gets production credentials. This exercises directory structure and Apps hosting directly (EX-01).

**Shared photo album:** Upload originals, enqueue bounded thumbnail work under a service identity, publish a directory/projection of approved images and derivatives. Test duplicate job delivery, crash before/after result linking, malicious image inputs, metadata stripping policy, failed jobs and owner quotas. Deleting a public album root does not delete separately retained originals. Workers may be reviewed built-ins, explicitly operated services or approved function deployments once their job/codec/resource gates pass (EX-02).

**Submit-only intake form:** An anonymous visitor submits a response and optionally an attachment, but cannot enumerate/read earlier responses. The authenticated owner sees the materialization and update events. Test repeated request IDs, expired attachment leases, spam admission and no leaked submission data through success receipts, watch, or guessed IDs. This is a strong test of asymmetric permissions and guest app sessions (EX-03).

## Proposed acceptance cases

All cases are **specified only**. Use non-admin users and malicious/old clients, isolated storage, fake clocks and failure injection; verify server behavior rather than just UI hiding. Relate object tests to OBJ-01–OBJ-24 and base tests to the A/P/B/E/G cases in [core conformance](conformance.md).

| ID | Scenario | Acceptance |
| --- | --- | --- |
| APP-01 | App requests unapproved resource; app A calls B's gateway; manifest requests expanded permission | Server denies; deployment does not self-grant; user credentials remain isolated |
| APP-02 | Promote twice while an old tab lazy-loads assets; run GC before/after the seven-day window; exhaust app quota; preview promoted; code rollback | Pinned old assets remain byte-coherent during the window; promotion fails atomically if retention quota cannot be reserved; expired versioned URLs return 410 even if blocks remain; old-tab gateway compatibility or reload is explicit; preview bindings stay isolated; data not silently reverted |
| APP-03 | Forged owner/actor/service fields, stale membership revision, revoked browser session | Identity derived from session; commit fence and bounded active-work refresh; no worker authority leaked |
| APP-04 | Fresh SSH session handed to trusted UI; attenuated API credential exchanged for app session; guest attempts general minting | Shared cookie implementation preserves origin/audience/grant ceiling; only direct fresh SSH handoff retains mint provenance; app/guest exchange cannot widen or mint |
| APP-05 | Public frontend root traversed; uploaded HTML rendered; private route cached | No backend artifact/secret exposure; content-origin isolation; private/expiring data cannot bypass checks via cache |
| APP-06 | Domain released/rebound; stale cookie, callback, service worker or Host used | Ownership reverified; old sessions/routes fenced; no new-owner identity confusion; explicit lifecycle policy |
| FILE-01 | Expiring root share redeemed immediately before/after expiry; owner edits original directory | Frozen root unchanged; server clock decides admission; expiry/revocation stops new server batches; existing copies remain |
| FILE-02 | Concurrent last-use redemption and parallel ranged downloads under a byte limit | Atomic reservation; no oversubscription; retries session-bound; repeated transmitted bytes accounted; no double refund after crash |
| FILE-03 | Upload exceeds per-user quota, same content exists under another user, share expires | Reservation enforced without existence disclosure; logical vs physical accounting distinct; other roots preserved |
| FILE-04 | Direct connection succeeds/fails, forced TURN fallback, sender disconnects, resume from verified chunks | Correct direct/relayed/unavailable state; bytes match manifest; no silent hosted durability claim; backpressure bounded |
| FILE-05 | Enforceable-limits share requests P2P; revoke ongoing relay allocation | Direct mode refused; relay shutdown/accounting bound measured; no claim that server terminates already-established direct peers |
| CHAT-01 | Duplicate send, reconnect gap, concurrent edit/delete and materializer stall | One logical command result; ordered catch-up; correct permissions/revisions; visible pending/stalled state |
| CHAT-02 | Member removed during attachment upload/download or call join | No new authorized links/joins/batches after fence/refresh; orphan upload leased; previously delivered content not recalled |
| CHAT-03 | NAT/firewall matrix, media congestion, one-to-one then bounded group call | Negotiation/fallback works; clear unsupported codecs/topologies; bounded load; no use of durable event log for media frames |
| CHAT-04 | Recorder/browser crashes, duplicate/out-of-order piece upload, disk full during finalization | Acknowledged pieces survive; explicit partial/failed status; no fake ready object; retry doesn't duplicate manifest entries |
| CHAT-05 | Consent/membership changes; incompatible segments; encrypted media without recorder keys | Recording policy applied; final output playback tested; no recording claim without received/decryptable media |
| TODO-01 | Two offline devices edit/add/reorder tasks then reconnect | Library-consistent convergence, local reload persistence, no CAS overwrite/lost accepted changes |
| TODO-02 | Duplicate, out-of-order, cross-document and malformed/oversized sync changes | Doc-scoped dedup/auth; bounded causal buffering/failure; no spoofed actor privilege |
| TODO-03 | Snapshot/trim/restart followed by very old peer edits | Complete causal state restored; valid offline changes merge; attachment roots retained; JSON-only snapshots fail fixture |
| TODO-04 | Revoke offline editor, reconnect; switch browser account | Server denies new sync; local edits preserved/exportable; app does not expose previous account's cached board |
| TODO-05 | Automerge library/schema upgrade and snapshot builder failure | Compatible pinned fixtures or explicit incompatibility; no silent history loss or trim past failed adapter |
| QUOTE-01 | Concurrent edits/retried creates, tag queries over pagination | CAS/idempotency correct; stable bounded query results; supported filters explicit |
| QUOTE-02 | Publish quotes containing private notes/draft attachments; inspect raw shared root/diff | No private fields/dependencies in public graph; server authority required to expand published set |
| QUOTE-03 | Unpublish or expire share while another user is paging; public cached copy exists | New server access denied; cache/download limitation documented; no broad private-root grant |
| QUOTE-04 | Malicious quote text/source URL; spoofed owner or arbitrary query | Safe rendering; no implicit URL fetch; unauthorized command/query rejected |
| QUOTE-05 | Consumer lags/fails then rebuilds from compatible snapshot and suffix | Applied-position contract honored; visible stall; equivalent query state without replaying external effects |
| EX-01 | Release portal preview/promote/rollback and overlapping deploys | Directory reuse measured; one CAS winner; consistent assets; permission additions require approval |
| EX-02 | Thumbnail worker duplicate/crash/malicious input and shared derivative GC | Scoped, bounded, idempotent processing; atomic result linking; no dangling or prematurely deleted roots |
| EX-03 | Guest form submitter tries list/read/watch and reuses another upload ID | Submit-only authority enforced; no unauthorized reads/linking; owner receives accepted submission once |

## Design conclusions and build sequence

The examples require more than generic storage calls. Add/review these platform contracts before claiming that a generated frontend can implement them safely:

| Missing contract | Why it is necessary | Roadmap task |
| --- | --- | --- |
| Apps deployment/session/binding boundary | Hosting code must not inherit all visitor/admin authority | R-01 |
| Share grants, redemption and usage reservations | Expiry and per-user/per-use limits require atomic server state | R-02 |
| Bounded structured commands, queries and projections | Ownership checks and useful indexes cannot live only in UI code | R-03 |
| Rendezvous, TURN integration and media sessions | Browser P2P fallback and media are separate from durable streams | R-04 |
| Recording jobs and typed manifests | Media delivery is not durable playable recording | R-05 |
| Document-aware Automerge adapter and causal snapshots | Generic snapshots/prolly merge do not implement CRDT sync | R-06 |
| Non-admin end-to-end app fixtures | Prove usable APIs plus adversarial behavior | R-07 |
| Shared function execution and safe application transactions | Custom endpoints/consumers need profile-specific authority, predicate tracking, retries and effects | S-01–S-07 |

Recommended app sequence after object/auth foundations: **Quotes -> hosted file shares -> Automerge todos and text chat -> P2P files/one-to-one video -> group media/server recording**. Use release-portal and guest-form cases throughout to exercise hosting/permissions. Media/CRDT gates do not block the initial service or simpler platform fixtures. R-01 and R-02 designs can inform O-01 and authorization work now; prototypes remain bounded and isolated.

Design review sources: [Automerge repositories](https://automerge.org/docs/reference/repositories/), [Automerge storage](https://automerge.org/docs/reference/under-the-hood/storage/), [WebRTC protocols](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Protocols), [TURN RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html), [MediaStream Recording](https://www.w3.org/TR/mediastream-recording/), [MediaRecorder timing](https://developer.mozilla.org/en-US/docs/Web/API/MediaRecorder/dataavailable_event). Actual versions, browser compatibility, transport revocation bounds and media/CRDT benchmarks are untested gates.

# Retrospective

Written 2026-10-02, when this branch was archived. The branch is the Rust redesign of Patchwork (September 2026). The deployed service is the Go relay, which lives on `main` (formerly `legacy`). Nothing here is maintained. This page records what was built, what was learned, and where the work went.

## Why it stopped

The redesign followed one platform idea after another: streams and objects, then resource kinds, then owned resources with a global grant model, then an account platform, then a serverless runtime, then an S2-compatible gateway. Each step was reasonable on its own, but none of them was needed by a running use case. When the use cases were listed concretely ([use cases](use-cases.md)), the platform turned out to have no customer:

- **Vulcan (U1)** is the only case that needs real-time fan-out to many semi-anonymous subscribers. It only needs that because forges offer no event subscription API. The Go relay has served it without problems. If a forge ever offers native push events, Vulcan should use them and the relay can retire.
- **Other webhooks** feed into a specific system. That system should own its endpoint, verify the signature, and filter and reshape the payload in its own code. A generic proxy with a filter language sits between the two and is needed by neither.
- **Automerge apps (U2–U4)** own their users (OIDC, SCIM, invitation links) and their sync. One app server per app, built from a shared template, is simpler than a generic document service with its own authorization layer. The recipe plan already noted that a generic sync server "failed on the auth part" once before.
- **Scripts (U5–U7)** need streams and blobs. Existing servers (S2-style streams, S3-style objects) cover that, provided there is scoped token management in front of them.

The lesson: design from a running use case to the smallest thing that serves it, and stop there. A platform is justified by the second and third concrete customers, not by the first idea.

## Where the work went

| Need | Decision | Home |
| --- | --- | --- |
| Vulcan wake-ups | Keep the Go relay; clean it up, add tests | `main` branch of this repository |
| Small webhook handlers and misc jobs | One plain app server, one route per job, no plugin system | `hooks-server` (new project) |
| Streams for scripts and apps | s2-lite behind a token proxy that issues, checks and revokes scoped tokens | `s2-token-proxy` (new project) |
| Objects for scripts and apps | An existing S3 server with native keys (Garage or similar) | Ansible repository |
| App servers (OIDC, SCIM, Automerge sync) | A deployment convention and template, extracted when the second app is built | Ansible repository plus app repositories |
| Serverless functions, webhook proxy with CEL | Dropped | - |

The prompts handed to the infrastructure agent are in [handoff prompts](handoff-prompts.md).

## What this branch built

About 7,500 lines of Rust and 60 integration tests, all passing at archive time (`cargo test --locked --all-targets`). [Implementation status](implementation-status.md) lists the evidence per feature.

- SQLite (WAL, `synchronous=FULL`) retained and live streams with retention, idempotency receipts, follow, live and watch subscriptions over SSE.
- Biscuit 6.0 credentials with offline attenuation, a typed allow-only grant model, revocation, and SSH (SSHSIG) login.
- URL-transport credentials (V-01): kind `api_url`, a `?token=` query parameter lifted into the `Authorization` header by middleware before any handler runs, at most 16 grants that are either append-only or read/subscribe-only, a separate lifetime cap, `Referrer-Policy: no-referrer`, and rejection of a token sent both ways.
- Stream-derived KV with conditional writes, GitHub HMAC webhook ingress with durable receipts, and online backup with identity-preserving restore.

Pieces worth reusing, especially for `s2-token-proxy`:

| Piece | File |
| --- | --- |
| Biscuit token format, verification, attenuation | `src/auth/token.rs`, `src/auth.rs` |
| Credential minting, lifetime caps, revocation | `src/store/identity.rs` |
| URL-token lifting middleware and its rules | `src/http/data.rs` (`lift_url_token`), `tests/url_transport.rs` |
| SSH signature login | `src/auth/ssh.rs` |
| HMAC webhook verification and receipts | `src/store/hooks.rs`, `src/http/data/hooks.rs` |
| Long-lived subscriptions (follow, live, watch) | `src/http/data/subscriptions.rs` |

## Findings worth keeping

### Vulcan and Forgejo

- Vulcan treats any 2xx response to its subscribe GET as a wake-up. An idle timeout must therefore return a non-2xx status (408 was the plan), never 2xx.
- Subscribers hold only a URL and cannot send headers. The subscribe URL may be visible to every reader of the repository, so it must be a separate secret from the publish URL, and its credential must not allow publishing.
- Forgejo sends `X-Forgejo-Signature` (HMAC-SHA256 of the body; whether it carries a `sha256=` prefix was not confirmed), `X-Forgejo-Event` and `X-Forgejo-Delivery`, plus GitHub, Gitea and Gogs aliases. It can also send a configured `Authorization` header. Its retry and timeout behavior is undocumented, so answer quickly with a 2xx.
- Vulcan pushes its own `refs/vulcan/notifications` ref. A webhook for that push only causes a redundant, harmless reconciliation.

### Credentials in URLs

Bearer tokens in query strings are acceptable when the credential is narrow and single-purpose: one action class, a bounded stream or prefix scope, its own kind so it cannot be confused with a session or admin credential, revocable, and stripped from the request before logging or handlers see it. Session and admin credentials in a URL are refused. Details are in [authorization](authorization.md) and decisions D37–D46 in [decisions](decisions.md).

### S2 and s2-lite

s2-lite (MIT, Rust, SlateDB, local disk supported) has no access control; its documentation says to gate it with your own auth layer. Hosted S2 tokens support exact and prefix scopes, expiry, revocation and auto-prefixing. A proxy that reproduces that model in front of s2-lite is the `s2-token-proxy` project. Neither offers listening to many streams over one connection, which matters for stream-triggered work.

### Filter and script runtimes

Measured on one development machine in September 2026. Sources are in `research/runtime-bench` at the repository root; numbers are indicative, not rigorous.

Warm evaluation of a filter over a 1.4 KB webhook event:

| Runtime | Per event |
| --- | --- |
| V8 | 9.8 µs |
| Starlark (frozen module, fresh heap per event) | 15 µs |
| Rune | 20 µs |
| QuickJS | 25 µs |
| Lua 5.4 | 41 µs |
| Steel | 76 µs |
| CEL (`cel` 0.14.5) | 91 µs |
| Boa | 242 µs |
| Javy (QuickJS in WebAssembly, isolated per event) | 275 µs |
| Jsonnet | 313 µs |
| QuickJS-NG, isolated per event | 343 µs |

Compute (fib(30) / 10M-iteration loop / 200k-element list, milliseconds):

| Runtime | fib(30) | loop | list |
| --- | --- | --- | --- |
| wasmtime | 9 | 17 | 0.9 |
| wasmtime with epoch interruption | 14 | 38 | 1.4 |
| wasmtime with fuel | 16 | 24 | 1.5 |
| V8 | 14.5 | 28 | 23 |
| LuaJIT | 20 | 23 | 3.7 |
| Lua 5.4 | 85 | 257 | 15 |
| Wren | 147 | 771 | 29 |
| QuickJS | 243 | 1032 | 60 |
| Starlark | 243 | 692 | 24 |
| Rune | 341 | 1843 | 77 |
| Steel | 372 | 2895 | 131 |
| Boa | 781 | 941 | 221 |

Stopping runaway code:

- **Hard limits work:** QuickJS (interrupt handler and memory limit), Lua 5.4 (instruction hook), Rune, wasmtime (epoch or fuel), V8 (`terminate_execution`).
- **Best effort:** Starlark.
- **Weak or none:** Boa (iteration cap only); LuaJIT (the hook did not fire inside a JIT-compiled loop); Steel, Wren, Jsonnet and CEL (no effective limits).

Further findings from a separate review:

- The Starlark Rust crate has about 815 `unsafe` sites, so it is hermetic but not a security boundary.
- Javy needs a 45 MB toolchain and about a second to compile each script.
- Rhai is viable but slower than the leaders.
- The `cel` crate has no type check at save time and no cost limit, and some expressions are superlinear: `list.map(a, list)` took 4.2 s at n=400.

Conclusion at the time: for trusted filters, Starlark or QuickJS. For untrusted or hot-path code, WebAssembly via wasmtime, which is the fastest and has hard limits, at the cost of a compile step for the author. In the end nothing needed it.

## Documents on this branch

The design documents ([design](design.md), [roadmap](roadmap.md), [decisions](decisions.md), [use cases](use-cases.md)) are left as they were at the last redesign step, including the open questions they raise. They describe a direction that was abandoned. Read them as history, not as plans.

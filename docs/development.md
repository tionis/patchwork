# Rust development

## Authenticated loopback prototype

Run `./scripts/prototype-demo.sh` from the repository root for an isolated demonstration. It builds the binaries, creates temporary keys/data, signs in, round-trips binary bytes and verifies read-only enforcement. It stops its server and prints the retained data/log directory. Requires Rust 1.98.1, a native C/C++ toolchain with CMake, OpenSSH tools and Python 3. Credentials are never printed.

For an interactive instance, build with `cargo build --locked --bins`, use a fresh private data directory, and bootstrap its intended origin:

```bash
./target/debug/patchwork admin bootstrap \
  --data-dir /tmp/patchwork-local \
  --ssh-public-key "$HOME/.ssh/id_ed25519.pub" \
  --origin http://127.0.0.1:8080
./target/debug/patchwork-server --data-dir /tmp/patchwork-local \
  --listen 127.0.0.1:8080 --data-api
```

In another terminal:

```bash
./target/debug/patchwork login --url http://127.0.0.1:8080 \
  --ssh-key "$HOME/.ssh/id_ed25519" \
  --ssh-public-key "$HOME/.ssh/id_ed25519.pub" \
  --output /tmp/patchwork-local/session
./target/debug/patchwork stream --token-file /tmp/patchwork-local/session create events/demo
```

Use the returned `str_…` ID with `append ID` (binary stdin), `read ID --from 0` (JSON/base64), or `get ID 0` (exact binary stdout). Connection flags `--token-file` and `--url` go after the top-level stream/token command, or alongside append/read/follow options. Run each command with `--help` for placement. Credential files use exclusive creation and mode 0600; choose a new output path for each login. Agent-backed login uses the public-key path as `--ssh-key` with its key loaded in ssh-agent.

## Authentication and administration

SSH sessions last 15 minutes. `token mint --scope-file FILE --output FILE --lifetime-seconds 3600` requires a fresh unattenuated SSH session and current delegation authority. API credentials cap at one day (or the configured lower policy limit). A scope file is an array, for example `[{"actions":["record.read"],"selector":{"kind":"prefix","value":"events/"}}]`. Exact stream selectors use `{"kind":"stream","value":"str_…"}`; instance administration uses `{"kind":"instance","value":"INSTANCE_UUID"}`. Nonempty prefixes end with `/`; an empty prefix explicitly matches all canonical names. Old credential ceilings do not expand when principal grants expand.

`token whoami`, `token list`, and `token inspect` return structured information without bearer secrets; inspect is local and explicitly unverified. Administrative principal lists and token lists accept `--after ID --limit N`; stream lists accept their opaque `--cursor`. Replay accepts `--max-bytes N`. `token attenuate --read-only --stream ID --expires-at 2027-01-01T00:00:00Z --output FILE` appends checks offline. Holding the parent still gives its original authority. `token revoke ID` invalidates that root and its descendants. An API token or attenuated session cannot mint a replacement credential.

`admin principals --token-file FILE list` lists principal descriptors. Create/update accept `--file` JSON containing `ssh_public_key`, `enabled`, `can_mint`, and `grants`; update also takes the principal ID and `--revision N`. Disabling a principal fences its credentials. The last enabled administrator cannot be removed through the API. `admin policy --token-file FILE` reads the lifetime policy; add `--file FILE --revision N` for replacement. Administrative changes write audit rows.

For lost administrator access, stop the server and run `patchwork admin recover --data-dir DIR --ssh-public-key FILE`, then restart and log in. This explicit local filesystem-authorized operation restores that key's administrator access and emits an audit descriptor. It preserves other credentials and their issuance ceilings; it is not blanket credential revocation or issuer rotation. There is no HTTP recovery endpoint.

## Streams, processing and retries

`stream list --prefix events/`, `stream resolve NAME`, `stream show ID`, and `stream delete ID --config-revision N` cover discovery and lifecycle. `stream config ID` and `stream metadata ID` return JSON with the ETag and value; add `--file FILE --revision N` to replace. Revisions are independent, and delete/recreate changes the ID. Metadata uses `{"value":{...},"object_refs":[]}`; nonempty object references and unsupported config fields fail.

Config JSON uses decimal strings for byte/age bounds. For example:

```json
{
  "retention": {"mode":"bounded", "max_bytes":"10485760", "max_age_seconds":"3600"},
  "max_record_bytes":"1048576",
  "filters":[{"kind":"uppercase_ascii"}],
  "validators":[{"kind":"utf8"}]
}
```

Pass this with `stream create NAME --config-file FILE`, or replace an existing retained stream's config. Retention also supports `infinite` and `none`; retained/none transitions are rejected. Plain bounded streams trim by age or bytes in bounded batches; a record larger than the retention byte target may be trimmed immediately. No snapshot/recovery attachment can be configured yet.

Filters run in order: `uppercase_ascii`, `prepend`, `drop_if_contains`, `reject_if_contains`; byte literals use `data_base64`. Validators inspect final bytes: `utf8`, `json`, `content_type` with `value`, and `max_bytes` with an integer `value`. Limits are 16 filters, 16 validators, 4 KiB literals and a 100 ms processing deadline. A deliberate drop allocates no position; rejection/config/auth failures are errors.

`append ID --idempotency-key KEY --content-type text/plain` persists a retained outcome for 24 hours, keyed by stream, authenticated principal, endpoint and key. Retry identical original bytes/content type with the same key after transport uncertainty; another payload conflicts. The receipt survives payload trimming, changed pipelines, a fresh session for the same principal, and restart. Replay always rechecks current authority. Unkeyed retries can append twice. Live publication rejects idempotency keys.

`admin creation-rules --token-file FILE` reads the default and longest-prefix templates. Each template has `allow_append` and concrete `config`; rules add `prefix`. Replace with `--file FILE --revision N`. `append-named NAME` can create only when the selected rule enables it and both create and append grants permit it. A drop/reject leaves an absent name absent. Creation/config races return conflicts and can be retried; reads never create streams.

## Follow, live and watch

`follow ID --from N` replays retained records and waits for new ones. `--last-event-id STREAM_ID:NEXT_POSITION` resumes after the last delivered record; inconsistent simultaneous cursors fail. Trimmed history returns 410 before admission or a terminal `history_lost` event afterward. The server holds at most one retained record per polling subscription, with no long-lived database transaction.

For a stream configured with `{"mode":"none"}`, `live ID` receives a ready event containing process epoch and sequence, then ephemeral records. Restart changes the epoch; no replay cursor exists. Queues hold eight records and overflow closes with `lagged`. `watch --prefix events/` or repeated `watch --stream ID` returns hints only, without payload or metadata. All explicit IDs must be authorized; prefix watch requires universal prefix authority and an unattenuated token. Use an explicitly scoped server-issued token for prefix watch. Subscriptions reauthorize before batches and at least every second while idle, and close on revocation/deletion. CLI streams SSE to stdout and exits nonzero for terminal error events.

## HTTP, bounds and deployment

Repository-root `openapi.json` is the implemented OpenAPI 3.1 contract. Canonical data routes start with `/v1`; earlier root aliases remain compatible. Config/metadata/admin replacement uses ETag/If-Match. Positions, revisions and byte bounds are decimal strings; acceptance and expiry timestamps are RFC3339. Errors are problem JSON with a safe request ID and no-store caching.

The server requires loopback binding for data mode. The CLI accepts verified HTTPS origins and loopback HTTP; redirects are disabled. A TLS reverse proxy can front the loopback server: bootstrap the intended HTTPS origin, preserve `/v1`, and disable response buffering for SSE. Forwarded IP headers are deliberately not trusted, so proxy traffic shares the proxy peer's login budget. Public deployment still requires capacity/security review. Default startup without `--data-api` exposes only healthz/readyz; data mode requires prior bootstrap.

Admission bounds are 64 in-flight requests before body extraction, a 10-second request/upload deadline, 32 blocking operations and 128 subscriptions. Login has fixed 60-second windows of 32 requests per socket peer and 256 globally, a bounded peer map, five exchange attempts per challenge, and 128 pending challenges. A 429 includes Retry-After. General bodies/records cap at 1 MiB; metadata at 64 KiB; replay at 1–1000 records and 1 byte–16 MiB, with one oversized-for-the-page record permitted for progress. Tokens cap at 32 KiB/eight blocks, 1,000 initial/derived facts, 100 iterations and 50 ms Datalog execution. These bounds are not service throughput guarantees.

Ctrl-C/SIGTERM marks readiness false, stops subscription work and drains for at most five seconds. Logs omit payloads and bearer secrets. Readiness reports completed startup, not continuous disk health. Logical deletion retains storage rows; retention reuses SQLite pages but does not automatically shrink the file.

## Verification and measurements

Run from the repository root:

```bash
cargo build --locked --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo run --locked --release --example auth-benchmark -- 100
vulcan --vault docs --output json doctor --fail-on-issues
```

The benchmark prints CPU/profile/limits and a 1/8/32-block × 10/100/1000-extra-fact matrix with p50/p95/p99, throughput and Linux process cumulative peak RSS. Thirty-two blocks and more than 1,000 total facts are intentional rejection cases. The metric includes signature parsing plus one attenuation decision, not the entire HTTP/SQLite command path. The malformed-token corpus is a reproducible regression test, not a sustained fuzz campaign. `prototype_process` tests binary CLI I/O, scoped tokens, admin commands, keyed retries after a hard restart, recovery and shutdown with a follow; storage/subscription tests cover concurrency, CAS, pipeline/retention receipts, live overflow and revoked readers. These checks do not certify arbitrary power loss or production capacity.

The toolchain and lockfile are pinned. First builds need dependency downloads; cached builds support `--offline`. CI is configured but local runs do not prove remote CI passed. The upstream proc-macro-error2 future-compatibility warning remains. See [implementation status](implementation-status.md) and [roadmap](roadmap.md) for release gates and later services.

Use private data directories. Do not copy only an active SQLite main file as a backup. `patchwork backup` and `patchwork restore` cover the database (stage 1); deployment certification and schema upgrades remain future work. Pre-release schema changes edit migration 0001 in place (D29); recreate old development directories. No conversion is performed. The wiki uses Vulcan; use [index](index.md) for design navigation and `vulcan --vault docs --output json doctor --fail-on-issues` after documentation changes.

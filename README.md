# Patchwork

Patchwork is a small HTTP relay for connecting two requests as a live byte
stream. It is inspired by [patchbay.pub](https://patchbay.pub/) and
[duct](https://github.com/schollz/duct), and is particularly useful as a
webhook receiver when the real consumer is behind NAT or only runs on demand.

Patchwork does not store relay bodies. A queue producer and consumer rendezvous,
then bytes flow directly from the producer request to the consumer response with
end-to-end backpressure. Cancellation on either side tears down the transfer.

## Quick start

Builds use the vendored dependency tree and Go 1.26.2:

```bash
go build -mod=vendor -o patchwork .
SECRET_KEY="$(openssl rand -hex 32)" ./patchwork start --port 8080
```

In separate terminals, connect a consumer and producer:

```bash
curl --no-buffer http://localhost:8080/public/events
curl --data-binary @payload.json http://localhost:8080/public/events
```

Either side may arrive first. Both requests remain open until they are paired
and the body has been consumed. There is no offline message queue.

## Relay modes

### Queue

Queue mode is the default. Each producer is paired with exactly one consumer.
All of these select queue behavior:

```text
/public/name
/public/queue/name
/public/./name
```

Producers use `POST`, `PUT`, or `PATCH`; consumers use `GET`. The legacy `/p/`
prefix is an alias for `/public/`. A GET with a non-empty `body` query parameter
acts as a small producer for shell and browser use:

```bash
curl 'http://localhost:8080/public/demo?body=hello'
```

### Pub/sub

Pub/sub sends one live body stream to every subscriber already waiting when the
publisher starts:

```bash
curl --no-buffer http://localhost:8080/public/pubsub/events
curl --no-buffer http://localhost:8080/public/pubsub/events
curl -d event http://localhost:8080/public/pubsub/events
```

`/public/./events?pubsub=true` is equivalent. A subscription receives one
publication and then closes. A publisher with no current subscribers succeeds
without publishing or retaining the body. Memory use is bounded; the slowest
connected subscriber applies backpressure while disconnected subscribers are
removed independently.

## Webhook hooks

`GET /h` and `GET /r` create an unguessable channel name and a deterministic
HMAC secret. `SECRET_KEY` must remain stable across restarts if existing hook
URLs should remain valid.

Forward hooks protect the producing side:

```bash
hook=$(curl -s http://localhost:8080/h)
# Read `channel` and `secret` from the JSON response.

# Public consumer, normally kept connected before the webhook arrives:
curl --no-buffer http://localhost:8080/h/CHANNEL

# Protected producer URL configured at the webhook source:
curl --data-binary @event.json \
  'http://localhost:8080/h/CHANNEL?secret=SECRET'
```

Reverse hooks protect the consuming side:

```bash
curl -d event http://localhost:8080/r/CHANNEL
curl --no-buffer 'http://localhost:8080/r/CHANNEL?secret=SECRET'
```

Hook secrets are accepted only in the `secret` query parameter. Request logs
record query parameter names, not values.

Delivery mode is sender-selected per producer request:

- `mode=queue` (default): block until exactly one consumer takes the message.
- `mode=pubsub`: fan out to all currently waiting consumers; succeed
  immediately with the message dropped when none are waiting. The legacy
  `?pubsub` flag is equivalent.

Consumers just `GET` the channel with no mode parameter and accept whichever
mode the producer chose:

```bash
curl --no-buffer http://localhost:8080/h/CHANNEL
curl --data-binary @event.json \
  'http://localhost:8080/h/CHANNEL?secret=SECRET&mode=pubsub'
```

`discard=true` on the producer drains and drops the body and delivers only
metadata (`Patch-Method`, `Patch-Uri`, `Patch-H-*`) with an empty body. Use it
for notify-only pings or payloads the relay should not see. Combined with
`mode=pubsub` it is a fire-and-forget ping that succeeds even with no
consumer waiting.

## Relayed HTTP metadata

The consumer receives the original request body plus:

- `Patch-Method`: the exact producer method.
- `Patch-Uri`: the exact producer path and query string.
- Every end-to-end request header under its original name, including repeated
  webhook signature headers and `Authorization`.

Connection-specific and framing headers are discarded. This includes headers
named by `Connection`, `Content-Length`, `Transfer-Encoding`, and `Upgrade`.
Patchwork owns response framing and flushes chunks as they arrive.

`Patch-Uri` can contain credentials supplied in the producer URL. Treat relay
consumers as trusted data-plane peers even though Patchwork redacts those values
from its own logs.

## Request/response rendezvous

Paths below `/req/` and `/res/` form a paired exchange. A requester first sends
its body on `/req/name`, then waits for a stream on `/res/name`.

A regular responder can predeclare a fixed response while waiting for a request:

```bash
# Start first. The body and controls become the eventual requester response.
curl -H 'Patch-Status: 201' -H 'Patch-H-X-Result: created' \
  -d '{"created":true}' http://localhost:8080/public/res/create

curl -d '{"name":"example"}' http://localhost:8080/public/req/create
```

Use switch mode when a worker must inspect the request before constructing a
response:

```bash
# Requester; blocks for the final response.
curl -d '{"task":"build"}' http://localhost:8080/public/req/jobs

# Worker selects a temporary response channel. Its response contains the
# request body and the relayed Patch-Method, Patch-Uri, and Patch-H-* metadata.
curl -d worker-42 'http://localhost:8080/public/res/jobs?switch=true'

# Worker posts the computed response. Only these explicit controls are decoded
# into the original requester's response.
curl -H 'Patch-Status: 202' -H 'Patch-H-X-Worker: worker-42' \
  -d accepted http://localhost:8080/public/worker-42
```

`Patch-Status` must contain exactly one status from 200 through 599.
`Patch-H-Name` supplies a final response header. Invalid or unsafe metadata is
rejected before a regular responder can claim a request. Switch workers time out
after 30 seconds by default and produce a 504 response.

## User namespaces

`/u/{username}/...` is optional and backed by the local sqlite identity
store. Supply a token using `Authorization: Bearer TOKEN`; an omitted token
selects a literal token named `public`. Users, tokens, and notification
backends are managed through the admin API (see below) instead of files in
git repositories.

```bash
# Bootstrap the first admin (uses PATCHWORK_DB_PATH, default ./patchwork.db)
patchwork admin create --username alice --admin

# Then issue tokens via the admin API, e.g.
curl -b session-cookie -X POST http://localhost:8080/api/v1/users/alice/tokens \
  -d '{"name":"webhook-client","patterns":{"POST":["/incoming/*","/_/ntfy"]}}'
```

Permissions use OpenSSH-style pattern lists and are selected by HTTP method
(`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, plus `huproxy` targets). Token
lookups hit the local database on every request, so revocation takes effect
immediately — there is no cache to invalidate.

See [configuration](docs/configuration.md) and
[notifications](docs/notifications.md) for the full formats.

## Admin API and WebUI

Token, user, notification, session, and group management lives behind a
versioned admin API under `/api/v1`, authenticated by WebUI sessions. The
WebUI at `/admin` (same binary) is a thin consumer of exactly this API.

Browser login uses Authentik OIDC when `PATCHWORK_OIDC_ISSUER` is set;
otherwise the API is driven with the bootstrap admin plus direct store
access. Inbound SCIM provisioning (`/scim/v2/...`) is an optional,
off-by-default capability for Users and Groups.

## HuProxy

`/huproxy/{user}/{host}/{port}` tunnels a TCP connection over a binary WebSocket
after checking the user's `huproxy` ACL:

```text
wss://patchwork.example/huproxy/alice/git.internal.example/22
Authorization: Bearer TOKEN
```

Only binary WebSocket messages are accepted. Tunnel cancellation closes both
the WebSocket and TCP sides so blocked reads do not leak connections.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | required | HMAC key for hook secrets |
| `PATCHWORK_DB_PATH` | `./patchwork.db` | sqlite identity store location (`0600`, plain file backup) |
| `H2C` | unset | Set to `true`/`1`/`yes` to serve HTTP/2 cleartext directly instead of HTTP/1.1 |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | unset | Serve HTTPS directly when both are set; Go negotiates HTTP/2 automatically. Mutually exclusive with `H2C` |
| `PATCHWORK_OIDC_ISSUER` | unset | OIDC issuer for WebUI login when set (plus `PATCHWORK_OIDC_CLIENT_ID`, `PATCHWORK_OIDC_CLIENT_SECRET`) |
| `PATCHWORK_SCIM_ENABLED` | unset | Set to `true` to enable inbound SCIM provisioning (requires `PATCHWORK_SCIM_TOKEN`) |
| `METRICS_TOKEN` | unset | Enables authenticated `/metrics` when set |
| `TRUSTED_PROXY_CIDRS` | unset | Comma-separated proxies trusted to supply client-IP headers |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN`, or `ERROR` |
| `LOG_SOURCE` | `false` | Include source locations in logs |

Only `SECRET_KEY` is required for a public or hook-only deployment.
Forwarding headers are ignored unless the direct network peer
belongs to `TRUSTED_PROXY_CIDRS`.

`GET /healthz` and `GET /status` are liveness endpoints. `/metrics` returns 404
unless `METRICS_TOKEN` is configured, then requires
`Authorization: Bearer METRICS_TOKEN`.

By default patchwork serves plain HTTP/1.1, which is correct behind a
TLS-terminating reverse proxy (the Quadlet/Fly layout). Admins serving it
directly can set `H2C` or `TLS_CERT_FILE`/`TLS_KEY_FILE` for HTTP/2-capable
endpoints; point `healthcheck --url` at the matching scheme in that case.

## Containers and Quadlet

Podman builds the image entirely from vendored dependencies. The default image
is native to the host; `container-push` builds and publishes an amd64/arm64 OCI
manifest:

```bash
make container-smoke REGISTRY=localhost
podman run --rm -p 8080:8080 \
  -e SECRET_KEY="a-long-random-secret" localhost/patchwork:latest
```

[`deployments/patchwork.container`](deployments/patchwork.container) is a
production-oriented system Quadlet example. Install it under
`/etc/containers/systemd/`, create the root-readable environment file it
references, then reload and start it:

```bash
sudo install -m 0644 deployments/patchwork.container /etc/containers/systemd/
sudo install -d -m 0750 /etc/patchwork
sudo install -m 0600 /dev/null /etc/patchwork/patchwork.env
sudoedit /etc/patchwork/patchwork.env
sudo systemctl daemon-reload
sudo systemctl enable --now patchwork.service
```

The environment file must contain `SECRET_KEY=...`. The Quadlet binds only to
loopback for a local reverse proxy, runs the image read-only with no added Linux
capabilities, performs application-level health checks, and uses Podman's
registry auto-update integration. Adjust `PublishPort` and `EnvironmentFile`
for a rootless user unit.

The process handles SIGINT and SIGTERM with graceful HTTP shutdown. Active
relays are canceled if they do not complete within the shutdown window.

## Development

The default verification suite formats, vets, runs shuffled race-enabled tests,
and enforces the coverage floor:

```bash
make verify
```

The relay stress target repeats its concurrency suite 100 times under the race
detector:

```bash
make test-stress
```

The tests cover live pre-EOF streaming, exact-once queue delivery, pub/sub
backpressure and disconnects, mid-transfer cancellation, shutdown, local
token validation/rotation/revocation, admin API guards, OIDC login against a
stub provider, SCIM provisioning, HTTP metadata validation, hooks,
notifications, metrics authentication, rate-limit spoofing and bounds, and
WebSocket/TCP tunnel lifecycle behavior.

## License

MIT

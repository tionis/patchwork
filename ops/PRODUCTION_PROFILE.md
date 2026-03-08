# Patchwork Production Profile

Fill and version this file per environment before first deployment.
The goal is to lock concrete values for release-blocking runtime policy.

## Identity and Access

- Service base URL:
- OIDC issuer:
- OIDC client ID:
- OIDC redirect URL:
- OIDC admin subjects:
- Bootstrap admin token policy:
  - Enabled for bootstrap only: yes/no
  - Rotation procedure documented: yes/no
  - Removal after initial token minting: yes/no

## Traffic and Limits

- Global rate limit RPS / burst:
- Per-token rate limit RPS / burst:
- HTTP read/write timeouts:
- Max expected concurrent SSE connections:

## Blob Policy

- Blob signing key source (secret manager path):
- Signed URL TTL:
- Blob GC interval:
- Blob GC grace period:

## SQLite Runtime and Extensions

- Build tags:
- Required compile options:
- cr-sqlite extension path:
- sqlite-vec extension path:
- sqlean extension path:
- sqlean module directory:

## Backup and Restore

- Backup schedule (timer/cron):
- Backup storage location:
- Retention window:
- Restore target procedure:
- Last successful drill date:
- Measured RTO:
- Measured RPO:

## Networking and Edge

- TLS termination location:
- Forwarded header policy:
- Cookie security validation complete: yes/no
- Firewall/network exposure scope:

## Monitoring and Alerting

- Prometheus scrape job:
- Alertmanager route for Patchwork alerts:
- Log pipeline rule for `blob gc sweep failed`:
- Disk usage alerts enabled:

## Release Control

- Release tag format:
- Changelog location:
- CI gate required (`make build-all`, `make test-sqlitedriver-ext`): yes/no

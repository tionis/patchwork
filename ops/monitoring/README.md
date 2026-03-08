# Patchwork Monitoring Baseline

This directory provides a minimal monitoring baseline for first deployment.

## Inputs

- Patchwork `/metrics` endpoint
- Node exporter metrics (host/disk)
- Optional blackbox probe for `GET /healthz`

## Included Rules

- `ops/monitoring/prometheus-rules.yml`
  - request error rate (`5xx`)
  - auth failure spikes (`401`/`403`)
  - rate-limit spikes (`429`)
  - unusually high active runtime workers
  - low disk free percent (requires node exporter)

## Blob GC Monitoring

Blob GC currently reports failures in service logs (`blob gc sweep failed`).
Until dedicated blob-GC Prometheus metrics are added, configure log-based alerting
in your log pipeline for this message and track blob directory growth via host
filesystem metrics.

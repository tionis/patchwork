#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

echo "[release-check] running build + extension checks"
make build-all
make test-sqlitedriver-ext

echo "[release-check] running go test suite"
go test ./...

echo "[release-check] running deploy smoke checks"
make smoke-first-deploy
make smoke-first-deploy-oidc

echo "[release-check] all checks passed"

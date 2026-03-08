#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <version>" >&2
  echo "example: $0 0.1.0" >&2
  exit 1
fi

VERSION="$1"
TAG="v${VERSION}"
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "working tree is not clean; commit/stash changes first" >&2
  exit 1
fi

if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null 2>&1; then
  echo "tag already exists: ${TAG}" >&2
  exit 1
fi

if ! grep -q "^## \\[${VERSION}\\]" CHANGELOG.md; then
  echo "CHANGELOG.md missing version section: ## [${VERSION}]" >&2
  exit 1
fi

ops/scripts/release-check.sh

git tag -a "${TAG}" -m "Release ${TAG}"
echo "created tag ${TAG}"
echo "next: git push origin main && git push origin ${TAG}"

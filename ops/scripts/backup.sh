#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${1:-${PATCHWORK_DATA_DIR:-}}"
BACKUP_ROOT="${2:-${PATCHWORK_BACKUP_DIR:-./backups}}"

if [[ -z "${DATA_DIR}" ]]; then
  echo "usage: $0 <data-dir> [backup-root]" >&2
  echo "or set PATCHWORK_DATA_DIR/PATCHWORK_BACKUP_DIR" >&2
  exit 1
fi

if [[ ! -d "${DATA_DIR}" ]]; then
  echo "data dir not found: ${DATA_DIR}" >&2
  exit 1
fi

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "sqlite3 CLI is required for consistent SQLite backups" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  HASH_CMD=(shasum -a 256)
else
  echo "sha256sum or shasum is required to generate backup checksums" >&2
  exit 1
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
snapshot_dir="${BACKUP_ROOT}/${timestamp}"
mkdir -p "${snapshot_dir}" "${snapshot_dir}/documents" "${snapshot_dir}/blobs" "${snapshot_dir}/blob-staging"

backup_started_epoch="$(date +%s)"

if [[ -f "${DATA_DIR}/service.db" ]]; then
  sqlite3 "${DATA_DIR}/service.db" ".backup '${snapshot_dir}/service.db'"
fi

if [[ -d "${DATA_DIR}/documents" ]]; then
  while IFS= read -r -d '' db_file; do
    name="$(basename "${db_file}")"
    sqlite3 "${db_file}" ".backup '${snapshot_dir}/documents/${name}'"
  done < <(find "${DATA_DIR}/documents" -maxdepth 1 -type f -name '*.sqlite3' -print0 | sort -z)
fi

if [[ -d "${DATA_DIR}/blobs" ]]; then
  cp -a "${DATA_DIR}/blobs/." "${snapshot_dir}/blobs/"
fi

if [[ -d "${DATA_DIR}/blob-staging" ]]; then
  cp -a "${DATA_DIR}/blob-staging/." "${snapshot_dir}/blob-staging/"
fi

{
  echo "created_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "data_dir=${DATA_DIR}"
  echo "backup_started_epoch=${backup_started_epoch}"
} >"${snapshot_dir}/metadata.env"

(
  cd "${snapshot_dir}"
  find . -type f ! -name 'SHA256SUMS' -print0 \
    | sort -z \
    | xargs -0 "${HASH_CMD[@]}" > SHA256SUMS
)

backup_finished_epoch="$(date +%s)"
duration="$((backup_finished_epoch - backup_started_epoch))"

echo "backup_created=${snapshot_dir}"
echo "backup_duration_seconds=${duration}"

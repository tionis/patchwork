#!/usr/bin/env bash
set -euo pipefail

BACKUP_SNAPSHOT="${1:-}"
TARGET_DATA_DIR="${2:-}"

if [[ -z "${BACKUP_SNAPSHOT}" || -z "${TARGET_DATA_DIR}" ]]; then
  echo "usage: $0 <backup-snapshot-dir> <target-data-dir>" >&2
  exit 1
fi

if [[ ! -d "${BACKUP_SNAPSHOT}" ]]; then
  echo "backup snapshot not found: ${BACKUP_SNAPSHOT}" >&2
  exit 1
fi

if [[ ! -f "${BACKUP_SNAPSHOT}/service.db" ]]; then
  echo "backup snapshot missing service.db: ${BACKUP_SNAPSHOT}" >&2
  exit 1
fi

mkdir -p "${TARGET_DATA_DIR}" "${TARGET_DATA_DIR}/documents" "${TARGET_DATA_DIR}/blobs" "${TARGET_DATA_DIR}/blob-staging"

restore_started_epoch="$(date +%s)"

cp -f "${BACKUP_SNAPSHOT}/service.db" "${TARGET_DATA_DIR}/service.db"
rm -f "${TARGET_DATA_DIR}/documents/"*.sqlite3

if [[ -d "${BACKUP_SNAPSHOT}/documents" ]]; then
  cp -a "${BACKUP_SNAPSHOT}/documents/." "${TARGET_DATA_DIR}/documents/"
fi

rm -rf "${TARGET_DATA_DIR}/blobs" "${TARGET_DATA_DIR}/blob-staging"
mkdir -p "${TARGET_DATA_DIR}/blobs" "${TARGET_DATA_DIR}/blob-staging"

if [[ -d "${BACKUP_SNAPSHOT}/blobs" ]]; then
  cp -a "${BACKUP_SNAPSHOT}/blobs/." "${TARGET_DATA_DIR}/blobs/"
fi
if [[ -d "${BACKUP_SNAPSHOT}/blob-staging" ]]; then
  cp -a "${BACKUP_SNAPSHOT}/blob-staging/." "${TARGET_DATA_DIR}/blob-staging/"
fi

restore_finished_epoch="$(date +%s)"
duration="$((restore_finished_epoch - restore_started_epoch))"

echo "restore_target=${TARGET_DATA_DIR}"
echo "restore_duration_seconds=${duration}"

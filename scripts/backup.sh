#!/bin/bash
# ==============================================================================
# GuardianMail AI - SRE Automated Encrypted Backup Script
# ==============================================================================
set -euo pipefail

# Configurations
MONGODB_URL="${MONGODB_URL:-mongodb://localhost:27017}"
DB_NAME="${MONGODB_DB_NAME:-guardianmail}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
BACKUP_PASSWORD="${BACKUP_PASSWORD:-SuperSecureBackupPassword2026!}"
RETENTION_DAYS=7

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
TEMP_ARCHIVE="${BACKUP_DIR}/tmp_${DB_NAME}_${TIMESTAMP}.archive"
FINAL_ENC_BACKUP="${BACKUP_DIR}/${DB_NAME}_backup_${TIMESTAMP}.archive.enc"

# Ensure backup directory exists
mkdir -p "${BACKUP_DIR}"

echo "Starting automated database dump for database: ${DB_NAME}..."

# 1. Perform gzip-compressed mongodump archive extraction
if ! mongodump --uri="${MONGODB_URL}" --db="${DB_NAME}" --archive="${TEMP_ARCHIVE}" --gzip; then
    echo "ERROR: mongodump operation failed." >&2
    exit 1
fi

# 2. Encrypt the backup archive using OpenSSL AES-256
echo "Encrypting the backup archive..."
if ! openssl enc -aes-256-cbc -salt -pbkdf2 -in "${TEMP_ARCHIVE}" -out "${FINAL_ENC_BACKUP}" -pass pass:"${BACKUP_PASSWORD}"; then
    echo "ERROR: OpenSSL backup encryption failed." >&2
    rm -f "${TEMP_ARCHIVE}"
    exit 1
fi

# Clean up unencrypted temporary archive
rm -f "${TEMP_ARCHIVE}"

echo "SUCCESS: Backup completed. Encrypted archive: ${FINAL_ENC_BACKUP}"

# 3. Enforce SRE retention policy: delete files older than configured days
echo "Cleaning up backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -name "${DB_NAME}_backup_*.archive.enc" -type f -mtime +"${RETENTION_DAYS}" -exec rm -f {} \; -print

echo "SRE Backup job completed successfully."

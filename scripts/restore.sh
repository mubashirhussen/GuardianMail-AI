#!/bin/bash
# ==============================================================================
# GuardianMail AI - SRE Automated Decrypted Restore Script
# ==============================================================================
set -euo pipefail

# Configurations
MONGODB_URL="${MONGODB_URL:-mongodb://localhost:27017}"
BACKUP_PASSWORD="${BACKUP_PASSWORD:-SuperSecureBackupPassword2026!}"

# Parameter check
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 /path/to/backup_file.archive.enc" >&2
    exit 1
fi

ENC_BACKUP_FILE="$1"
TEMP_DECRYPTED="tmp_restore_decrypted.archive"

if [ ! -f "${ENC_BACKUP_FILE}" ]; then
    echo "ERROR: Encrypted backup file does not exist: ${ENC_BACKUP_FILE}" >&2
    exit 1
fi

echo "Decrypting database archive backup..."
# 1. Decrypt AES-256 encrypted archive using OpenSSL
if ! openssl enc -d -aes-256-cbc -pbkdf2 -in "${ENC_BACKUP_FILE}" -out "${TEMP_DECRYPTED}" -pass pass:"${BACKUP_PASSWORD}"; then
    echo "ERROR: OpenSSL decryption failed. Check password credentials." >&2
    exit 1
fi

echo "Initiating database restoration (database will be dropped and recreated)..."
# 2. Run mongorestore
if ! mongorestore --uri="${MONGODB_URL}" --archive="${TEMP_DECRYPTED}" --gzip --drop; then
    echo "ERROR: mongorestore database execution failed." >&2
    rm -f "${TEMP_DECRYPTED}"
    exit 1
fi

# Clean up decrypted temporary archive
rm -f "${TEMP_DECRYPTED}"

echo "SUCCESS: Database restoration completed successfully."

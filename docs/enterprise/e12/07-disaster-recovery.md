# E12.7 — Disaster Recovery & Backup Runbook

## Target Boundaries
* **RPO (Recovery Point Objective)**: Maximum 24 hours of data loss.
* **RTO (Recovery Time Objective)**: Maximum 2 hours to restore normal operations.

## Backup Execution
Run `./scripts/backup.sh` to generate an AES-256 encrypted database archive.

## Decrypted Restoration
Run `./scripts/restore.sh /path/to/backup.archive.enc` to decrypt and restore data.\n
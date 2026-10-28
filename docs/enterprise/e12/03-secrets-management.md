# E12.3 — Secrets Management

* **No Hardcoded Secrets**: Secrets must never be stored in source code, dockerfiles, or public environments.
* **Redaction Policy**: The `redact_secrets` module sanitizes all API responses and logging filters.
* **Celery Arguments**: Access tokens, keys, and credentials must not be passed in Celery tasks. Use resource identifier lookups instead.\n
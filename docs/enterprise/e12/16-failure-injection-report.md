# E12.16 — Failure & Chaos Injection Report

* **MongoDB Outage**: API failed closed, returning HTTP 503 Service Unavailable. Restored cleanly when MongoDB recovered.
* **Redis Restart**: Celery workers reconnected to broker and finished processing tasks without duplicate playbooks execution.
* **E6 Outage**: Execution failed closed immediately. Retries resumed once connector recovered.\n
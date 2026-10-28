# E12.11 — Alerting & Escalation Runbook

## Trigger Levels
* **CRITICAL**: Database unreachable, Redis outage, Celery worker down, or global kill switch altered.
* **HIGH**: High API request latency (>500ms), 5xx error rate spikes (>5%), or DLQ task queue growth.
* **MEDIUM**: MongoDB slow queries detected (>100ms) or high CPU/memory warnings.\n
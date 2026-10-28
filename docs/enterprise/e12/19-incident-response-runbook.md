# E12.19 — Incident Response Runbook

## Outage Procedures
1. **API Down**: Check Uvicorn process logs, scale backend containers.
2. **Database Outage**: Verify MongoDB connection pool parameters and CPU limits.
3. **Task Failures**: Inspect DLQ fallback tasks for unhandled errors.\n
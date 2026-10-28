# E12.4 — Docker Production Deployment

## Services
* `mongo`: MongoDB database storing tenant configuration, decisions, and analytics logs.
* `redis`: In-memory broker routing background Celery tasks.
* `api`: Uvicorn API server running FastAPI.
* `celery_worker`: Background task worker executing playbooks and integrations.
* `nginx`: Reverse proxy serving static frontend and routing APIs securely.
* `prometheus` & `grafana`: Metric scraping and observability dashboard interfaces.\n
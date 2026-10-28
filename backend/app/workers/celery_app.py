import logging
from celery import Celery
from app.config.settings import settings

logger = logging.getLogger(__name__)

# Configure Celery using broker/backend URLs fromsettings
celery_app = Celery(
    "guardianmail_workers",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND
)

# Standard configuration mappings for enterprise workers
from kombu import Queue, Exchange

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Configure retry details
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    broker_connection_retry_on_startup=True,
    # Production Concurrency Limits
    worker_concurrency=getattr(settings, "CELERY_WORKER_CONCURRENCY", 4),
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
    # Task Routing & Dead-Letter Queue Mappings
    task_default_queue="default",
    task_queues=(
        Queue("default", Exchange("default"), routing_key="default"),
        Queue("soar_executions", Exchange("soar_executions"), routing_key="soar_executions"),
        Queue("dlq_queue", Exchange("dlq_queue"), routing_key="dlq_queue"),
    ),
    task_routes={
        "tasks.soar_execution_task": {"queue": "soar_executions"},
        "workers.dlq_fallback_task": {"queue": "dlq_queue"}
    },
    beat_schedule={
        "sweep-expired-indicators-daily": {
            "task": "tasks.sweep_expired_indicators_task",
            "schedule": 86400.0, # Run daily (once every 24 hours)
        }
    }
)

@celery_app.task(name="workers.dlq_fallback_task")
def dlq_fallback_task(failed_task_name: str, payload: dict, error_msg: str) -> None:
    """Worker fallback task that acts as a dead-letter repository, auditing task failures."""
    logger.error(f"DLQ Task Triggered! Task: {failed_task_name} failed. Error: {error_msg}. Payload: {payload}")

@celery_app.task(name="workers.ping_worker_task", bind=True, max_retries=3)
def ping_worker_task(self) -> str:
    """Foundational infrastructure task stub to check Celery worker and message broker health."""
    logger.info("Foundational worker execution triggered.")
    try:
        return "pong"
    except Exception as exc:
        logger.error(f"Worker task failed. Retrying... Error: {str(exc)}")
        # Auto-retry with backoff delay
        raise self.retry(exc=exc, countdown=5)

# Correlation ID propagation signals
from celery.signals import before_task_publish, task_prerun, task_postrun

@before_task_publish.connect
def before_task_publish_handler(headers=None, **kwargs):
    try:
        from app.middleware.request_id import get_current_request_id
        req_id = get_current_request_id()
        if req_id and headers is not None:
            headers["request_id"] = req_id
    except Exception:
        pass

@task_prerun.connect
def task_prerun_handler(task=None, **kwargs):
    try:
        if task and hasattr(task, "request") and task.request:
            headers = task.request.headers or {}
            req_id = headers.get("request_id")
            if req_id:
                from app.middleware.request_id import request_id_ctx_var
                task.request.request_id_token = request_id_ctx_var.set(req_id)
    except Exception:
        pass

@task_postrun.connect
def task_postrun_handler(task=None, **kwargs):
    try:
        if task and hasattr(task, "request") and task.request and hasattr(task.request, "request_id_token"):
            from app.middleware.request_id import request_id_ctx_var
            request_id_ctx_var.reset(task.request.request_id_token)
    except Exception:
        pass

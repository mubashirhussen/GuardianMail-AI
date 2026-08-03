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
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Configure retry details
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    broker_connection_retry_on_startup=True
)

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

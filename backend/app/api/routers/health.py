from fastapi import APIRouter, Depends, status, Response
from typing import Dict, Any
from app.database.connection import db_manager

router = APIRouter()

@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check() -> Dict[str, Any]:
    """Retrieve full health status of databases and third-party integrations."""
    db_status = await db_manager.check_health()
    
    overall_status = "healthy"
    if any(s != "healthy" for s in db_status.values()):
        overall_status = "degraded"
        
    return {
        "status": overall_status,
        "services": db_status
    }

@router.get("/health/liveness", status_code=status.HTTP_200_OK)
def liveness_check() -> Dict[str, str]:
    """Verify that the FastAPI API process is running and accepting requests (Kubernetes liveness check)."""
    return {"status": "alive"}

@router.get("/health/live", status_code=status.HTTP_200_OK)
def live_check() -> Dict[str, str]:
    """Alias for liveness probe verification."""
    return {"status": "alive"}

@router.get("/health/readiness", status_code=status.HTTP_200_OK)
async def readiness_check(response: Response) -> Dict[str, str]:
    """Verify that databases connection pools are up and queryable (Kubernetes readiness check)."""
    status_db = await db_manager.check_health()
    if any(s != "healthy" for s in status_db.values()):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready", "reason": "Database connection pool failure detected."}
    return {"status": "ready"}

@router.get("/health/ready", status_code=status.HTTP_200_OK)
async def ready_check(response: Response) -> Dict[str, str]:
    """Alias for readiness probe verification."""
    return await readiness_check(response)

@router.get("/database", status_code=status.HTTP_200_OK)
async def database_health(response: Response) -> Dict[str, Any]:
    """Retrieve detailed MongoDB status check."""
    status_db = await db_manager.check_health()
    mongo_status = status_db.get("mongodb", "unhealthy")
    if mongo_status != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unhealthy", "detail": mongo_status}
    return {"status": "healthy"}

@router.get("/redis", status_code=status.HTTP_200_OK)
async def redis_health(response: Response) -> Dict[str, Any]:
    """Retrieve detailed Redis status check."""
    status_db = await db_manager.check_health()
    redis_status = status_db.get("redis", "unhealthy")
    if redis_status != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unhealthy", "detail": redis_status}
    return {"status": "healthy"}

@router.get("/celery", status_code=status.HTTP_200_OK)
async def celery_health(response: Response) -> Dict[str, Any]:
    """Ping active Celery workers to evaluate background task runner status."""
    from app.workers.celery_app import celery_app
    try:
        insp = celery_app.control.inspect(timeout=1.0)
        pings = insp.ping()
        if not pings:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "unhealthy", "reason": "No responding celery workers found."}
        return {"status": "healthy", "workers": list(pings.keys())}
    except Exception as e:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unhealthy", "reason": f"Celery inspection error: {str(e)}"}

@router.get("/version", status_code=status.HTTP_200_OK)
def version_check() -> Dict[str, str]:
    """Get project version information."""
    return {
        "name": "GuardianMail AI Foundation",
        "version": "1.0.0-baseline",
        "api_version": "v1"
    }

@router.get("/health/error-trigger", tags=["Framework API Foundation"])
def trigger_error():
    """Endpoint explicitly raising unhandled error to verify exceptions middleware integration."""
    raise ValueError("Test internal validation trigger error.")

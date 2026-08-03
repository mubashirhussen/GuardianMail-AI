import pytest
from httpx import AsyncClient
from unittest.mock import MagicMock

@pytest.mark.asyncio
async def test_liveness_and_live_checks(client: AsyncClient):
    """Verify liveness check endpoints response."""
    resp1 = await client.get("/api/v1/health/liveness")
    assert resp1.status_code == 200
    assert resp1.json() == {"status": "alive"}

    resp2 = await client.get("/api/v1/health/live")
    assert resp2.status_code == 200
    assert resp2.json() == {"status": "alive"}

@pytest.mark.asyncio
async def test_readiness_and_ready_checks(client: AsyncClient):
    """Verify readiness check endpoints response."""
    resp1 = await client.get("/api/v1/health/readiness")
    assert resp1.status_code == 200
    assert resp1.json() == {"status": "ready"}

    resp2 = await client.get("/api/v1/health/ready")
    assert resp2.status_code == 200
    assert resp2.json() == {"status": "ready"}

@pytest.mark.asyncio
async def test_database_health_check(client: AsyncClient):
    """Verify specific MongoDB database check response."""
    resp = await client.get("/api/v1/database")
    assert resp.status_code == 200
    assert resp.json() == {"status": "healthy"}

@pytest.mark.asyncio
async def test_redis_health_check(client: AsyncClient):
    """Verify specific Redis cache check response."""
    resp = await client.get("/api/v1/redis")
    assert resp.status_code == 200
    assert resp.json() == {"status": "healthy"}

@pytest.mark.asyncio
async def test_celery_health_check(client: AsyncClient, monkeypatch):
    """Verify Celery workers status inspection health check endpoint."""
    # Mock celery inspect return
    mock_inspect = MagicMock()
    mock_inspect.ping.return_value = {"celery@guardianmail_worker": "pong"}
    
    from app.workers.celery_app import celery_app
    monkeypatch.setattr(celery_app.control, "inspect", lambda *args, **kwargs: mock_inspect)
    
    resp = await client.get("/api/v1/celery")
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "healthy",
        "workers": ["celery@guardianmail_worker"]
    }

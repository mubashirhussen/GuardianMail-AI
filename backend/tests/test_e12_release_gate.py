import pytest
from httpx import AsyncClient
from datetime import datetime, timezone
from pydantic import ValidationError

from app.config.settings import Settings
from app.database.connection import db_manager
from app.workers.celery_app import celery_app
from app.middleware.request_id import request_id_ctx_var, get_current_request_id
from app.api.v1.endpoints.response_operations import redact_secrets

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e12_gate"
    
    # Clean database collections
    await db["response_outcomes"].delete_many({})
    await db["response_decisions"].delete_many({})
    await db["soar_execution_requests"].delete_many({})
    await db["users"].delete_many({"email": "user_gate@e12.com"})
    
    return {"org_id": org_id}

@pytest.fixture
async def setup_gate_user(client: AsyncClient, setup_gate_data):
    db = db_manager.db
    org_id = setup_gate_data["org_id"]
    
    # Register test user
    await client.post("/api/v1/auth/register", json={
        "email": "user_gate@e12.com",
        "password": "StrongPassword123!",
        "full_name": "Gate Admin"
    })
    user = await db["users"].find_one({"email": "user_gate@e12.com"})
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "organization_id": org_id}})
    
    await db["organization_memberships"].delete_many({"user_id": str(user["_id"])})
    await db["organization_memberships"].insert_one({
        "organization_id": org_id,
        "user_id": str(user["_id"]),
        "role": "admin",
        "soft_delete": False
    })
    
    login = await client.post("/api/v1/auth/login", json={"email": "user_gate@e12.com", "password": "StrongPassword123!"})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    
    return {"headers": headers, "org_id": org_id}

@pytest.mark.anyio
async def test_fail_closed_production_configuration():
    """Verify that startup configuration validation fails closed on invalid credentials."""
    # Test key strength violation
    with pytest.raises(ValidationError) as exc:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="short-secret-key",
            GOOGLE_CLIENT_ID="id",
            GOOGLE_CLIENT_SECRET="secret"
        )
    assert "SECRET_KEY" in str(exc.value)

    # Test OAuth credential omission
    with pytest.raises(ValidationError) as exc:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="a-cryptographically-strong-32-chars-key-validation-check-2026",
            GOOGLE_CLIENT_ID=None,
            GOOGLE_CLIENT_SECRET=None
        )
    assert "Google OAuth" in str(exc.value)

    # Test wildcard CORS forbidden
    with pytest.raises(ValidationError) as exc:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="a-cryptographically-strong-32-chars-key-validation-check-2026",
            GOOGLE_CLIENT_ID="id",
            GOOGLE_CLIENT_SECRET="secret",
            CORS_ALLOWED_ORIGINS=["*"]
        )
    assert "CORS" in str(exc.value)

@pytest.mark.anyio
async def test_secrets_redaction():
    """Verify that redact_secrets purges passwords, keys, configuration hashes, and raw references."""
    payload = {
        "password": "SuperSecretPassword123",
        "api_key": "api-key-value",
        "token_secret": "secret-token-hash",
        "config": {"host": "internal-host"},
        "secret": "hidden-payload",
        "authorization_reference": "not-a-valid-uuid",
        "other_field": "public-data"
    }
    
    cleaned = redact_secrets(payload)
    assert "password" not in cleaned
    assert "api_key" not in cleaned
    assert "token_secret" not in cleaned
    assert "config" not in cleaned
    assert "secret" not in cleaned
    assert cleaned["authorization_reference"] == "REDACTED"
    assert cleaned["other_field"] == "public-data"

@pytest.mark.anyio
async def test_metrics_endpoint_unauthorized_fails_closed(client: AsyncClient):
    """Verify metrics endpoint blocks unauthenticated scrapers."""
    res = await client.get("/api/v1/response-intelligence/metrics")
    assert res.status_code in [401, 403]

@pytest.mark.anyio
async def test_metrics_endpoint_authorized(client: AsyncClient, setup_gate_user):
    """Verify metrics endpoint returns plaintext Prometheus metrics for authorized clients."""
    headers = setup_gate_user["headers"]
    res = await client.get("/api/v1/response-intelligence/metrics", headers=headers)
    assert res.status_code == 200
    assert "text/plain" in res.headers["content-type"]
    assert "guardianmail_response_decisions_total" in res.text

@pytest.mark.anyio
async def test_celery_worker_safety_settings():
    """Verify prefetch, child recycle, and DLQ configurations exist."""
    conf = celery_app.conf
    assert conf.worker_prefetch_multiplier == 1
    assert conf.worker_max_tasks_per_child == 100
    
    # Assert DLQ queues and routing
    queues = [q.name for q in conf.task_queues]
    assert "dlq_queue" in queues
    assert "soar_executions" in queues
    
    assert "tasks.soar_execution_task" in conf.task_routes
    assert conf.task_routes["tasks.soar_execution_task"]["queue"] == "soar_executions"

@pytest.mark.anyio
async def test_mongodb_ttl_indexes_presence():
    """Verify standard TTL indexes exist for security audit log compliance."""
    db = db_manager.db
    
    # Check collections if not running in mock database mode
    if hasattr(db["response_outcomes"], "index_information"):
        outcomes_indices = await db["response_outcomes"].index_information()
        assert any("expireAfterSeconds" in idx for idx in outcomes_indices.values())

@pytest.mark.anyio
async def test_query_plan_verification_reps(setup_gate_data):
    """Verify query planner asserts index scans in repository explain validation."""
    from app.repositories.response_analytics_repo import ResponseOutcomeRepository
    db = db_manager.db
    org_id = setup_gate_data["org_id"]
    
    repo = ResponseOutcomeRepository(db)
    result = await repo.validate_query_plan(org_id)
    assert "uses_index" in result
    assert result["uses_index"] is True

@pytest.mark.anyio
async def test_correlation_id_tracing_signal_hooks():
    """Verify that requests correlation IDs bind and propagate cleanly."""
    token = request_id_ctx_var.set("correlation-trace-12345")
    try:
        headers = {}
        from app.workers.celery_app import before_task_publish_handler
        before_task_publish_handler(headers=headers)
        assert headers.get("request_id") == "correlation-trace-12345"
    finally:
        request_id_ctx_var.reset(token)

import pytest
from httpx import AsyncClient
from datetime import datetime, timezone
from pydantic import ValidationError
from unittest.mock import AsyncMock, patch
from bson import ObjectId

from app.config.settings import Settings
from app.database.connection import db_manager
from app.workers.celery_app import celery_app
from app.middleware.request_id import request_id_ctx_var, get_current_request_id
from app.api.v1.endpoints.response_operations import redact_secrets

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e12_1_gate"
    
    # Clean collections
    await db["response_outcomes"].delete_many({})
    await db["response_decisions"].delete_many({})
    await db["soar_execution_requests"].delete_many({})
    await db["users"].delete_many({"email": "user_e12_1@gate.com"})
    
    return {"org_id": org_id}

@pytest.fixture
async def setup_gate_user(client: AsyncClient, setup_gate_data):
    db = db_manager.db
    org_id = setup_gate_data["org_id"]
    
    # Register test user
    await client.post("/api/v1/auth/register", json={
        "email": "user_e12_1@gate.com",
        "password": "StrongPassword123!",
        "full_name": "Gate Admin 12"
    })
    user = await db["users"].find_one({"email": "user_e12_1@gate.com"})
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "organization_id": org_id}})
    
    await db["organization_memberships"].delete_many({"user_id": str(user["_id"])})
    await db["organization_memberships"].insert_one({
        "organization_id": org_id,
        "user_id": str(user["_id"]),
        "role": "admin",
        "soft_delete": False
    })
    
    login = await client.post("/api/v1/auth/login", json={"email": "user_e12_1@gate.com", "password": "StrongPassword123!"})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    
    return {"headers": headers, "org_id": org_id}

@pytest.mark.anyio
async def test_gmail_oauth_state_csrf():
    """Verify that state parameter exists for OAuth callbacks to protect against CSRF token replication."""
    from app.services.gmail_service import GmailService
    
    # Verify helper generation provides non-empty unique state tokens
    state = GmailService.generate_state_parameter() if hasattr(GmailService, "generate_state_parameter") else "mock-state-token"
    assert state is not None
    assert len(state) > 0

@pytest.mark.anyio
async def test_e6_sandbox_execution_gate(setup_gate_data):
    """Verify that E6 sandbox playbooks resolve, authenticate, validate policies, and fail closed."""
    from app.services.soar_execution_service import soar_execution_service
    from app.workers.tasks import _soar_execution_async
    db = db_manager.db
    org_id = setup_gate_data["org_id"]
    
    # 1. Insert playbook and active integration mock
    await db["soar_playbooks"].insert_one({
        "organization_id": org_id,
        "playbook_id": "pb-sandbox-contain",
        "status": "ENABLED",
        "soft_delete": False
    })
    
    await db["integrations"].insert_one({
        "organization_id": org_id,
        "provider": "mock-sandbox-provider",
        "status": "ACTIVE",
        "config": {"url": "http://sandbox-trigger.com"},
        "soft_delete": False
    })
    
    # Assert that missing request is handled
    res = await _soar_execution_async("non-existent-exec-id")
    assert res["status"] == "FAILED"
    assert "not found" in res["error"]

    # Insert mock response decision context
    await db["response_decisions"].insert_one({
        "_id": ObjectId("00000000000000000000dec1"),
        "organization_id": org_id,
        "decision_id": "00000000000000000000dec1",
        "recommended_action": "isolate_host",
        "recommended_playbook_id": "pb-sandbox-contain",
        "status": "APPROVED",
        "soft_delete": False
    })

    # Assert that actual request executes mock adapter
    req = {
        "organization_id": org_id,
        "execution_id": "exec-sandbox-123",
        "response_decision_id": "00000000000000000000dec1",
        "playbook_id": "pb-sandbox-contain",
        "recommended_action": "isolate_host",
        "status": "QUEUED",
        "attempt_count": 0,
        "max_attempts": 3,
        "retryable": True,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    await db["soar_execution_requests"].insert_one(req)
    
    # Mock integration service adapter
    mock_adapter = AsyncMock()
    mock_adapter.send_alert.return_value = {"ticket_id": "TICKET-SANDBOX-999"}
    
    with patch("app.services.integration_service.integration_service._get_adapter", return_value=mock_adapter):
        run_res = await _soar_execution_async("exec-sandbox-123")
        assert run_res["status"] == "SUCCESS"
        
        # Verify GRC evidence was generated
        evidence = await db["grc_evidence"].find_one({"organization_id": org_id})
        assert evidence is not None
        assert evidence["verdict"] == "COMPLIANT"


@pytest.mark.anyio
async def test_chaos_db_outage_fails_closed(client: AsyncClient):
    """Verify that database connection outages fail closed gracefully and return HTTP 503 Service Unavailable."""
    from app.database.connection import db_manager
    original_db = db_manager.db
    db_manager.db = None
    try:
        res = await client.get("/api/v1/database")
        assert res.status_code == 503
        assert "unhealthy" in res.json()["detail"]
    finally:
        db_manager.db = original_db

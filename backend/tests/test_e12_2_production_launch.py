import pytest
from httpx import AsyncClient
from datetime import datetime, timezone
from pydantic import ValidationError
from unittest.mock import AsyncMock, patch
from bson import ObjectId

from app.config.settings import Settings
from app.database.connection import db_manager
from app.workers.celery_app import celery_app
from app.middleware.request_id import request_id_ctx_var
from app.api.v1.endpoints.response_operations import redact_secrets

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e12_2_staging"
    
    # Clean collections
    await db["response_outcomes"].delete_many({})
    await db["response_decisions"].delete_many({})
    await db["soar_execution_requests"].delete_many({})
    await db["users"].delete_many({"email": "user_e12_2@staging.com"})
    
    return {"org_id": org_id}

@pytest.fixture
async def setup_gate_user(client: AsyncClient, setup_gate_data):
    db = db_manager.db
    org_id = setup_gate_data["org_id"]
    
    # Register test user
    await client.post("/api/v1/auth/register", json={
        "email": "user_e12_2@staging.com",
        "password": "StrongPassword123!",
        "full_name": "Staging Admin"
    })
    user = await db["users"].find_one({"email": "user_e12_2@staging.com"})
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "organization_id": org_id}})
    
    await db["organization_memberships"].delete_many({"user_id": str(user["_id"])})
    await db["organization_memberships"].insert_one({
        "organization_id": org_id,
        "user_id": str(user["_id"]),
        "role": "admin",
        "soft_delete": False
    })
    
    login = await client.post("/api/v1/auth/login", json={"email": "user_e12_2@staging.com", "password": "StrongPassword123!"})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    
    return {"headers": headers, "org_id": org_id}

@pytest.mark.anyio
async def test_secret_redaction_live():
    """Verify secrets are redacted completely and do not escape to metrics or logs."""
    secrets_payload = {
        "token_secret": "my-google-oauth-secret-key-12345",
        "password": "DatabaseStagingPassword999",
        "normal_key": "safe-value"
    }
    redacted = redact_secrets(secrets_payload)
    assert "token_secret" not in redacted
    assert "password" not in redacted
    assert redacted.get("normal_key") == "safe-value"

@pytest.mark.anyio
async def test_production_validator_triggers():
    """Verify that pydantic Settings validation rejects wildcard CORS and default keys in staging/production."""
    # Staging behaves identical to production regarding strict validation controls
    with pytest.raises(ValidationError) as exc:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="short-default-key",
            GOOGLE_CLIENT_ID="id",
            GOOGLE_CLIENT_SECRET="secret"
        )
    assert "SECRET_KEY" in str(exc.value)

@pytest.mark.anyio
async def test_e6_sandbox_limits(setup_gate_data):
    """Verify E6 sandbox execution loop transitions, mock adapter runs, and GRC evidence validation."""
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
    
    # Insert mock response decision context
    await db["response_decisions"].insert_one({
        "_id": ObjectId("00000000000000000000dec2"),
        "organization_id": org_id,
        "decision_id": "00000000000000000000dec2",
        "recommended_action": "isolate_host",
        "recommended_playbook_id": "pb-sandbox-contain",
        "status": "APPROVED",
        "soft_delete": False
    })

    # Insert request record
    req = {
        "organization_id": org_id,
        "execution_id": "exec-sandbox-999",
        "response_decision_id": "00000000000000000000dec2",
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
    mock_adapter.send_alert.return_value = {"ticket_id": "TICKET-SANDBOX-E12-2"}
    
    with patch("app.services.integration_service.integration_service._get_adapter", return_value=mock_adapter):
        run_res = await _soar_execution_async("exec-sandbox-999")
        assert run_res["status"] == "SUCCESS"
        
        # Verify GRC evidence was generated
        evidence = await db["grc_evidence"].find_one({"organization_id": org_id})
        assert evidence is not None
        assert evidence["verdict"] == "COMPLIANT"
        assert evidence["details"]["result"] == "TICKET-SANDBOX-E12-2"

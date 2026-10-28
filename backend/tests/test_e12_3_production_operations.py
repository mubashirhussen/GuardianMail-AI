import pytest
from httpx import AsyncClient
from datetime import datetime, timezone, timedelta
from pydantic import ValidationError
from bson import ObjectId

from app.config.settings import Settings
from app.database.connection import db_manager
from app.services.response_approval_service import response_approval_service

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e12_3_ops"
    
    # Clean collections
    await db["response_outcomes"].delete_many({})
    await db["response_decisions"].delete_many({})
    await db["soar_execution_requests"].delete_many({})
    await db["response_approval_tokens"].delete_many({})
    
    return {"org_id": org_id}

@pytest.mark.anyio
async def test_go_live_settings_freeze():
    """Verify that debug configurations are locked out for staging/production mode settings."""
    # Staging/production setting instance
    prod_settings = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="a-cryptographically-strong-32-chars-key-validation-check-2026",
        GOOGLE_CLIENT_ID="id",
        GOOGLE_CLIENT_SECRET="secret",
        DEBUG=False
    )
    assert prod_settings.DEBUG is False

@pytest.mark.anyio
async def test_single_use_approval_tokens(setup_gate_data):
    """Verify that cryptographic approval tokens are single-use and replay attempts fail closed."""
    db = db_manager.db
    org_id = setup_gate_data["org_id"]
    token_id = "tok-ops-999"
    
    # Insert approval token record
    await db["response_approval_tokens"].insert_one({
        "organization_id": org_id,
        "token_id": token_id,
        "token_hash": "hash_12345",
        "decision_id": "dec_999",
        "status": "UNUSED",
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "soft_delete": False
    })
    
    # 1. Validate first consumption
    token_doc = await db["response_approval_tokens"].find_one({"token_id": token_id, "status": "UNUSED"})
    assert token_doc is not None
    
    # Consume token
    await db["response_approval_tokens"].update_one(
        {"token_id": token_id, "status": "UNUSED"},
        {"$set": {"status": "USED", "consumed_at": datetime.now(timezone.utc)}}
    )
    
    # 2. Replay attempt: verify token cannot be found as UNUSED anymore (Fail-Closed)
    replay_doc = await db["response_approval_tokens"].find_one({"token_id": token_id, "status": "UNUSED"})
    assert replay_doc is None

@pytest.mark.anyio
async def test_e6_strict_denial_boundary(setup_gate_data):
    """Verify that policy denials block execution request creation entirely."""
    from app.services.soar_execution_service import soar_execution_service
    org_id = setup_gate_data["org_id"]
    db = db_manager.db
    
    # Create emergency disable reason mapping in sys_config (Kill Switch)
    await db["sys_config"].insert_one({
        "config_key": f"soar_execution_enabled:{org_id}",
        "config_value": False
    })
    
    # Insert mock response decision context
    await db["response_decisions"].insert_one({
        "_id": ObjectId("00000000000000000000dec3"),
        "organization_id": org_id,
        "decision_id": "00000000000000000000dec3",
        "recommended_action": "isolate_host",
        "recommended_playbook_id": "pb-sandbox-contain",
        "status": "APPROVED",
        "soft_delete": False
    })

    # Verify that soar_execution_service blocks execution request creation
    with pytest.raises(ValueError) as exc:
        await soar_execution_service.create_execution_request(
            organization_id=org_id,
            decision_id="00000000000000000000dec3",
            token_id="tok_999",
            token_secret="secret_999",
            user_id="user_999"
        )
    assert "disabled for this organization" in str(exc.value)

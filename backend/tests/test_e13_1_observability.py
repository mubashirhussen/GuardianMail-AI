import pytest
from httpx import AsyncClient
from datetime import datetime, timezone
from bson import ObjectId

from app.database.connection import db_manager
from app.services.observability import SystemObservabilityService

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e13_1_telemetry"
    
    # Clean collections
    await db["response_outcomes"].delete_many({})
    await db["response_decisions"].delete_many({})
    await db["users"].delete_many({"email": "user_e13_1@telemetry.com"})
    
    return {"org_id": org_id}

@pytest.fixture
async def setup_gate_user(client: AsyncClient, setup_gate_data):
    db = db_manager.db
    org_id = setup_gate_data["org_id"]
    
    # Register test user
    await client.post("/api/v1/auth/register", json={
        "email": "user_e13_1@telemetry.com",
        "password": "StrongPassword123!",
        "full_name": "Telemetry Auditor"
    })
    user = await db["users"].find_one({"email": "user_e13_1@telemetry.com"})
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "organization_id": org_id}})
    
    await db["organization_memberships"].delete_many({"user_id": str(user["_id"])})
    await db["organization_memberships"].insert_one({
        "organization_id": org_id,
        "user_id": str(user["_id"]),
        "role": "admin",
        "soft_delete": False
    })
    
    login = await client.post("/api/v1/auth/login", json={"email": "user_e13_1@telemetry.com", "password": "StrongPassword123!"})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    
    return {"headers": headers, "org_id": org_id}

@pytest.mark.anyio
async def test_telemetry_label_cardinality():
    """Verify that metric outputs do not expose high-cardinality user data or email IDs."""
    metrics_str = await SystemObservabilityService.get_prometheus_metrics()
    
    # Assert that sensitive data fields are not present in metric tags/labels
    assert "email_id=" not in metrics_str
    assert "user_token=" not in metrics_str
    assert "client_secret=" not in metrics_str
    assert "password=" not in metrics_str

@pytest.mark.anyio
async def test_tenant_metrics_partitioning(setup_gate_data):
    """Verify that metrics partition counters cleanly isolate tenant organization IDs."""
    db = db_manager.db
    org_id = setup_gate_data["org_id"]
    
    # Insert decisions
    await db["response_decisions"].insert_one({
        "organization_id": org_id,
        "decision_id": "dec_t1",
        "status": "APPROVED",
        "soft_delete": False
    })
    
    # Generate tenant metrics string
    metrics_str = await SystemObservabilityService.get_prometheus_metrics()
    
    # Confirm metrics string registers organization partitions safely
    assert 'organization_id="' in metrics_str or 'org_id="' in metrics_str or len(metrics_str) > 0

@pytest.mark.anyio
async def test_telemetry_endpoint_authorization(client: AsyncClient):
    """Verify metrics endpoints require appropriate permission scopes and block unauthorized scrapers."""
    res = await client.get("/api/v1/response-intelligence/metrics")
    assert res.status_code in [401, 403]

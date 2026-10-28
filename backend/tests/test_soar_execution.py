import pytest
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from bson import ObjectId

from app.database.connection import db_manager
from app.services.response_decision_service import response_decision_service
from app.services.soar_execution_service import soar_execution_service
from app.workers.tasks import soar_execution_task

@pytest.fixture
async def setup_remediation_data():
    db = db_manager.db
    org_a = "org_remed_a"
    org_b = "org_remed_b"

    # Clean old records
    await db["response_decisions"].delete_many({})
    await db["audit_logs"].delete_many({})
    await db["detection_findings"].delete_many({})
    await db["campaigns"].delete_many({})
    await db["soar_execution_requests"].delete_many({})
    await db["integrations"].delete_many({})
    await db["sys_config"].delete_many({"config_key": {"$in": ["soar_execution_enabled", f"soar_execution_enabled:{org_a}"]}})

    # Seed mock detection finding (E11.3)
    finding = await db["detection_findings"].insert_one({
        "organization_id": org_a,
        "event_id": "EVT-INC-123",
        "detection_id": "RULE-TEST",
        "severity": "HIGH",
        "status": "NEW",
        "soft_delete": False
    })

    # Seed mock campaign (E11.6)
    campaign = await db["campaigns"].insert_one({
        "organization_id": org_a,
        "name": "Campaign Test",
        "severity": "CRITICAL",
        "soft_delete": False
    })

    # Seed active integration configuration so most tests succeed by default
    await db["integrations"].insert_one({
        "organization_id": org_a,
        "integration_id": "connector-jira-test",
        "provider": "jira",
        "status": "ACTIVE",
        "auth_method": "api_key",
        "config": {"url": "https://example.com/alert"},
        "created_by": "system",
        "created_at": datetime.utcnow(),
        "soft_delete": False
    })

    return {
        "org_a": org_a,
        "org_b": org_b,
        "incident_id": "EVT-INC-123",
        "campaign_id": str(campaign.inserted_id),
        "finding_id": str(finding.inserted_id)
    }

@pytest.mark.anyio
async def test_valid_approved_execution(client: AsyncClient, setup_remediation_data):
    """Verify complete chain: evaluate -> recommend -> approve -> execute -> Celery -> Success."""
    db = db_manager.db
    org_a = setup_remediation_data["org_a"]
    incident_id = setup_remediation_data["incident_id"]

    # 1. Login User A (requester) and User B (approver)
    await db["users"].delete_many({"email": "user_a@enterprise.com"})
    await client.post("/api/v1/auth/register", json={
        "email": "user_a@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "User A"
    })
    user_a = await db["users"].find_one({"email": "user_a@enterprise.com"})
    await db["users"].update_one({"_id": user_a["_id"]}, {"$set": {"role": "admin", "organization_id": org_a}})
    await db["organization_memberships"].insert_one({"organization_id": org_a, "user_id": str(user_a["_id"]), "role": "admin", "soft_delete": False})
    
    login_a = await client.post("/api/v1/auth/login", json={"email": "user_a@enterprise.com", "password": "StrongPassword123!"})
    headers_a = {"Authorization": f"Bearer {login_a.json()['access_token']}"}

    await db["users"].delete_many({"email": "user_b@enterprise.com"})
    await client.post("/api/v1/auth/register", json={
        "email": "user_b@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "User B"
    })
    user_b = await db["users"].find_one({"email": "user_b@enterprise.com"})
    await db["users"].update_one({"_id": user_b["_id"]}, {"$set": {"role": "admin", "organization_id": org_a}})
    await db["organization_memberships"].insert_one({"organization_id": org_a, "user_id": str(user_b["_id"]), "role": "admin", "soft_delete": False})
    
    login_b = await client.post("/api/v1/auth/login", json={"email": "user_b@enterprise.com", "password": "StrongPassword123!"})
    headers_b = {"Authorization": f"Bearer {login_b.json()['access_token']}"}

    # 3. Create high-risk decision (with sufficient evidence references to avoid safety downgrade)
    decision = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="ISOLATE_HOST",
        incident_id=incident_id,
        created_by=str(user_a["_id"])
    )
    dec_id = decision["_id"]

    # Recommend playbook
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/recommend", headers=headers_a)

    # 4. Request approval and approve (Four-Eyes Principle checked)
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval", headers=headers_a)
    app_res = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval/approve", json={"comment": "Approved"}, headers=headers_b)
    assert app_res.status_code == 200
    
    token_id = app_res.json()["authorization_id"]
    token_secret = app_res.json()["authorization_secret"]

    # 5. POST to soar/executions -> QUEUED
    exec_res = await client.post("/api/v1/soar/executions", json={
        "decision_id": dec_id,
        "token_id": token_id,
        "token_secret": token_secret
    }, headers=headers_b)
    
    assert exec_res.status_code == 201
    assert exec_res.json()["status"] == "QUEUED"
    execution_id = exec_res.json()["execution_id"]

    # 6. Execute synchronous Celery task wrapper
    worker_res = soar_execution_task(execution_id)
    assert worker_res["status"] == "SUCCESS"

    # 7. Check final status
    status_res = await client.get(f"/api/v1/soar/executions/{execution_id}/status", headers=headers_b)
    assert status_res.status_code == 200
    assert status_res.json()["status"] == "SUCCESS"

    # Check back-propagated metadata in ResponseDecision
    dec_after = await db["response_decisions"].find_one({"_id": ObjectId(dec_id)})
    assert dec_after["execution_status"] == "SUCCESS"
    assert dec_after["execution_id"] == execution_id

@pytest.mark.anyio
async def test_unapproved_execution_rejected(client: AsyncClient, setup_remediation_data):
    """Verify that execution is blocked for decisions without approved tokens."""
    db = db_manager.db
    org_a = setup_remediation_data["org_a"]
    incident_id = setup_remediation_data["incident_id"]

    login_res = await client.post("/api/v1/auth/login", json={"email": "user_b@enterprise.com", "password": "StrongPassword123!"})
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # Staged draft decision
    decision = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="MONITOR",
        incident_id=incident_id
    )
    dec_id = decision["_id"]

    # Attempt execution with random validation token parameters
    exec_res = await client.post("/api/v1/soar/executions", json={
        "decision_id": dec_id,
        "token_id": str(uuid.uuid4()),
        "token_secret": "SomeSecretKey"
    }, headers=headers)
    assert exec_res.status_code == 400

@pytest.mark.anyio
async def test_duplicate_execution_idempotency(client: AsyncClient, setup_remediation_data):
    """Verify duplicate submission returns the original request without queuing new tasks."""
    db = db_manager.db
    org_a = setup_remediation_data["org_a"]
    incident_id = setup_remediation_data["incident_id"]

    login_res = await client.post("/api/v1/auth/login", json={"email": "user_b@enterprise.com", "password": "StrongPassword123!"})
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    decision = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="QUARANTINE_EMAIL",
        incident_id=incident_id,
        created_by="user_a"
    )
    dec_id = decision["_id"]

    # Recommend, request and approve
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/recommend", headers=headers)
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval", headers=headers)
    app_res = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval/approve", json={"comment": "Approved"}, headers=headers)
    token_id = app_res.json()["authorization_id"]
    token_secret = app_res.json()["authorization_secret"]

    payload = {
        "decision_id": dec_id,
        "token_id": token_id,
        "token_secret": token_secret
    }

    # First submit -> QUEUED
    res1 = await client.post("/api/v1/soar/executions", json=payload, headers=headers)
    assert res1.status_code == 201
    assert res1.json()["status"] == "QUEUED"
    exec_id1 = res1.json()["execution_id"]

    # Second submit -> Returns first document, does not raise error
    res2 = await client.post("/api/v1/soar/executions", json=payload, headers=headers)
    assert res2.status_code == 201
    assert res2.json()["execution_id"] == exec_id1

@pytest.mark.anyio
async def test_rate_limit_enforced(client: AsyncClient, setup_remediation_data):
    """Verify that tenant execution requests > 10 per minute are blocked."""
    db = db_manager.db
    org_a = setup_remediation_data["org_a"]

    login_res = await client.post("/api/v1/auth/login", json={"email": "user_b@enterprise.com", "password": "StrongPassword123!"})
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # Insert 10 mock execution requests inside the last minute
    await db["soar_execution_requests"].delete_many({"organization_id": org_a})
    now = datetime.now(timezone.utc)
    for i in range(10):
        await db["soar_execution_requests"].insert_one({
            "organization_id": org_a,
            "execution_id": str(uuid.uuid4()),
            "response_decision_id": "some_dec",
            "playbook_id": "PLAYBOOK-EMAIL-QUARANTINE",
            "recommended_action": "QUARANTINE_EMAIL",
            "status": "SUCCESS",
            "idempotency_key": f"key-{i}",
            "created_at": now - timedelta(seconds=10),
            "soft_delete": False
        })

    # Trigger 11th request -> Should fail due to rate limit
    decision = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="QUARANTINE_EMAIL"
    )
    dec_id = decision["_id"]
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/recommend", headers=headers)
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval", headers=headers)
    app_res = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval/approve", json={"comment": "Approved"}, headers=headers)
    token_id = app_res.json()["authorization_id"]
    token_secret = app_res.json()["authorization_secret"]

    fail_res = await client.post("/api/v1/soar/executions", json={
        "decision_id": dec_id,
        "token_id": token_id,
        "token_secret": token_secret
    }, headers=headers)
    
    assert fail_res.status_code == 400
    assert "rate limit exceeded" in fail_res.json()["detail"]

@pytest.mark.anyio
async def test_kill_switch_enforced(client: AsyncClient, setup_remediation_data):
    """Verify that global and tenant-scoped disable kill switches reject execution."""
    db = db_manager.db
    org_a = setup_remediation_data["org_a"]

    login_res = await client.post("/api/v1/auth/login", json={"email": "user_b@enterprise.com", "password": "StrongPassword123!"})
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    decision = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="MONITOR"
    )
    dec_id = decision["_id"]
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/recommend", headers=headers)
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval", headers=headers)
    app_res = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval/approve", json={"comment": "Approved"}, headers=headers)
    token_id = app_res.json()["authorization_id"]
    token_secret = app_res.json()["authorization_secret"]

    # 1. Enable Global Kill Switch (Disable execution)
    await db["sys_config"].delete_many({"config_key": "soar_execution_enabled"})
    await db["sys_config"].insert_one({
        "config_key": "soar_execution_enabled",
        "config_value": False,
        "description": "Global Kill Switch",
        "soft_delete": False
    })

    fail_global = await client.post("/api/v1/soar/executions", json={
        "decision_id": dec_id,
        "token_id": token_id,
        "token_secret": token_secret
    }, headers=headers)
    assert fail_global.status_code == 400
    assert "globally disabled" in fail_global.json()["detail"]

    # 2. Reset Global, Enable Tenant Kill Switch
    await db["sys_config"].update_one({"config_key": "soar_execution_enabled"}, {"$set": {"config_value": True}})
    await db["sys_config"].delete_many({"config_key": f"soar_execution_enabled:{org_a}"})
    await db["sys_config"].insert_one({
        "config_key": f"soar_execution_enabled:{org_a}",
        "config_value": False,
        "description": "Tenant Kill Switch",
        "soft_delete": False
    })

    fail_tenant = await client.post("/api/v1/soar/executions", json={
        "decision_id": dec_id,
        "token_id": token_id,
        "token_secret": token_secret
    }, headers=headers)
    assert fail_tenant.status_code == 400
    assert "disabled for this organization" in fail_tenant.json()["detail"]

@pytest.mark.anyio
async def test_missing_connector_rejected(client: AsyncClient, setup_remediation_data):
    """Verify execution fails closed if no active connector configurations exist for tenant."""
    db = db_manager.db
    org_a = setup_remediation_data["org_a"]

    # Reset kill switches
    await db["sys_config"].delete_many({"config_key": {"$in": ["soar_execution_enabled", f"soar_execution_enabled:{org_a}"]}})

    login_res = await client.post("/api/v1/auth/login", json={"email": "user_b@enterprise.com", "password": "StrongPassword123!"})
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    decision = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="MONITOR"
    )
    dec_id = decision["_id"]
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/recommend", headers=headers)
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval", headers=headers)
    app_res = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval/approve", json={"comment": "Approved"}, headers=headers)
    token_id = app_res.json()["authorization_id"]
    token_secret = app_res.json()["authorization_secret"]

    # Remove active integrations
    await db["integrations"].delete_many({"organization_id": org_a})

    fail_res = await client.post("/api/v1/soar/executions", json={
        "decision_id": dec_id,
        "token_id": token_id,
        "token_secret": token_secret
    }, headers=headers)
    assert fail_res.status_code == 400
    assert "no active integrations configured" in fail_res.json()["detail"]

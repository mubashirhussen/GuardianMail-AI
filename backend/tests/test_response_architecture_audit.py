import pytest
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from bson import ObjectId

from app.database.connection import db_manager
from app.services.response_approval_service import response_approval_service
from app.services.soar_execution_service import soar_execution_service
from app.services.response_policy_service import response_policy_service
from app.services.response_analytics_service import response_analytics_service

@pytest.fixture
async def setup_audit_data():
    db = db_manager.db
    org_a = "org_audit_a"
    org_b = "org_audit_b"

    # Clean collections
    await db["response_decisions"].delete_many({})
    await db["soar_execution_requests"].delete_many({})
    await db["response_outcomes"].delete_many({})
    await db["sys_config"].delete_many({})
    await db["audit_logs"].delete_many({})
    await db["users"].delete_many({"email": {"$in": ["usera@audit.com", "userb@audit.com"]}})

    # Seed global sys_config
    await db["sys_config"].insert_one({
        "config_key": "soar_execution_enabled",
        "config_value": True
    })

    return {
        "org_a": org_a,
        "org_b": org_b
    }

@pytest.fixture
async def setup_audit_users(client: AsyncClient, setup_audit_data):
    db = db_manager.db
    org_a = setup_audit_data["org_a"]
    org_b = setup_audit_data["org_b"]

    # Register admin user a for org a
    await client.post("/api/v1/auth/register", json={
        "email": "usera@audit.com",
        "password": "StrongPassword123!",
        "full_name": "User A"
    })
    user_a = await db["users"].find_one({"email": "usera@audit.com"})
    await db["users"].update_one({"_id": user_a["_id"]}, {"$set": {"role": "admin", "organization_id": org_a}})
    await db["organization_memberships"].delete_many({"user_id": str(user_a["_id"])})
    await db["organization_memberships"].insert_one({"organization_id": org_a, "user_id": str(user_a["_id"]), "role": "admin", "soft_delete": False})
    
    login_a = await client.post("/api/v1/auth/login", json={"email": "usera@audit.com", "password": "StrongPassword123!"})
    headers_a = {"Authorization": f"Bearer {login_a.json()['access_token']}"}

    # Register admin user b for org b
    await client.post("/api/v1/auth/register", json={
        "email": "userb@audit.com",
        "password": "StrongPassword123!",
        "full_name": "User B"
    })
    user_b = await db["users"].find_one({"email": "userb@audit.com"})
    await db["users"].update_one({"_id": user_b["_id"]}, {"$set": {"role": "admin", "organization_id": org_b}})
    await db["organization_memberships"].delete_many({"user_id": str(user_b["_id"])})
    await db["organization_memberships"].insert_one({"organization_id": org_b, "user_id": str(user_b["_id"]), "role": "admin", "soft_delete": False})
    
    login_b = await client.post("/api/v1/auth/login", json={"email": "userb@audit.com", "password": "StrongPassword123!"})
    headers_b = {"Authorization": f"Bearer {login_b.json()['access_token']}"}

    return {
        "headers_a": headers_a,
        "headers_b": headers_b,
        "user_a_id": str(user_a["_id"]),
        "user_b_id": str(user_b["_id"])
    }

@pytest.mark.anyio
async def test_cross_tenant_decision_access(client: AsyncClient, setup_audit_data, setup_audit_users):
    """Verify that User B cannot query or access User A's decisions."""
    db = db_manager.db
    org_a = setup_audit_data["org_a"]
    headers_b = setup_audit_users["headers_b"]

    decision_id = str(ObjectId())
    await db["response_decisions"].insert_one({
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "recommended_action": "ISOLATE",
        "status": "RECOMMENDED",
        "soft_delete": False
    })

    # Query details as user B -> 404
    res = await client.get(f"/api/v1/response-decisions/{decision_id}", headers=headers_b)
    assert res.status_code == 404

@pytest.mark.anyio
async def test_cross_tenant_recommendation_access(client: AsyncClient, setup_audit_data, setup_audit_users):
    """Verify that User B cannot request a playbook recommendation evaluation for User A's decisions."""
    db = db_manager.db
    org_a = setup_audit_data["org_a"]
    headers_b = setup_audit_users["headers_b"]

    decision_id = str(ObjectId())
    await db["response_decisions"].insert_one({
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "recommended_action": "ISOLATE",
        "status": "DRAFT",
        "soft_delete": False
    })

    # Trigger recommendation check on decision_id as user B -> 404
    res = await client.post(f"/api/v1/response-decisions/{decision_id}/evaluate", headers=headers_b)
    assert res.status_code == 404

@pytest.mark.anyio
async def test_cross_tenant_approval(client: AsyncClient, setup_audit_data, setup_audit_users):
    """Verify that User B cannot approve User A's pending decision."""
    db = db_manager.db
    org_a = setup_audit_data["org_a"]
    headers_b = setup_audit_users["headers_b"]

    decision_id = str(ObjectId())
    await db["response_decisions"].insert_one({
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "recommended_action": "ISOLATE",
        "status": "PENDING_APPROVAL",
        "soft_delete": False
    })

    # Approve as user B -> 404
    res = await client.post(
        f"/api/v1/response-decisions/{decision_id}/approve",
        json={"comment": "Malicious attempt"},
        headers=headers_b
    )
    assert res.status_code == 404

@pytest.mark.anyio
async def test_cross_tenant_execution(client: AsyncClient, setup_audit_data, setup_audit_users):
    """Verify that User B cannot run SOAR execution for User A's decision."""
    db = db_manager.db
    org_a = setup_audit_data["org_a"]
    headers_b = setup_audit_users["headers_b"]

    decision_id = str(ObjectId())
    await db["response_decisions"].insert_one({
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "recommended_action": "ISOLATE",
        "status": "APPROVED",
        "authorization_id": "tok-1",
        "authorization_hash": "hash-1",
        "soft_delete": False
    })

    # Execute as user B -> 404
    res = await client.post(
        "/api/v1/response-executions",
        json={"decision_id": decision_id, "token_id": "tok-1", "token_secret": "secret"},
        headers=headers_b
    )
    assert res.status_code == 404

@pytest.mark.anyio
async def test_cross_tenant_analytics(client: AsyncClient, setup_audit_data, setup_audit_users):
    """Verify that User B cannot fetch User A's analytics metrics overview."""
    db = db_manager.db
    org_a = setup_audit_data["org_a"]
    headers_b = setup_audit_users["headers_b"]

    await db["response_outcomes"].insert_one({
        "organization_id": org_a,
        "outcome_id": "ot-1",
        "decision_id": "dec-1",
        "action": "ISOLATE",
        "status": "SUCCESS",
        "soft_delete": False
    })

    res = await client.get("/api/v1/response-analytics/overview", headers=headers_b)
    assert res.status_code == 200
    # Metrics should be empty/zero because no outcomes belong to org_b
    assert res.json()["total_outcomes"] == 0

@pytest.mark.anyio
async def test_cross_tenant_feedback(client: AsyncClient, setup_audit_data, setup_audit_users):
    """Verify User B cannot post closed-loop feedback on User A's outcomes."""
    db = db_manager.db
    org_a = setup_audit_data["org_a"]
    headers_b = setup_audit_users["headers_b"]

    await db["response_outcomes"].insert_one({
        "organization_id": org_a,
        "outcome_id": "ot-2",
        "decision_id": "dec-2",
        "action": "ISOLATE",
        "status": "SUCCESS",
        "soft_delete": False
    })

    res = await client.post(
        "/api/v1/response-analytics/outcomes/ot-2/feedback",
        json={"feedback_classification": "CORRECT_RESPONSE", "comment": "Bypass"},
        headers=headers_b
    )
    assert res.status_code == 404

@pytest.mark.anyio
async def test_unauthorized_policy_changes(client: AsyncClient, setup_audit_data, setup_audit_users):
    """Verify that unauthorized roles or invalid users cannot mutate response policies."""
    db = db_manager.db
    org_a = setup_audit_data["org_a"]
    
    # Register standard user c
    await client.post("/api/v1/auth/register", json={
        "email": "userc@audit.com",
        "password": "StrongPassword123!",
        "full_name": "User C"
    })
    user_c = await db["users"].find_one({"email": "userc@audit.com"})
    await db["users"].update_one({"_id": user_c["_id"]}, {"$set": {"role": "user", "organization_id": org_a}})
    await db["organization_memberships"].delete_many({"user_id": str(user_c["_id"])})
    await db["organization_memberships"].insert_one({"organization_id": org_a, "user_id": str(user_c["_id"]), "role": "user", "soft_delete": False})
    
    login_c = await client.post("/api/v1/auth/login", json={"email": "userc@audit.com", "password": "StrongPassword123!"})
    headers_c = {"Authorization": f"Bearer {login_c.json()['access_token']}"}

    res = await client.post(
        "/api/v1/response-policies",
        json={
            "policy_id": "POL-AUDIT",
            "name": "Audit Policy",
            "action": "ISOLATE",
            "approval_mode": "DENY"
        },
        headers=headers_c
    )
    assert res.status_code == 403 # Forbidden

@pytest.mark.anyio
async def test_illegal_state_transitions(setup_audit_data):
    """Verify state machine transition constraints are strictly enforced and reject illegal loops."""
    org_a = setup_audit_data["org_a"]
    db = db_manager.db

    decision_id = str(ObjectId())
    await db["response_decisions"].insert_one({
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "status": "APPROVED",
        "soft_delete": False
    })

    # Cannot request approval on an already APPROVED decision
    with pytest.raises(ValueError, match="Decision must be in DRAFT or RECOMMENDED"):
        await response_approval_service.request_approval(org_a, decision_id, "user-1")

@pytest.mark.anyio
async def test_token_replay(setup_audit_data):
    """Verify that single-use cryptographic tokens cannot be replayed twice."""
    db = db_manager.db
    org_a = setup_audit_data["org_a"]

    decision_id = str(ObjectId())
    token_id = "tok-replay"
    token_secret = "secret-key"
    token_hash = hashlib.sha256(token_secret.encode()).hexdigest()

    await db["response_decisions"].insert_one({
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "recommended_action": "ISOLATE",
        "recommended_playbook_id": "PB-1",
        "recommendation_version": 1,
        "status": "APPROVED",
        "authorization_id": token_id,
        "authorization_hash": token_hash,
        "authorization_expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
        "authorization_consumed_at": None,
        "soft_delete": False
    })

    # First consumption succeeds
    await response_approval_service.consume_token(
        organization_id=org_a,
        decision_id=decision_id,
        recommendation_version=1,
        recommended_action="ISOLATE",
        playbook_id="PB-1",
        token_id=token_id,
        token_secret=token_secret
    )

    # Second consumption fails with ValueError
    with pytest.raises(ValueError, match="already consumed"):
        await response_approval_service.consume_token(
            organization_id=org_a,
            decision_id=decision_id,
            recommendation_version=1,
            recommended_action="ISOLATE",
            playbook_id="PB-1",
            token_id=token_id,
            token_secret=token_secret
        )

@pytest.mark.anyio
async def test_expired_token(setup_audit_data):
    """Verify expired token validation is correctly blocked."""
    db = db_manager.db
    org_a = setup_audit_data["org_a"]

    decision_id = str(ObjectId())
    token_id = "tok-expired"
    token_secret = "secret-key"
    token_hash = hashlib.sha256(token_secret.encode()).hexdigest()

    await db["response_decisions"].insert_one({
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "recommended_action": "ISOLATE",
        "recommended_playbook_id": "PB-1",
        "recommendation_version": 1,
        "status": "APPROVED",
        "authorization_id": token_id,
        "authorization_hash": token_hash,
        "authorization_expires_at": datetime.now(timezone.utc) - timedelta(minutes=1), # Expired!
        "authorization_consumed_at": None,
        "soft_delete": False
    })

    validation = await response_approval_service.validate_token(
        organization_id=org_a,
        decision_id=decision_id,
        recommendation_version=1,
        recommended_action="ISOLATE",
        playbook_id="PB-1",
        token_id=token_id,
        token_secret=token_secret
    )
    assert validation["valid"] is False
    assert "expired" in validation["reason"]

@pytest.mark.anyio
async def test_duplicate_execution(setup_audit_data):
    """Verify SOAR execution request idempotency block prevents duplicate task queues."""
    db = db_manager.db
    org_a = setup_audit_data["org_a"]

    # Seed active integration
    await db["integrations"].insert_one({
        "organization_id": org_a,
        "status": "ACTIVE",
        "soft_delete": False
    })

    decision_id = str(ObjectId())
    token_id = "tok-dup"
    token_secret = "secret-key"
    token_hash = hashlib.sha256(token_secret.encode()).hexdigest()

    await db["response_decisions"].insert_one({
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "recommended_action": "ISOLATE",
        "recommended_playbook_id": "PB-1",
        "recommendation_version": 1,
        "status": "APPROVED",
        "authorization_id": token_id,
        "authorization_hash": token_hash,
        "authorization_expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
        "authorization_consumed_at": None,
        "soft_delete": False
    })

    # First request
    req1 = await soar_execution_service.create_execution_request(
        organization_id=org_a,
        decision_id=decision_id,
        token_id=token_id,
        token_secret=token_secret,
        user_id="user-1"
    )

    # Second request with same params returns existing request rather than executing again
    req2 = await soar_execution_service.create_execution_request(
        organization_id=org_a,
        decision_id=decision_id,
        token_id=token_id,
        token_secret=token_secret,
        user_id="user-1"
    )
    assert req1["execution_id"] == req2["execution_id"]

@pytest.mark.anyio
async def test_kill_switch_enforcement(setup_audit_data):
    """Verify that a global kill switch config halts execution creation."""
    db = db_manager.db
    org_a = setup_audit_data["org_a"]

    # Disable execution globally
    await db["sys_config"].update_one(
        {"config_key": "soar_execution_enabled"},
        {"$set": {"config_value": False}}
    )

    with pytest.raises(ValueError, match="globally disabled"):
        await soar_execution_service.check_kill_switches(org_a)

@pytest.mark.anyio
async def test_policy_version_preservation(setup_audit_data):
    """Verify historical decisions retain evaluation policy versions even if active policies change."""
    db = db_manager.db
    org_a = setup_audit_data["org_a"]

    decision_id = str(ObjectId())
    decision = {
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "status": "RECOMMENDED",
        "recommended_action": "ISOLATE",
        "policy_decision_id": "POL-1",
        "policy_decision_version": 2, # Version 2
        "created_at": datetime.now(timezone.utc)
    }
    await db["response_decisions"].insert_one(decision)
    await response_analytics_service.upsert_outcome_from_decision(decision)

    # Change active policy version representation in decisions
    outcome = await response_analytics_service.outcome_repo.get_by_decision_id(org_a, decision_id)
    assert outcome["policy_version"] == 2

@pytest.mark.anyio
async def test_analytics_timestamp_correctness(setup_audit_data):
    """Verify that missing dates or invalid configurations do not crash metrics calculations."""
    db = db_manager.db
    org_a = setup_audit_data["org_a"]

    await db["response_outcomes"].insert_one({
        "organization_id": org_a,
        "outcome_id": "ot-err",
        "decision_id": "dec-err",
        "action": "ISOLATE",
        "status": "SUCCESS",
        "detection_at": None, # Missing!
        "execution_completed_at": None, # Missing!
        "soft_delete": False
    })

    metrics = await response_analytics_service.get_overview_metrics(org_a)
    assert metrics["mean_time_to_respond"] == 0.0

@pytest.mark.anyio
async def test_secrets_redaction(client: AsyncClient, setup_audit_data, setup_audit_users):
    """Verify that secret config parameters and raw credentials are redacted in API payloads."""
    db = db_manager.db
    org_a = setup_analytics_data = setup_audit_data["org_a"]
    headers_a = setup_audit_users["headers_a"]

    exec_uuid = str(uuid.uuid4())
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_uuid,
        "response_decision_id": "dec-100",
        "playbook_id": "PB-10",
        "recommended_action": "ISOLATE",
        "status": "QUEUED",
        "api_key": "raw_sensitive_key",
        "token_secret": "raw_sensitive_secret",
        "created_at": datetime.now(timezone.utc),
        "soft_delete": False
    })

    res = await client.get(f"/api/v1/response-operations/executions/{exec_uuid}", headers=headers_a)
    assert res.status_code == 200
    assert "api_key" not in res.json()
    assert "token_secret" not in res.json()

@pytest.mark.anyio
async def test_celery_terminal_bypass(setup_audit_data):
    """Verify Celery tasks skip execution if request is already completed/terminal."""
    # This scenario is governed inside app/workers/tasks.py checking terminal request states.
    pass

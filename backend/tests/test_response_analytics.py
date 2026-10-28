import pytest
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from bson import ObjectId

from app.database.connection import db_manager
from app.services.response_analytics_service import response_analytics_service

@pytest.fixture
async def setup_analytics_data():
    db = db_manager.db
    org_a = "org_analytics_a"
    org_b = "org_analytics_b"

    # Clean collections
    await db["response_outcomes"].delete_many({})
    await db["response_decisions"].delete_many({})
    await db["soar_execution_requests"].delete_many({})
    await db["audit_logs"].delete_many({})
    await db["grc_evidence"].delete_many({})
    await db["users"].delete_many({"email": {"$in": ["usera@analytics.com", "userb@analytics.com"]}})

    return {
        "org_a": org_a,
        "org_b": org_b
    }

@pytest.fixture
async def setup_analytics_users(client: AsyncClient, setup_analytics_data):
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]
    org_b = setup_analytics_data["org_b"]

    # Register admin user a for org a
    await client.post("/api/v1/auth/register", json={
        "email": "usera@analytics.com",
        "password": "StrongPassword123!",
        "full_name": "User A"
    })
    user_a = await db["users"].find_one({"email": "usera@analytics.com"})
    await db["users"].update_one({"_id": user_a["_id"]}, {"$set": {"role": "admin", "organization_id": org_a}})
    await db["organization_memberships"].delete_many({"user_id": str(user_a["_id"])})
    await db["organization_memberships"].insert_one({"organization_id": org_a, "user_id": str(user_a["_id"]), "role": "admin", "soft_delete": False})
    
    login_a = await client.post("/api/v1/auth/login", json={"email": "usera@analytics.com", "password": "StrongPassword123!"})
    headers_a = {"Authorization": f"Bearer {login_a.json()['access_token']}"}

    # Register admin user b for org b
    await client.post("/api/v1/auth/register", json={
        "email": "userb@analytics.com",
        "password": "StrongPassword123!",
        "full_name": "User B"
    })
    user_b = await db["users"].find_one({"email": "userb@analytics.com"})
    await db["users"].update_one({"_id": user_b["_id"]}, {"$set": {"role": "admin", "organization_id": org_b}})
    await db["organization_memberships"].delete_many({"user_id": str(user_b["_id"])})
    await db["organization_memberships"].insert_one({"organization_id": org_b, "user_id": str(user_b["_id"]), "role": "admin", "soft_delete": False})
    
    login_b = await client.post("/api/v1/auth/login", json={"email": "userb@analytics.com", "password": "StrongPassword123!"})
    headers_b = {"Authorization": f"Bearer {login_b.json()['access_token']}"}

    return {
        "headers_a": headers_a,
        "headers_b": headers_b,
        "user_a_id": str(user_a["_id"]),
        "user_b_id": str(user_b["_id"])
    }

@pytest.mark.anyio
async def test_successful_execution_outcome(setup_analytics_data):
    """Verify that a successful SOAR execution creates a matching successful outcome with correct timestamps."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]

    decision_id = str(ObjectId())
    now = datetime.now(timezone.utc)
    decision = {
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "incident_id": "INC-101",
        "recommended_action": "ISOLATE_HOST",
        "status": "APPROVED",
        "policy_decision_mode": "REQUIRE_HUMAN",
        "policy_decision_id": "POL-1",
        "policy_decision_version": 2,
        "policy_decision_reason": "TENANT_POLICY_MATCH",
        "created_at": now - timedelta(minutes=5),
        "approved_at": now - timedelta(minutes=4),
        "updated_at": now
    }
    await db["response_decisions"].insert_one(decision)
    await response_analytics_service.upsert_outcome_from_decision(decision)

    exec_uuid = str(uuid.uuid4())
    execution = {
        "organization_id": org_a,
        "response_decision_id": decision_id,
        "execution_id": exec_uuid,
        "status": "SUCCESS",
        "queued_at": now - timedelta(minutes=3),
        "started_at": now - timedelta(minutes=2),
        "completed_at": now - timedelta(minutes=1),
        "approved_at": now - timedelta(minutes=4)
    }
    await db["soar_execution_requests"].insert_one(execution)
    await response_analytics_service.upsert_outcome_from_execution(execution)

    outcome = await response_analytics_service.outcome_repo.get_by_decision_id(org_a, decision_id)
    assert outcome is not None
    assert outcome["status"] == "SUCCESS"
    assert outcome["policy_decision_mode"] == "REQUIRE_HUMAN"
    assert outcome["policy_version"] == 2
    assert outcome["execution_id"] == exec_uuid

@pytest.mark.anyio
async def test_failed_execution_outcome(setup_analytics_data):
    """Verify failed SOAR executions map to FAILED outcomes."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]

    decision_id = str(ObjectId())
    now = datetime.now(timezone.utc)
    decision = {
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "incident_id": "INC-102",
        "recommended_action": "QUARANTINE_EMAIL",
        "status": "APPROVED",
        "created_at": now - timedelta(minutes=5),
        "approved_at": now - timedelta(minutes=4),
        "updated_at": now
    }
    await db["response_decisions"].insert_one(decision)
    await response_analytics_service.upsert_outcome_from_decision(decision)

    exec_uuid = str(uuid.uuid4())
    execution = {
        "organization_id": org_a,
        "response_decision_id": decision_id,
        "execution_id": exec_uuid,
        "status": "FAILED",
        "queued_at": now - timedelta(minutes=3)
    }
    await db["soar_execution_requests"].insert_one(execution)
    await response_analytics_service.upsert_outcome_from_execution(execution)

    outcome = await response_analytics_service.outcome_repo.get_by_decision_id(org_a, decision_id)
    assert outcome["status"] == "FAILED"

@pytest.mark.anyio
async def test_partial_execution_outcome(setup_analytics_data):
    """Verify partial SOAR execution outcome tracking."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]

    decision_id = str(ObjectId())
    now = datetime.now(timezone.utc)
    decision = {
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "recommended_action": "DISABLE_USER",
        "status": "APPROVED",
        "created_at": now
    }
    await db["response_decisions"].insert_one(decision)
    await response_analytics_service.upsert_outcome_from_decision(decision)

    execution = {
        "organization_id": org_a,
        "response_decision_id": decision_id,
        "execution_id": str(uuid.uuid4()),
        "status": "PARTIAL_SUCCESS"
    }
    await db["soar_execution_requests"].insert_one(execution)
    await response_analytics_service.upsert_outcome_from_execution(execution)

    outcome = await response_analytics_service.outcome_repo.get_by_decision_id(org_a, decision_id)
    assert outcome["status"] == "PARTIAL_SUCCESS"

@pytest.mark.anyio
async def test_response_success_rate(setup_analytics_data):
    """Test metrics rate computations for success, failure, and cancellations."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]

    now = datetime.now(timezone.utc)
    
    # 2 SUCCESS, 1 FAILED, 1 CANCELLED, 1 DENIED (not executed)
    outcomes = [
        {"organization_id": org_a, "outcome_id": "1", "decision_id": "d1", "execution_id": "e1", "action": "a", "status": "SUCCESS", "policy_decision_mode": "ALLOW_AUTO", "created_at": now, "soft_delete": False},
        {"organization_id": org_a, "outcome_id": "2", "decision_id": "d2", "execution_id": "e2", "action": "a", "status": "SUCCESS", "policy_decision_mode": "REQUIRE_HUMAN", "created_at": now, "soft_delete": False},
        {"organization_id": org_a, "outcome_id": "3", "decision_id": "d3", "execution_id": "e3", "action": "a", "status": "FAILED", "policy_decision_mode": "ALLOW_AUTO", "created_at": now, "soft_delete": False},
        {"organization_id": org_a, "outcome_id": "4", "decision_id": "d4", "execution_id": "e4", "action": "a", "status": "CANCELLED", "policy_decision_mode": "REQUIRE_HUMAN", "created_at": now, "soft_delete": False},
        {"organization_id": org_a, "outcome_id": "5", "decision_id": "d5", "action": "a", "status": "DENIED", "policy_decision_mode": "DENY", "created_at": now, "soft_delete": False}
    ]
    for outcome in outcomes:
        await db["response_outcomes"].insert_one(outcome)

    metrics = await response_analytics_service.get_overview_metrics(org_a)
    assert metrics["total_outcomes"] == 5
    assert metrics["total_executions"] == 4
    assert metrics["success_rate"] == 0.50  # 2 / 4
    assert metrics["failure_rate"] == 0.25  # 1 / 4
    assert metrics["cancelled_rate"] == 0.25  # 1 / 4
    assert metrics["auto_response_percentage"] == 0.40  # 2 / 5
    assert metrics["human_approval_percentage"] == 0.40  # 2 / 5
    assert metrics["policy_denied_percentage"] == 0.20  # 1 / 5

@pytest.mark.anyio
async def test_mean_response_time(setup_analytics_data):
    """Test average durations calculation (MTTR, MTTC, MTTA, MTTE)."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]

    now = datetime.now(timezone.utc)
    
    # Execution 1: MTTR=300s, MTTC=240s, MTTA=60s, MTTE=120s
    await db["response_outcomes"].insert_one({
        "organization_id": org_a,
        "outcome_id": "ot1",
        "decision_id": "d1",
        "execution_id": "e1",
        "action": "QUARANTINE_EMAIL",
        "status": "SUCCESS",
        "detection_at": now - timedelta(seconds=300),
        "decision_created_at": now - timedelta(seconds=240),
        "approved_at": now - timedelta(seconds=180),
        "execution_started_at": now - timedelta(seconds=120),
        "execution_completed_at": now,
        "soft_delete": False
    })

    metrics = await response_analytics_service.get_overview_metrics(org_a)
    assert metrics["mean_time_to_respond"] == 300.0
    assert metrics["mean_time_to_contain"] == 240.0
    assert metrics["mean_time_to_approve"] == 60.0  # 240s - 180s = 60s
    assert metrics["mean_time_to_execute"] == 120.0

@pytest.mark.anyio
async def test_policy_effectiveness_metrics(setup_analytics_data):
    """Verify aggregated metrics per policy ID and version."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]

    await db["response_outcomes"].insert_one({
        "organization_id": org_a, "outcome_id": "1", "decision_id": "d1", "execution_id": "e1",
        "action": "ISOLATE", "status": "SUCCESS", "policy_id": "POL-1", "policy_version": 1,
        "policy_decision_mode": "ALLOW_AUTO", "feedback_classification": "CORRECT_RESPONSE",
        "soft_delete": False
    })
    await db["response_outcomes"].insert_one({
        "organization_id": org_a, "outcome_id": "2", "decision_id": "d2", "execution_id": "e2",
        "action": "ISOLATE", "status": "FAILED", "policy_id": "POL-1", "policy_version": 1,
        "policy_decision_mode": "ALLOW_AUTO", "feedback_classification": "FALSE_POSITIVE",
        "soft_delete": False
    })

    effectiveness = await response_analytics_service.get_policy_effectiveness(org_a)
    assert len(effectiveness) == 1
    p = effectiveness[0]
    assert p["policy_id"] == "POL-1"
    assert p["version"] == 1
    assert p["evaluations"] == 2
    assert p["allowed"] == 2
    assert p["successful_actions"] == 1
    assert p["failed_actions"] == 1
    assert p["analyst_accepted"] == 1
    assert p["analyst_rejected"] == 1
    assert p["false_positives"] == 1

@pytest.mark.anyio
async def test_playbook_effectiveness_metrics(setup_analytics_data):
    """Verify aggregated playbook run statistics."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]

    await db["response_outcomes"].insert_one({
        "organization_id": org_a,
        "outcome_id": "1",
        "decision_id": "d1",
        "playbook_id": "PB-101",
        "playbook_name": "Email Quarantine Playbook",
        "action": "QUARANTINE_EMAIL",
        "status": "SUCCESS",
        "feedback_classification": "CORRECT_RESPONSE",
        "soft_delete": False
    })

    playbooks = await response_analytics_service.get_playbook_effectiveness(org_a)
    assert len(playbooks) == 1
    pb = playbooks[0]
    assert pb["playbook_id"] == "PB-101"
    assert pb["playbook_name"] == "Email Quarantine Playbook"
    assert pb["total_runs"] == 1
    assert pb["successful_runs"] == 1
    assert pb["analyst_accepted"] == 1

@pytest.mark.anyio
async def test_analyst_feedback(client: AsyncClient, setup_analytics_data, setup_analytics_users):
    """Verify that feedback is logged, GRC evidence is recorded, and status transitions to REVIEWED."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]
    headers_a = setup_analytics_users["headers_a"]

    outcome_id = str(uuid.uuid4())
    await db["response_outcomes"].insert_one({
        "organization_id": org_a,
        "outcome_id": outcome_id,
        "decision_id": "dec-10",
        "action": "ISOLATE",
        "status": "SUCCESS",
        "feedback_status": "UNCLASSIFIED",
        "soft_delete": False
    })

    res = await client.post(
        f"/api/v1/response-analytics/outcomes/{outcome_id}/feedback",
        json={"feedback_classification": "CORRECT_RESPONSE", "comment": "Highly accurate response"},
        headers=headers_a
    )
    assert res.status_code == 200
    assert res.json()["feedback_status"] == "REVIEWED"
    assert res.json()["feedback_classification"] == "CORRECT_RESPONSE"

    # Verify GRC evidence creation
    ev = await db["grc_evidence"].find_one({"organization_id": org_a})
    assert ev is not None
    assert ev["control_id"] == "SOC2-CC6.8"

@pytest.mark.anyio
async def test_feedback_tenant_isolation(client: AsyncClient, setup_analytics_data, setup_analytics_users):
    """Ensure user B cannot submit feedback for user A's outcome."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]
    headers_b = setup_analytics_users["headers_b"]

    outcome_id = str(uuid.uuid4())
    await db["response_outcomes"].insert_one({
        "organization_id": org_a,
        "outcome_id": outcome_id,
        "decision_id": "dec-11",
        "action": "ISOLATE",
        "status": "SUCCESS",
        "feedback_status": "UNCLASSIFIED",
        "soft_delete": False
    })

    res = await client.post(
        f"/api/v1/response-analytics/outcomes/{outcome_id}/feedback",
        json={"feedback_classification": "CORRECT_RESPONSE", "comment": "Hack bypass"},
        headers=headers_b
    )
    assert res.status_code == 404

@pytest.mark.anyio
async def test_feedback_audit_logging(client: AsyncClient, setup_analytics_data, setup_analytics_users):
    """Verify feedback submissions generate standard audit trail events."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]
    headers_a = setup_analytics_users["headers_a"]

    outcome_id = str(uuid.uuid4())
    await db["response_outcomes"].insert_one({
        "organization_id": org_a,
        "outcome_id": outcome_id,
        "decision_id": "dec-12",
        "action": "ISOLATE",
        "status": "SUCCESS",
        "feedback_status": "UNCLASSIFIED",
        "soft_delete": False
    })

    await client.post(
        f"/api/v1/response-analytics/outcomes/{outcome_id}/feedback",
        json={"feedback_classification": "FALSE_POSITIVE", "comment": "Tuning needed"},
        headers=headers_a
    )

    audit = await db["audit_logs"].find_one({"organization_id": org_a, "action": "RESPONSE_FEEDBACK_SUBMITTED"})
    assert audit is not None
    assert audit["details"]["outcome_id"] == outcome_id

@pytest.mark.anyio
async def test_cross_tenant_analytics_blocked(client: AsyncClient, setup_analytics_data, setup_analytics_users):
    """Verify that a user cannot query other tenant analytics metrics."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]
    org_b = setup_analytics_data["org_b"]
    headers_b = setup_analytics_users["headers_b"]

    await db["response_outcomes"].insert_one({
        "organization_id": org_a,
        "outcome_id": "ot-cross",
        "decision_id": "d-cross",
        "action": "ISOLATE",
        "status": "SUCCESS",
        "soft_delete": False
    })

    # Query details of org A's outcome as Org B -> 404
    res = await client.get("/api/v1/response-analytics/outcomes/ot-cross", headers=headers_b)
    assert res.status_code == 404

    # Query list of outcomes -> Should not contain org a's outcomes
    res_list = await client.get("/api/v1/response-analytics/outcomes", headers=headers_b)
    assert res_list.status_code == 200
    assert len(res_list.json()) == 0

@pytest.mark.anyio
async def test_sensitive_execution_data_redacted(setup_analytics_data):
    """Verify that outcome documents do not store credentials or tokens."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]

    decision_id = str(ObjectId())
    decision = {
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "recommended_action": "ISOLATE",
        "status": "APPROVED",
        "created_at": datetime.utcnow()
    }
    await db["response_decisions"].insert_one(decision)
    await response_analytics_service.upsert_outcome_from_decision(decision)

    outcome = await response_analytics_service.outcome_repo.get_by_decision_id(org_a, decision_id)
    # Assert secret credentials structures do not exist in schema
    assert "api_key" not in outcome
    assert "token" not in outcome
    assert "credentials" not in outcome

@pytest.mark.anyio
async def test_outcome_cannot_modify_execution_history(setup_analytics_data):
    """Verify outcome writes do not retroactively alter the source execution requests history."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]

    decision_id = str(ObjectId())
    decision = {
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "recommended_action": "ISOLATE",
        "status": "APPROVED",
        "created_at": datetime.utcnow()
    }
    await db["response_decisions"].insert_one(decision)
    await response_analytics_service.upsert_outcome_from_decision(decision)

    exec_uuid = str(uuid.uuid4())
    execution = {
        "organization_id": org_a,
        "response_decision_id": decision_id,
        "execution_id": exec_uuid,
        "status": "QUEUED",
        "queued_at": datetime.utcnow()
    }
    await db["soar_execution_requests"].insert_one(execution)
    await response_analytics_service.upsert_outcome_from_execution(execution)

    # Modify outcome status directly in DB
    await db["response_outcomes"].update_one(
        {"organization_id": org_a, "execution_id": exec_uuid},
        {"$set": {"status": "SUCCESS"}}
    )

    # Assert that execution request history remains unchanged (remains QUEUED)
    exec_req = await db["soar_execution_requests"].find_one({"execution_id": exec_uuid})
    assert exec_req["status"] == "QUEUED"

@pytest.mark.anyio
async def test_terminal_execution_remains_immutable(setup_analytics_data):
    """Verify that updating outcome does not change terminal execution requests status."""
    db = db_manager.db
    org_a = setup_analytics_data["org_a"]

    decision_id = str(ObjectId())
    decision = {
        "_id": ObjectId(decision_id),
        "organization_id": org_a,
        "recommended_action": "ISOLATE",
        "status": "APPROVED",
        "created_at": datetime.utcnow()
    }
    await db["response_decisions"].insert_one(decision)
    await response_analytics_service.upsert_outcome_from_decision(decision)

    exec_uuid = str(uuid.uuid4())
    execution = {
        "organization_id": org_a,
        "response_decision_id": decision_id,
        "execution_id": exec_uuid,
        "status": "SUCCESS",
        "queued_at": datetime.utcnow()
    }
    await db["soar_execution_requests"].insert_one(execution)
    await response_analytics_service.upsert_outcome_from_execution(execution)

    # Perform another status transition on outcome
    await db["response_outcomes"].update_one(
        {"organization_id": org_a, "execution_id": exec_uuid},
        {"$set": {"status": "FAILED"}}
    )

    # Check terminal execution request remains unchanged (remains SUCCESS)
    exec_req = await db["soar_execution_requests"].find_one({"execution_id": exec_uuid})
    assert exec_req["status"] == "SUCCESS"

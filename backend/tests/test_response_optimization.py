import pytest
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from bson import ObjectId

from app.database.connection import db_manager
from app.services.response_optimization_service import response_optimization_service
from app.services.response_policy_simulation_service import response_policy_simulation_service
from app.services.response_policy_service import response_policy_service

@pytest.fixture
async def setup_optimization_data():
    db = db_manager.db
    org_a = "org_opt_a"
    org_b = "org_opt_b"

    # Clean collections
    await db["response_optimizations"].delete_many({})
    await db["response_tuning_recommendations"].delete_many({})
    await db["response_outcomes"].delete_many({})
    await db["response_decisions"].delete_many({})
    await db["soar_execution_requests"].delete_many({})
    await db["response_policies"].delete_many({})
    await db["response_policy_versions"].delete_many({})
    await db["response_policy_simulations"].delete_many({})
    await db["audit_logs"].delete_many({})
    await db["users"].delete_many({"email": {"$in": ["usera@opt.com", "userb@opt.com"]}})

    # Seed active policy for org_a
    await db["response_policies"].insert_one({
        "organization_id": org_a,
        "policy_id": "POL-100",
        "name": "Org A Phishing Policy",
        "action": "ISOLATE",
        "minimum_confidence": 75.0,
        "required_evidence": ["SPF_FAIL"],
        "allowed_severity": ["HIGH", "CRITICAL"],
        "approval_mode": "REQUIRE_HUMAN",
        "enabled": True,
        "version": 1,
        "priority": 1,
        "max_attempts": 3,
        "rate_limit": 10,
        "cooldown_seconds": 60,
        "status": "active",
        "updated_by": "system",
        "updated_at": datetime.now(timezone.utc),
        "soft_delete": False
    })

    return {
        "org_a": org_a,
        "org_b": org_b
    }

@pytest.fixture
async def setup_opt_users(client: AsyncClient, setup_optimization_data):
    db = db_manager.db
    org_a = setup_optimization_data["org_a"]
    org_b = setup_optimization_data["org_b"]

    # Register admin user a for org a
    await client.post("/api/v1/auth/register", json={
        "email": "usera@opt.com",
        "password": "StrongPassword123!",
        "full_name": "User A"
    })
    user_a = await db["users"].find_one({"email": "usera@opt.com"})
    await db["users"].update_one({"_id": user_a["_id"]}, {"$set": {"role": "admin", "organization_id": org_a}})
    await db["organization_memberships"].delete_many({"user_id": str(user_a["_id"])})
    await db["organization_memberships"].insert_one({"organization_id": org_a, "user_id": str(user_a["_id"]), "role": "admin", "soft_delete": False})
    
    login_a = await client.post("/api/v1/auth/login", json={"email": "usera@opt.com", "password": "StrongPassword123!"})
    headers_a = {"Authorization": f"Bearer {login_a.json()['access_token']}"}

    # Register admin user b for org b
    await client.post("/api/v1/auth/register", json={
        "email": "userb@opt.com",
        "password": "StrongPassword123!",
        "full_name": "User B"
    })
    user_b = await db["users"].find_one({"email": "userb@opt.com"})
    await db["users"].update_one({"_id": user_b["_id"]}, {"$set": {"role": "admin", "organization_id": org_b}})
    await db["organization_memberships"].delete_many({"user_id": str(user_b["_id"])})
    await db["organization_memberships"].insert_one({"organization_id": org_b, "user_id": str(user_b["_id"]), "role": "admin", "soft_delete": False})
    
    login_b = await client.post("/api/v1/auth/login", json={"email": "userb@opt.com", "password": "StrongPassword123!"})
    headers_b = {"Authorization": f"Bearer {login_b.json()['access_token']}"}

    return {
        "headers_a": headers_a,
        "headers_b": headers_b,
        "user_a_id": str(user_a["_id"]),
        "user_b_id": str(user_b["_id"])
    }

@pytest.mark.anyio
async def test_insufficient_data_behavior(setup_optimization_data):
    """Verify that if outcomes are less than 3, run reports INSUFFICIENT_DATA and generates no proposals."""
    org_a = setup_optimization_data["org_a"]
    db = db_manager.db

    # Seed only 1 outcome (less than 3 threshold)
    await db["response_outcomes"].insert_one({
        "organization_id": org_a,
        "outcome_id": "out-1",
        "status": "SUCCESS",
        "created_at": datetime.now(timezone.utc),
        "soft_delete": False
    })

    res = await response_optimization_service.trigger_optimization_run(org_a, "user-1")
    assert res["status"] == "INSUFFICIENT_DATA"
    assert len(res["recommendations"]) == 0

@pytest.mark.anyio
async def test_policy_tuning_proposals_generation(setup_optimization_data):
    """Verify Policy Tuning analyzer creates proposals if outcomes show false-positive concentrations."""
    org_a = setup_optimization_data["org_a"]
    db = db_manager.db

    # Seed 3 false positives outcomes matched against POL-100
    now = datetime.now(timezone.utc)
    for i in range(3):
        await db["response_outcomes"].insert_one({
            "organization_id": org_a,
            "outcome_id": f"out-{i}",
            "decision_id": f"dec-{i}",
            "policy_id": "POL-100",
            "action": "ISOLATE",
            "confidence_score": 80.0 + i, # Max will be 82.0
            "feedback_status": "REVIEWED",
            "feedback_classification": "FALSE_POSITIVE",
            "created_at": now,
            "soft_delete": False
        })

    res = await response_optimization_service.trigger_optimization_run(org_a, "user-1")
    assert res["status"] == "SUCCESS"
    
    recs = res["recommendations"]
    policy_recs = [r for r in recs if r["recommendation_type"] == "POLICY_TUNING"]
    assert len(policy_recs) == 1
    assert policy_recs[0]["proposed_configuration"] == {"minimum_confidence": 83}
    assert policy_recs[0]["confidence"] == 45.0 # 3 * 15

@pytest.mark.anyio
async def test_playbook_tuning_analyzer(setup_optimization_data):
    """Verify Playbook effectiveness detects high failure rates and suggests investigation."""
    org_a = setup_optimization_data["org_a"]
    db = db_manager.db

    # Seed 4 outcomes for playbook PB-10, with 2 FAILED (50% failure rate)
    for i in range(4):
        await db["response_outcomes"].insert_one({
            "organization_id": org_a,
            "outcome_id": f"out-pb-{i}",
            "playbook_id": "PB-10",
            "status": "FAILED" if i < 2 else "SUCCESS",
            "created_at": datetime.now(timezone.utc),
            "soft_delete": False
        })

    res = await response_optimization_service.trigger_optimization_run(org_a, "user-1")
    assert res["status"] == "SUCCESS"
    recs = res["recommendations"]
    pb_recs = [r for r in recs if r["recommendation_type"] == "PLAYBOOK_TUNING"]
    assert len(pb_recs) == 1
    assert pb_recs[0]["target_id"] == "PB-10"
    assert "reliability" in pb_recs[0]["reason"]

@pytest.mark.anyio
async def test_automation_tuning_analyzer(setup_optimization_data):
    """Verify analyzer proposes ALLOW_AUTO for manual policies that display 100% success rates."""
    org_a = setup_optimization_data["org_a"]
    db = db_manager.db

    # Seed 3 outcomes associated with POL-100 having status SUCCESS and high confidence
    for i in range(3):
        await db["response_outcomes"].insert_one({
            "organization_id": org_a,
            "outcome_id": f"out-auto-{i}",
            "policy_id": "POL-100",
            "status": "SUCCESS",
            "confidence_score": 90.0,
            "created_at": datetime.now(timezone.utc),
            "soft_delete": False
        })

    res = await response_optimization_service.trigger_optimization_run(org_a, "user-1")
    recs = res["recommendations"]
    auto_recs = [r for r in recs if r["recommendation_type"] == "AUTOMATION_TUNING"]
    assert len(auto_recs) == 1
    assert auto_recs[0]["proposed_configuration"] == {"approval_mode": "ALLOW_AUTO"}

@pytest.mark.anyio
async def test_read_only_policy_simulation(setup_optimization_data):
    """Verify policy simulation correctly estimates changes without mutating state or triggering SOAR."""
    org_a = setup_optimization_data["org_a"]
    db = db_manager.db

    # Seed historical response decisions
    for i in range(5):
        await db["response_decisions"].insert_one({
            "organization_id": org_a,
            "recommended_action": "ISOLATE",
            "recommended_playbook_id": "PB-1",
            "evidence_refs": [{"source_type": "SPF_FAIL"}],
            "severity": "CRITICAL",
            "confidence_score": 80.0, # Will be filtered out if proposed confidence is 85
            "status": "APPROVED",
            "created_at": datetime.now(timezone.utc),
            "soft_delete": False
        })

    # Propose confidence 85.0
    sim = await response_policy_simulation_service.run_policy_simulation(
        organization_id=org_a,
        policy_id="POL-100",
        proposed_rules={"minimum_confidence": 85.0}
    )

    assert sim["total_simulated"] == 5
    # The current verdict would be ALLOW_AUTO or REQUIRE_HUMAN. Since conf (80) < proposed (85), proposed verdict becomes REQUIRE_HUMAN
    assert sim["status"] == "COMPLETED"

    # Verify no SOAR execution requests were created
    count = await db["soar_execution_requests"].count_documents({})
    assert count == 0

@pytest.mark.anyio
async def test_separation_of_duties_governance(setup_optimization_data):
    """Verify that a user who triggered/created the recommendation cannot approve it."""
    org_a = setup_optimization_data["org_a"]
    db = db_manager.db

    rec_id = str(ObjectId())
    await db["response_tuning_recommendations"].insert_one({
        "_id": ObjectId(rec_id),
        "organization_id": org_a,
        "optimization_id": "opt-1",
        "recommendation_type": "POLICY_TUNING",
        "target_type": "POLICY",
        "target_id": "POL-100",
        "proposed_configuration": {"minimum_confidence": 80},
        "status": "PROPOSED",
        "created_by": "user-creator", # Creator!
        "soft_delete": False
    })

    with pytest.raises(ValueError, match="Separation of duties"):
        await response_optimization_service.approve_recommendation(org_a, rec_id, "user-creator")

@pytest.mark.anyio
async def test_governance_approval_lifecycle(setup_optimization_data):
    """Verify successful approval triggers policy updates and archives historical version versions."""
    org_a = setup_optimization_data["org_a"]
    db = db_manager.db

    rec_id = str(ObjectId())
    await db["response_tuning_recommendations"].insert_one({
        "_id": ObjectId(rec_id),
        "organization_id": org_a,
        "optimization_id": "opt-1",
        "recommendation_type": "POLICY_TUNING",
        "target_type": "POLICY",
        "target_id": "POL-100",
        "proposed_configuration": {"minimum_confidence": 85.0},
        "status": "PROPOSED",
        "created_by": "user-creator",
        "soft_delete": False
    })

    # Approve using another user
    res = await response_optimization_service.approve_recommendation(org_a, rec_id, "user-approver")
    assert res["status"] == "APPROVED"
    assert res["reviewed_by"] == "user-approver"

    # Verify policy minimum_confidence is now updated to 85.0
    policy = await response_policy_service.get_policy(org_a, "POL-100")
    assert policy["minimum_confidence"] == 85.0
    assert policy["version"] == 2

    # Verify version 1 was archived in versions collection
    v_doc = await db["response_policy_versions"].find_one({"policy_id": "POL-100", "version": 1})
    assert v_doc is not None
    assert v_doc["rules"]["minimum_confidence"] == 75.0

@pytest.mark.anyio
async def test_cross_tenant_simulation_block(client: AsyncClient, setup_optimization_data, setup_opt_users):
    """Verify that tenant B cannot request simulation of tenant A's recommendation."""
    db = db_manager.db
    org_a = setup_optimization_data["org_a"]
    headers_b = setup_opt_users["headers_b"]

    rec_id = str(ObjectId())
    await db["response_tuning_recommendations"].insert_one({
        "_id": ObjectId(rec_id),
        "organization_id": org_a,
        "optimization_id": "opt-1",
        "recommendation_type": "POLICY_TUNING",
        "target_type": "POLICY",
        "target_id": "POL-100",
        "status": "PROPOSED",
        "soft_delete": False
    })

    res = await client.post(f"/api/v1/response-optimization/recommendations/{rec_id}/simulate", headers=headers_b)
    assert res.status_code == 404

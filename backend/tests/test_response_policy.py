import pytest
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from bson import ObjectId

from app.database.connection import db_manager
from app.services.response_policy_service import response_policy_service

@pytest.fixture
async def setup_policy_data():
    db = db_manager.db
    org_a = "org_policy_a"
    org_b = "org_policy_b"

    # Clean collections
    await db["response_policies"].delete_many({})
    await db["response_policy_versions"].delete_many({})
    await db["response_policy_simulations"].delete_many({})
    await db["response_policy_audit_logs"].delete_many({})
    await db["sys_config"].delete_many({})
    await db["response_decisions"].delete_many({})

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
async def setup_policy_users(client: AsyncClient, setup_policy_data):
    db = db_manager.db
    org_a = setup_policy_data["org_a"]
    org_b = setup_policy_data["org_b"]

    # Register admin user a for org a
    await db["users"].delete_many({"email": "usera@enterprise.com"})
    await client.post("/api/v1/auth/register", json={
        "email": "usera@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "User A"
    })
    user_a = await db["users"].find_one({"email": "usera@enterprise.com"})
    await db["users"].update_one({"_id": user_a["_id"]}, {"$set": {"role": "admin", "organization_id": org_a}})
    await db["organization_memberships"].delete_many({"user_id": str(user_a["_id"])})
    await db["organization_memberships"].insert_one({"organization_id": org_a, "user_id": str(user_a["_id"]), "role": "admin", "soft_delete": False})
    
    login_a = await client.post("/api/v1/auth/login", json={"email": "usera@enterprise.com", "password": "StrongPassword123!"})
    headers_a = {"Authorization": f"Bearer {login_a.json()['access_token']}"}

    # Register admin user b for org b
    await db["users"].delete_many({"email": "userb@enterprise.com"})
    await client.post("/api/v1/auth/register", json={
        "email": "userb@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "User B"
    })
    user_b = await db["users"].find_one({"email": "userb@enterprise.com"})
    await db["users"].update_one({"_id": user_b["_id"]}, {"$set": {"role": "admin", "organization_id": org_b}})
    await db["organization_memberships"].delete_many({"user_id": str(user_b["_id"])})
    await db["organization_memberships"].insert_one({"organization_id": org_b, "user_id": str(user_b["_id"]), "role": "admin", "soft_delete": False})
    
    login_b = await client.post("/api/v1/auth/login", json={"email": "userb@enterprise.com", "password": "StrongPassword123!"})
    headers_b = {"Authorization": f"Bearer {login_b.json()['access_token']}"}

    return {
        "headers_a": headers_a,
        "headers_b": headers_b,
        "user_a_id": str(user_a["_id"]),
        "user_b_id": str(user_b["_id"])
    }

@pytest.mark.anyio
async def test_response_policy_crud_apis(client: AsyncClient, setup_policy_data, setup_policy_users):
    """Verify CRUD endpoints for response policies, validating tenant isolation & authorization."""
    headers_a = setup_policy_users["headers_a"]
    headers_b = setup_policy_users["headers_b"]
    db = db_manager.db

    payload = {
        "policy_id": "POL-100",
        "name": "Host Isolation Policy A",
        "action": "ISOLATE_HOST",
        "minimum_confidence": 75.0,
        "required_evidence": ["DETECTION", "IOC"],
        "allowed_severity": ["HIGH", "CRITICAL"],
        "approval_mode": "ALLOW_AUTO",
        "priority": 10
    }

    # 1. CREATE policy via Org A
    res = await client.post("/api/v1/response-policies", json=payload, headers=headers_a)
    assert res.status_code == 201
    assert res.json()["policy_id"] == "POL-100"
    assert res.json()["version"] == 1

    # 2. GET policy details
    res_get = await client.get(f"/api/v1/response-policies/POL-100", headers=headers_a)
    assert res_get.status_code == 200
    assert res_get.json()["name"] == "Host Isolation Policy A"

    # 3. Tenant isolation check: GET via Org B should return 404
    res_get_b = await client.get(f"/api/v1/response-policies/POL-100", headers=headers_b)
    assert res_get_b.status_code == 404

    # 4. UPDATE policy (Org A)
    update_payload = {"name": "Host Isolation Policy A Updated", "approval_mode": "REQUIRE_HUMAN"}
    res_update = await client.put(f"/api/v1/response-policies/POL-100", json=update_payload, headers=headers_a)
    assert res_update.status_code == 200
    assert res_update.json()["name"] == "Host Isolation Policy A Updated"
    assert res_update.json()["version"] == 2
    assert res_update.json()["approval_mode"] == "REQUIRE_HUMAN"

    # Verify historical version was snapshotted
    versions = await db["response_policy_versions"].find({"policy_id": "POL-100"}).to_list(length=10)
    assert len(versions) == 1
    assert versions[0]["version"] == 1

    # 5. LIST policies
    res_list = await client.get("/api/v1/response-policies", headers=headers_a)
    assert res_list.status_code == 200
    assert len(res_list.json()) == 1

    # 6. DELETE policy
    res_del = await client.delete(f"/api/v1/response-policies/POL-100", headers=headers_a)
    assert res_del.status_code == 204

    # Verify soft deleted
    res_get_deleted = await client.get(f"/api/v1/response-policies/POL-100", headers=headers_a)
    assert res_get_deleted.status_code == 404

@pytest.mark.anyio
async def test_policy_evaluation_engine_priority_match(setup_policy_data):
    """Verify that the policy evaluator matches rules correctly and respects priority precedence."""
    org_a = setup_policy_data["org_a"]
    db = db_manager.db

    # Seed two active policies with different priorities
    await db["response_policies"].insert_one({
        "organization_id": org_a,
        "policy_id": "POL-LOW-PRIO",
        "name": "Fallback Quarantine",
        "action": "QUARANTINE_EMAIL",
        "minimum_confidence": 10.0,
        "approval_mode": "REQUIRE_HUMAN",
        "priority": 1,
        "status": "active",
        "enabled": True,
        "soft_delete": False
    })
    await db["response_policies"].insert_one({
        "organization_id": org_a,
        "policy_id": "POL-HIGH-PRIO",
        "name": "Auto Quarantine High Confidence",
        "action": "QUARANTINE_EMAIL",
        "minimum_confidence": 80.0,
        "approval_mode": "ALLOW_AUTO",
        "priority": 10,
        "status": "active",
        "enabled": True,
        "soft_delete": False
    })

    # Case A: Confidence = 90 -> Matches both, but POL-HIGH-PRIO wins (priority 10) -> ALLOW_AUTO
    decision_payload = {
        "recommended_action": "QUARANTINE_EMAIL",
        "confidence_score": 90.0,
        "severity": "HIGH",
        "evidence_refs": [{"source_type": "DETECTION", "source_id": "D-1"}],
        "signal_summary": {}
    }
    res_a = await response_policy_service.evaluate_decision(org_a, decision_payload)
    assert res_a["decision"] == "ALLOW_AUTO"
    assert res_a["policy_id"] == "POL-HIGH-PRIO"

    # Case B: Confidence = 50 -> Fails POL-HIGH-PRIO confidence gate, falls back to POL-LOW-PRIO -> REQUIRE_HUMAN
    decision_payload["confidence_score"] = 50.0
    res_b = await response_policy_service.evaluate_decision(org_a, decision_payload)
    assert res_b["decision"] == "REQUIRE_HUMAN"
    assert res_b["policy_id"] == "POL-LOW-PRIO"

@pytest.mark.anyio
async def test_policy_evaluation_fallback_defaults(setup_policy_data):
    """Verify that unconfigured actions fall back to default global policy safeguards."""
    org_a = setup_policy_data["org_a"]

    # 1. High risk/destructive actions (e.g. ISOLATE_HOST) fallback to REQUIRE_HUMAN
    decision_payload = {
        "recommended_action": "ISOLATE_HOST",
        "confidence_score": 80.0,
        "severity": "MEDIUM",
        "risk_score": 50.0,
        "evidence_refs": [],
        "signal_summary": {}
    }
    res_destructive = await response_policy_service.evaluate_decision(org_a, decision_payload)
    assert res_destructive["decision"] == "REQUIRE_HUMAN"
    assert res_destructive["reason_code"] == "GLOBAL_DEFAULT_FALLBACK"

    # 2. Low risk/monitoring actions (e.g. MONITOR) fallback to ALLOW_AUTO
    decision_payload["recommended_action"] = "MONITOR"
    res_low_risk = await response_policy_service.evaluate_decision(org_a, decision_payload)
    assert res_low_risk["decision"] == "ALLOW_AUTO"

    # 3. High risk score override (risk_score >= 80) triggers REQUIRE_HUMAN on monitor
    decision_payload["risk_score"] = 85.0
    res_high_risk = await response_policy_service.evaluate_decision(org_a, decision_payload)
    assert res_high_risk["decision"] == "REQUIRE_HUMAN"

@pytest.mark.anyio
async def test_emergency_controls_kill_switches(setup_policy_data):
    """Verify Global, Tenant, Action, Playbook, and User scope emergency blocks immediately yield DENY."""
    org_a = setup_policy_data["org_a"]
    db = db_manager.db

    decision_payload = {
        "recommended_action": "ISOLATE_HOST",
        "recommended_playbook_id": "PLAYBOOK-100",
        "confidence_score": 90.0,
        "severity": "CRITICAL",
        "evidence_refs": [],
        "signal_summary": {}
    }

    # 1. Test GLOBAL_DISABLE
    await db["sys_config"].delete_many({})
    await db["sys_config"].insert_one({"config_key": "soar_execution_enabled", "config_value": False})
    res_global = await response_policy_service.evaluate_decision(org_a, decision_payload)
    assert res_global["decision"] == "DENY"
    assert res_global["reason_code"] == "GLOBAL_DISABLE"

    # Re-enable global
    await db["sys_config"].update_one({"config_key": "soar_execution_enabled"}, {"$set": {"config_value": True}})

    # 2. Test TENANT_DISABLE
    await db["sys_config"].insert_one({"config_key": f"soar_execution_enabled:{org_a}", "config_value": False})
    res_tenant = await response_policy_service.evaluate_decision(org_a, decision_payload)
    assert res_tenant["decision"] == "DENY"
    assert res_tenant["reason_code"] == "TENANT_DISABLE"

    await db["sys_config"].delete_many({"config_key": f"soar_execution_enabled:{org_a}"})

    # 3. Test ACTION_DISABLE
    await db["sys_config"].insert_one({"config_key": f"soar_execution_enabled:action:ISOLATE_HOST", "config_value": False})
    res_action = await response_policy_service.evaluate_decision(org_a, decision_payload)
    assert res_action["decision"] == "DENY"
    assert res_action["reason_code"] == "ACTION_DISABLE"

    await db["sys_config"].delete_many({"config_key": f"soar_execution_enabled:action:ISOLATE_HOST"})

    # 4. Test PLAYBOOK_DISABLE
    await db["sys_config"].insert_one({"config_key": f"soar_execution_enabled:playbook:PLAYBOOK-100", "config_value": False})
    res_playbook = await response_policy_service.evaluate_decision(org_a, decision_payload)
    assert res_playbook["decision"] == "DENY"
    assert res_playbook["reason_code"] == "PLAYBOOK_DISABLE"

    await db["sys_config"].delete_many({"config_key": f"soar_execution_enabled:playbook:PLAYBOOK-100"})

    # 5. Test USER_SCOPE_DISABLE
    await db["sys_config"].insert_one({"config_key": f"soar_execution_enabled:user:user-999", "config_value": False})
    res_user = await response_policy_service.evaluate_decision(org_a, decision_payload, user_id="user-999")
    assert res_user["decision"] == "DENY"
    assert res_user["reason_code"] == "USER_SCOPE_DISABLE"

@pytest.mark.anyio
async def test_policy_simulation_api(client: AsyncClient, setup_policy_data, setup_policy_users):
    """Verify policy simulations REST endpoint matches logic dry-runs and supports proposed overrides."""
    headers_a = setup_policy_users["headers_a"]
    org_a = setup_policy_data["org_a"]
    db = db_manager.db

    decision_ctx = {
        "decision_id": "6a852f8d8437c6aadc4abe99",
        "recommended_action": "MONITOR",
        "confidence_score": 95.0,
        "severity": "CRITICAL",
        "risk_score": 75.0,
        "evidence_refs": [{"source_type": "IOC", "source_id": "ioc-1"}],
        "signal_summary": {"threat_reputation": "malicious"}
    }

    # Simulate with active global default -> ALLOW_AUTO
    payload = {
        "decision_payload": decision_ctx
    }
    res_sim1 = await client.post("/api/v1/response-policies/simulate", json=payload, headers=headers_a)
    assert res_sim1.status_code == 200
    assert res_sim1.json()["decision"] == "ALLOW_AUTO"
    assert res_sim1.json()["reason_code"] == "GLOBAL_DEFAULT_FALLBACK"

    # Simulate with temporary proposed policy payload override -> REQUIRE_HUMAN
    payload_propose = {
        "policy_id": "POL-PROP-1",
        "action": "MONITOR",
        "minimum_confidence": 90.0,
        "approval_mode": "REQUIRE_HUMAN"
    }
    payload["policy_payload"] = payload_propose

    res_sim2 = await client.post("/api/v1/response-policies/simulate", json=payload, headers=headers_a)
    assert res_sim2.status_code == 200
    assert res_sim2.json()["decision"] == "REQUIRE_HUMAN"
    assert res_sim2.json()["policy_id"] == "POL-PROP-1"
    assert res_sim2.json()["reason_code"] == "TENANT_POLICY_MATCH"

    # Verify dry-run was logged in Simulations collection
    sims = await db["response_policy_simulations"].find({"organization_id": org_a}).to_list(length=10)
    assert len(sims) == 2

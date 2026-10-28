import pytest
from httpx import AsyncClient
from datetime import datetime, timezone, timedelta
from bson import ObjectId

from app.database.connection import db_manager
from app.services.response_decision_service import response_decision_service

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

    return {
        "org_a": org_a,
        "org_b": org_b,
        "incident_id": "EVT-INC-123",
        "campaign_id": str(campaign.inserted_id),
        "finding_id": str(finding.inserted_id)
    }

@pytest.mark.anyio
async def test_remediation_approval_requirements(setup_remediation_data):
    """Verify that action risk classifications correctly set approval requirements."""
    org_a = setup_remediation_data["org_a"]
    incident_id = setup_remediation_data["incident_id"]

    # High-risk action: ISOLATE_HOST -> approval mandatory, status PENDING_APPROVAL
    decision_high = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="ISOLATE_HOST",
        incident_id=incident_id
    )
    assert decision_high["approval_required"] is True
    assert decision_high["status"] == "PENDING_APPROVAL"

    # Low-risk action: MONITOR -> approval not required, status RECOMMENDED
    decision_low = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="MONITOR",
        incident_id=incident_id
    )
    assert decision_low["approval_required"] is False
    assert decision_low["status"] == "RECOMMENDED"

@pytest.mark.anyio
async def test_remediation_idempotency(setup_remediation_data):
    """Ensure duplicate recommendation actions for the same incident are prevented."""
    org_a = setup_remediation_data["org_a"]
    incident_id = setup_remediation_data["incident_id"]

    # Create recommendation
    r1 = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="QUARANTINE_EMAIL",
        incident_id=incident_id
    )
    r1_id = r1["_id"]

    # Create again -> must return identical ID
    r2 = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="QUARANTINE_EMAIL",
        incident_id=incident_id
    )
    assert r2["_id"] == r1_id

@pytest.mark.anyio
async def test_remediation_state_transitions(setup_remediation_data):
    """Verify valid state transitions and audit logging."""
    org_a = setup_remediation_data["org_a"]
    incident_id = setup_remediation_data["incident_id"]
    db = db_manager.db

    # Initialize a PENDING_APPROVAL recommendation
    decision = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="RESET_CREDENTIAL",
        incident_id=incident_id
    )
    dec_id = decision["_id"]

    # Invalid: PENDING_APPROVAL -> RECOMMENDED
    with pytest.raises(ValueError):
        await response_decision_service.update_decision_status(org_a, dec_id, "RECOMMENDED", "analyst_1")

    # Valid: PENDING_APPROVAL -> APPROVED
    updated = await response_decision_service.update_decision_status(org_a, dec_id, "APPROVED", "analyst_1")
    assert updated["status"] == "APPROVED"

    # Terminal state: APPROVED cannot transition further
    with pytest.raises(ValueError):
        await response_decision_service.update_decision_status(org_a, dec_id, "REJECTED", "analyst_1")

    # Verify audit logs insertion
    audits = await db["audit_logs"].find({
        "organization_id": org_a,
        "action": "RESPONSE_APPROVED"
    }).to_list()
    audit = next((a for a in audits if a.get("details", {}).get("decision_id") == dec_id), None)
    assert audit is not None
    assert audit["user_id"] == "analyst_1"

@pytest.mark.anyio
async def test_remediation_tenant_isolation(setup_remediation_data):
    """Verify Org A cannot view, retrieve, or approve Org B recommendations."""
    org_a = setup_remediation_data["org_a"]
    org_b = setup_remediation_data["org_b"]
    incident_id = setup_remediation_data["incident_id"]

    # Create recommendation under Org A
    decision_a = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="ISOLATE_HOST",
        incident_id=incident_id
    )
    dec_id = decision_a["_id"]

    # Org B trying to fetch -> must return None
    fetched_b = await response_decision_service.get_decision(org_b, dec_id)
    assert fetched_b is None

    # Org B trying to approve -> must fail with ValueError
    with pytest.raises(ValueError):
        await response_decision_service.update_decision_status(org_b, dec_id, "APPROVED", "analyst_b")

@pytest.mark.anyio
async def test_remediation_signal_grounding(setup_remediation_data):
    """Verify E11.3 findings and E11.6 campaigns are mapped as evidence references."""
    org_a = setup_remediation_data["org_a"]
    incident_id = setup_remediation_data["incident_id"]
    campaign_id = setup_remediation_data["campaign_id"]
    finding_id = setup_remediation_data["finding_id"]

    decision = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="ISOLATE_HOST",
        incident_id=incident_id,
        campaign_id=campaign_id
    )

    evidence_sources = [ref["source_type"] for ref in decision["evidence_refs"]]
    evidence_ids = [ref["source_id"] for ref in decision["evidence_refs"]]

    assert "FINDING" in evidence_sources
    assert finding_id in evidence_ids
    assert "CAMPAIGN" in evidence_sources
    assert campaign_id in evidence_ids
    assert decision["signal_summary"]["detections_count"] == 1
    assert decision["signal_summary"]["campaigns_count"] == 1

@pytest.mark.anyio
async def test_response_intelligence_api(client: AsyncClient):
    """Verify HTTP API endpoints for response intelligence including RBAC and boundary controls."""
    db = db_manager.db
    org_a = "org_api_a"
    org_b = "org_api_b"

    # Reset users and databases
    await db["users"].delete_many({"email": {"$in": ["admin_a@enterprise.com", "admin_b@enterprise.com"]}})
    await db["response_decisions"].delete_many({})
    await db["audit_logs"].delete_many({})

    # 1. Register & Setup Org A User
    await client.post("/api/v1/auth/register", json={
        "email": "admin_a@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Admin A"
    })
    user_a = await db["users"].find_one({"email": "admin_a@enterprise.com"})
    await db["users"].update_one({"_id": user_a["_id"]}, {"$set": {"role": "admin", "organization_id": org_a}})
    await db["organization_memberships"].insert_one({
        "organization_id": org_a,
        "user_id": str(user_a["_id"]),
        "role": "admin",
        "soft_delete": False
    })

    login_a = await client.post("/api/v1/auth/login", json={
        "email": "admin_a@enterprise.com",
        "password": "StrongPassword123!"
    })
    headers_a = {"Authorization": f"Bearer {login_a.json()['access_token']}"}

    # 2. Register & Setup Org B User
    await client.post("/api/v1/auth/register", json={
        "email": "admin_b@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Admin B"
    })
    user_b = await db["users"].find_one({"email": "admin_b@enterprise.com"})
    await db["users"].update_one({"_id": user_b["_id"]}, {"$set": {"role": "admin", "organization_id": org_b}})
    await db["organization_memberships"].insert_one({
        "organization_id": org_b,
        "user_id": str(user_b["_id"]),
        "role": "admin",
        "soft_delete": False
    })

    login_b = await client.post("/api/v1/auth/login", json={
        "email": "admin_b@enterprise.com",
        "password": "StrongPassword123!"
    })
    headers_b = {"Authorization": f"Bearer {login_b.json()['access_token']}"}

    # 3. Create recommendation under Org A
    res_create = await client.post("/api/v1/response-intelligence/decisions", json={
        "recommended_action": "ISOLATE_HOST",
        "incident_id": "INC-A-999"
    }, headers=headers_a)
    assert res_create.status_code == 201
    decision_id = res_create.json()["_id"]

    # 4. List decisions Org A -> should find 1
    res_list_a = await client.get("/api/v1/response-intelligence/decisions", headers=headers_a)
    assert res_list_a.status_code == 200
    assert len(res_list_a.json()) == 1
    assert res_list_a.json()[0]["_id"] == decision_id

    # 5. List decisions Org B -> should find 0
    res_list_b = await client.get("/api/v1/response-intelligence/decisions", headers=headers_b)
    assert res_list_b.status_code == 200
    assert len(res_list_b.json()) == 0

    # 6. Retrieve single Org A decision with Org B token -> should fail 404
    res_get_b = await client.get(f"/api/v1/response-intelligence/decisions/{decision_id}", headers=headers_b)
    assert res_get_b.status_code == 404

    # 7. Approve Org A decision with Org B token -> should fail with 400 or 404 (Raise 404 because not found in Org B context)
    res_approve_b = await client.patch(
        f"/api/v1/response-intelligence/decisions/{decision_id}/status",
        json={"status": "APPROVED"},
        headers=headers_b
    )
    assert res_approve_b.status_code == 400 or res_approve_b.status_code == 404

    # 8. Approve Org A decision with Org A token -> success
    res_approve_a = await client.patch(
        f"/api/v1/response-intelligence/decisions/{decision_id}/status",
        json={"status": "APPROVED"},
        headers=headers_a
    )
    assert res_approve_a.status_code == 200
    assert res_approve_a.json()["status"] == "APPROVED"

@pytest.mark.anyio
async def test_remediation_scoring_dynamic():
    """Verify dynamic weighted risk scoring logic."""
    from app.services.response_risk_engine import ResponseRiskEngine
    
    org_a = "org_remed_a"
    
    # 1. Critical risk scenario
    signals_critical = {
        "detection": {"score": 90.0, "organization_id": org_a},
        "threat_intel": {"score": 95.0, "organization_id": org_a},
        "campaign": {"score": 80.0, "organization_id": org_a},
        "ueba": {"score": 75.0, "organization_id": org_a},
        "investigation": {"score": 85.0, "organization_id": org_a}
    }
    calc_crit = ResponseRiskEngine.calculate_decision(org_a, signals_critical)
    assert calc_crit["risk_score"] >= 80
    assert calc_crit["severity"] == "CRITICAL"
    assert calc_crit["approval_required"] is True

    # 2. Low risk scenario
    signals_low = {
        "detection": {"score": 10.0, "organization_id": org_a},
        "threat_intel": {"score": 15.0, "organization_id": org_a},
        "campaign": {"score": 5.0, "organization_id": org_a},
        "ueba": {"score": 0.0, "organization_id": org_a},
        "investigation": {"score": 0.0, "organization_id": org_a}
    }
    calc_low = ResponseRiskEngine.calculate_decision(org_a, signals_low)
    assert calc_low["risk_score"] <= 15
    assert calc_low["severity"] == "LOW"
    assert calc_low["recommended_action"] == "MONITOR"
    assert calc_low["approval_required"] is False

@pytest.mark.anyio
async def test_remediation_input_validation_safety():
    """Ensure NaN, Infinity, negative values, and malformed signals are rejected."""
    from app.services.response_risk_engine import ResponseRiskEngine
    org_a = "org_remed_a"

    # Negative score
    with pytest.raises(ValueError):
        ResponseRiskEngine.calculate_decision(org_a, {
            "detection": {"score": -5.0, "organization_id": org_a}
        })

    # NaN score
    with pytest.raises(ValueError):
        ResponseRiskEngine.calculate_decision(org_a, {
            "detection": {"score": float("nan"), "organization_id": org_a}
        })

    # Infinity score
    with pytest.raises(ValueError):
        ResponseRiskEngine.calculate_decision(org_a, {
            "detection": {"score": float("inf"), "organization_id": org_a}
        })

@pytest.mark.anyio
async def test_remediation_cross_tenant_signal_rejected():
    """Verify that signals scoping to another organization are rejected."""
    from app.services.response_risk_engine import ResponseRiskEngine
    org_a = "org_remed_a"
    org_b = "org_remed_b"

    with pytest.raises(ValueError):
        ResponseRiskEngine.calculate_decision(org_a, {
            "detection": {"score": 85.0, "organization_id": org_b} # Org mismatch!
        })

@pytest.mark.anyio
async def test_remediation_signal_agreement_confidence():
    """Verify corroboration boosts confidence, and signal disagreement reduces confidence."""
    from app.services.response_risk_engine import ResponseRiskEngine
    org_a = "org_remed_a"

    # Corroborating: Detection high + threat intel high
    signals_corrob = {
        "detection": {"score": 80.0, "confidence": 80.0, "organization_id": org_a},
        "threat_intel": {"score": 85.0, "confidence": 80.0, "organization_id": org_a},
        "campaign": {"score": 80.0, "confidence": 80.0, "organization_id": org_a}
    }
    calc_corrob = ResponseRiskEngine.calculate_decision(org_a, signals_corrob)
    # Average base confidence = 80. Boost of +15 + 10 = +25. Capped at 100.
    assert calc_corrob["confidence_score"] == 100

    # Conflicting: Detection high + threat intel low
    signals_conflict = {
        "detection": {"score": 80.0, "confidence": 80.0, "organization_id": org_a},
        "threat_intel": {"score": 10.0, "confidence": 80.0, "organization_id": org_a}
    }
    calc_conflict = ResponseRiskEngine.calculate_decision(org_a, signals_conflict)
    # Average base confidence = 80. Penalty of -20 = 60.
    assert calc_conflict["confidence_score"] == 60

@pytest.mark.anyio
async def test_remediation_api_evaluate_recalculate(client: AsyncClient, setup_remediation_data):
    """Verify HTTP evaluate route triggers recalculations and records score logs."""
    db = db_manager.db
    org_a = setup_remediation_data["org_a"]
    incident_id = setup_remediation_data["incident_id"]

    # Clean user
    await db["users"].delete_many({"email": "eval_admin@enterprise.com"})

    # Setup user under org_remed_a
    await client.post("/api/v1/auth/register", json={
        "email": "eval_admin@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Eval Admin"
    })
    user = await db["users"].find_one({"email": "eval_admin@enterprise.com"})
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "organization_id": org_a}})
    await db["organization_memberships"].insert_one({
        "organization_id": org_a,
        "user_id": str(user["_id"]),
        "role": "admin",
        "soft_delete": False
    })

    # Login
    login_res = await client.post("/api/v1/auth/login", json={
        "email": "eval_admin@enterprise.com",
        "password": "StrongPassword123!"
    })
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # 2. Stage a decision recommendation in database
    decision = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="ISOLATE_HOST",
        incident_id=incident_id
    )
    dec_id = decision["_id"]

    # 3. Request evaluation endpoint
    eval_res = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/evaluate", headers=headers)
    assert eval_res.status_code == 200
    assert "risk_score" in eval_res.json()
    assert "decision_trace" in eval_res.json()

    # 4. Check audit logs insertion
    audits = await db["audit_logs"].find({
        "organization_id": org_a,
        "action": "RESPONSE_SCORE_RECALCULATED"
    }).to_list()
    audit = next((a for a in audits if a.get("details", {}).get("decision_id") == dec_id), None)
    assert audit is not None

@pytest.mark.anyio
async def test_playbook_resolution_logic():
    """Verify E6 playbook resolver finds configured playbooks and falls back to defaults."""
    from app.services.response_playbook_service import playbook_resolver
    db = db_manager.db
    org_a = "org_play_a"

    # Clean old configs
    await db["soar_playbooks"].delete_many({"organization_id": org_a})

    # Test Default Fallback
    fallback = await playbook_resolver.resolve_playbook(org_a, "QUARANTINE_EMAIL")
    assert fallback is not None
    assert fallback["playbook_id"] == "PLAYBOOK-EMAIL-QUARANTINE"

    # Seed custom playbook
    await db["soar_playbooks"].insert_one({
        "organization_id": org_a,
        "playbook_id": "CUSTOM-EMAIL-QUARANTINE",
        "playbook_name": "Org A Custom Email Quarantine",
        "action_type": "QUARANTINE_EMAIL",
        "status": "ENABLED",
        "soft_delete": False
    })

    resolved = await playbook_resolver.resolve_playbook(org_a, "QUARANTINE_EMAIL")
    assert resolved is not None
    assert resolved["playbook_id"] == "CUSTOM-EMAIL-QUARANTINE"

@pytest.mark.anyio
async def test_evidence_sufficiency_evaluation():
    """Verify that insufficient evidence downgrades the recommended action to NOTIFY_ANALYST."""
    from app.services.response_playbook_service import evidence_evaluator
    
    # 1. Sufficient: ISOLATE_HOST with FINDING
    res1 = evidence_evaluator.evaluate_evidence_sufficiency("ISOLATE_HOST", [{"source_type": "FINDING"}])
    assert res1["sufficient"] is True

    # 2. Insufficient: ISOLATE_HOST with IOC only
    res2 = evidence_evaluator.evaluate_evidence_sufficiency("ISOLATE_HOST", [{"source_type": "IOC"}])
    assert res2["sufficient"] is False
    assert "FINDING" in res2["missing_types"]

    # 3. Insufficient: Empty evidence
    res3 = evidence_evaluator.evaluate_evidence_sufficiency("ISOLATE_HOST", [])
    assert res3["sufficient"] is False

@pytest.mark.anyio
async def test_playbook_tenant_isolation():
    """Verify Org A cannot query or resolve Org B playbooks."""
    from app.services.response_playbook_service import playbook_resolver
    db = db_manager.db
    org_a = "org_play_a"
    org_b = "org_play_b"

    await db["soar_playbooks"].delete_many({"organization_id": {"$in": [org_a, org_b]}})

    # Seed Org B private playbook
    await db["soar_playbooks"].insert_one({
        "organization_id": org_b,
        "playbook_id": "ORG-B-PRIVATE-PLAYBOOK",
        "playbook_name": "Org B Private Host Isolation",
        "action_type": "ISOLATE_HOST",
        "status": "ENABLED",
        "soft_delete": False
    })

    # Resolve Org A -> should get the built-in fallback playbook rather than Org B's private playbook
    res_a = await playbook_resolver.resolve_playbook(org_a, "ISOLATE_HOST")
    assert res_a is not None
    assert res_a["playbook_id"] == "PLAYBOOK-HOST-ISOLATION"

    # Resolve Org B -> should get the custom private playbook
    res_b = await playbook_resolver.resolve_playbook(org_b, "ISOLATE_HOST")
    assert res_b is not None
    assert res_b["playbook_id"] == "ORG-B-PRIVATE-PLAYBOOK"

@pytest.mark.anyio
async def test_playbook_recommendation_api(client: AsyncClient, setup_remediation_data):
    """Verify recommend and recommendation endpoints generate playbooks and check sufficiency."""
    db = db_manager.db
    org_a = setup_remediation_data["org_a"]
    incident_id = setup_remediation_data["incident_id"]

    # Register/Login
    await db["users"].delete_many({"email": "rec_admin@enterprise.com"})
    await client.post("/api/v1/auth/register", json={
        "email": "rec_admin@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Rec Admin"
    })
    user = await db["users"].find_one({"email": "rec_admin@enterprise.com"})
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "organization_id": org_a}})
    await db["organization_memberships"].insert_one({
        "organization_id": org_a,
        "user_id": str(user["_id"]),
        "role": "admin",
        "soft_delete": False
    })

    login_res = await client.post("/api/v1/auth/login", json={
        "email": "rec_admin@enterprise.com",
        "password": "StrongPassword123!"
    })
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # 1. Create decision without evidence
    decision = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="ISOLATE_HOST",
        incident_id="EVT-INC-EMPTY"
    )
    dec_id = decision["_id"]

    # 2. Trigger recommend POST -> Should fail sufficiency and downgrade to NOTIFY_ANALYST
    rec_res = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/recommend", headers=headers)
    assert rec_res.status_code == 200
    assert rec_res.json()["recommended_action"] == "NOTIFY_ANALYST"
    assert "Evidence insufficient" in "".join(rec_res.json()["safety_constraints"])

    # 3. Trigger recommendation GET -> Should fetch mapped parameters
    get_res = await client.get(f"/api/v1/response-intelligence/decisions/{dec_id}/recommendation", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["recommended_action"] == "NOTIFY_ANALYST"
    playbook_id = get_res.json()["recommended_playbook_id"]
    assert playbook_id is None or "NOTIFY_ANALYST" in playbook_id or "GRC" in playbook_id or playbook_id == "PLAYBOOK-EMAIL-QUARANTINE"

@pytest.mark.anyio
async def test_approval_request_lifecycle(client: AsyncClient, setup_remediation_data):
    """Verify approval state machine transitions: RECOMMENDED -> PENDING -> APPROVED/REJECTED/CANCELLED."""
    db = db_manager.db
    org_a = setup_remediation_data["org_a"]
    incident_id = setup_remediation_data["incident_id"]

    # Login Analyst A (registered as admin)
    await db["users"].delete_many({"email": "analyst_a@enterprise.com"})
    await client.post("/api/v1/auth/register", json={
        "email": "analyst_a@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Analyst A"
    })
    user = await db["users"].find_one({"email": "analyst_a@enterprise.com"})
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "organization_id": org_a}})
    await db["organization_memberships"].insert_one({
        "organization_id": org_a,
        "user_id": str(user["_id"]),
        "role": "admin",
        "soft_delete": False
    })
    login_a = await client.post("/api/v1/auth/login", json={"email": "analyst_a@enterprise.com", "password": "StrongPassword123!"})
    headers_a = {"Authorization": f"Bearer {login_a.json()['access_token']}"}

    # 1. Stage decision
    dec = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="MONITOR", # Low risk action
        incident_id=incident_id,
        created_by=str(user["_id"])
    )
    dec_id = dec["_id"]

    # 2. Request approval
    req_res = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval", headers=headers_a)
    assert req_res.status_code == 200
    assert req_res.json()["status"] == "PENDING_APPROVAL"

    # 3. Retrieve metadata
    meta_res = await client.get(f"/api/v1/response-intelligence/decisions/{dec_id}/approval", headers=headers_a)
    assert meta_res.status_code == 200
    assert meta_res.json()["status"] == "PENDING_APPROVAL"
    assert "authorization_hash" not in meta_res.json() # Block token secret hash disclosure

    # 4. Cancel approval
    cancel_res = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval/cancel", headers=headers_a)
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"

@pytest.mark.anyio
async def test_approval_separation_of_duties(client: AsyncClient, setup_remediation_data):
    """Verify Four-Eyes Principle blocks requester from approving high-risk containment actions."""
    db = db_manager.db
    org_a = setup_remediation_data["org_a"]
    incident_id = setup_remediation_data["incident_id"]

    # Setup User A (admin)
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

    # Setup User B (admin)
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

    # 1. User A creates high-risk recommended decision
    decision = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="ISOLATE_HOST",
        incident_id=incident_id,
        created_by=str(user_a["_id"])
    )
    dec_id = decision["_id"]

    # 2. Request approval
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval", headers=headers_a)

    # 3. User A tries to approve -> Should be blocked 403 (Requester == Approver)
    approve_a = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval/approve", json={"comment": "Self approving"}, headers=headers_a)
    assert approve_a.status_code == 403

    # 4. User B approves -> Succeeds
    approve_b = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval/approve", json={"comment": "Authorized"}, headers=headers_b)
    assert approve_b.status_code == 200
    assert "authorization_secret" in approve_b.json()

@pytest.mark.anyio
async def test_approval_rejection_justification(client: AsyncClient, setup_remediation_data):
    """Verify that rejection requires a valid reason parameter."""
    db = db_manager.db
    org_a = setup_remediation_data["org_a"]
    incident_id = setup_remediation_data["incident_id"]

    # Login
    login_res = await client.post("/api/v1/auth/login", json={"email": "user_b@enterprise.com", "password": "StrongPassword123!"})
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    decision = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="MONITOR",
        incident_id=incident_id
    )
    dec_id = decision["_id"]

    # Request approval
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval", headers=headers)

    # Reject without reason -> Should fail 422/400
    rej_fail = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval/reject", json={}, headers=headers)
    assert rej_fail.status_code in [400, 422]

    # Reject with reason -> Succeeds
    rej_ok = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval/reject", json={"reason": "False Positive"}, headers=headers)
    assert rej_ok.status_code == 200
    assert rej_ok.json()["status"] == "REJECTED"

@pytest.mark.anyio
async def test_approval_validation_anti_replay(client: AsyncClient, setup_remediation_data):
    """Verify validation token single-use execution checks and double-spend replay attacks prevention."""
    db = db_manager.db
    org_a = setup_remediation_data["org_a"]
    incident_id = setup_remediation_data["incident_id"]

    # Login B (to approve)
    login_b = await client.post("/api/v1/auth/login", json={"email": "user_b@enterprise.com", "password": "StrongPassword123!"})
    headers_b = {"Authorization": f"Bearer {login_b.json()['access_token']}"}

    # 1. Setup decision (with sufficient evidence mapping to allow approval resolve)
    decision = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="QUARANTINE_EMAIL",
        incident_id=incident_id,
        created_by="user_a"
    )
    dec_id = decision["_id"]

    # 2. Stage E6 Playbook recommend
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/recommend", headers=headers_b)

    # 3. Request approval and approve
    await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval", headers=headers_b)
    approve_res = await client.post(f"/api/v1/response-intelligence/decisions/{dec_id}/approval/approve", json={"comment": "Accepting"}, headers=headers_b)
    assert approve_res.status_code == 200
    
    secret = approve_res.json()["authorization_secret"]
    token_id = approve_res.json()["authorization_id"]
    playbook_id = approve_res.json()["recommended_playbook_id"]
    action = approve_res.json()["recommended_action"]
    version = approve_res.json().get("recommendation_version", 1)

    payload = {
        "organization_id": org_a,
        "decision_id": dec_id,
        "recommendation_version": version,
        "recommended_action": action,
        "playbook_id": playbook_id,
        "token_id": token_id,
        "token_secret": secret
    }

    # 4. Validate Token -> Should be valid
    val_res = await client.post("/api/v1/response-intelligence/authorizations/validate", json=payload, headers=headers_b)
    assert val_res.status_code == 200
    assert val_res.json()["valid"] is True

    # 5. Consume Token -> Succeeds
    cons_res = await client.post("/api/v1/response-intelligence/authorizations/consume", json=payload, headers=headers_b)
    assert cons_res.status_code == 200
    assert cons_res.json()["consumed"] is True

    # 6. Replay Token -> Should reject consumption
    cons_replay = await client.post("/api/v1/response-intelligence/authorizations/consume", json=payload, headers=headers_b)
    assert cons_replay.status_code == 400

@pytest.mark.anyio
async def test_approval_tenant_isolation_idor(client: AsyncClient, setup_remediation_data):
    """Verify IDOR protections block cross-tenant approvals or validations."""
    db = db_manager.db
    org_a = setup_remediation_data["org_a"]
    org_b = setup_remediation_data["org_b"]
    incident_id = setup_remediation_data["incident_id"]

    # Register/Login Org B user
    await db["users"].delete_many({"email": "admin_b@enterprise.com"})
    await client.post("/api/v1/auth/register", json={
        "email": "admin_b@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Admin B"
    })
    user_b = await db["users"].find_one({"email": "admin_b@enterprise.com"})
    await db["users"].update_one({"_id": user_b["_id"]}, {"$set": {"role": "admin", "organization_id": org_b}})
    await db["organization_memberships"].insert_one({"organization_id": org_b, "user_id": str(user_b["_id"]), "role": "admin", "soft_delete": False})
    
    login_b = await client.post("/api/v1/auth/login", json={"email": "admin_b@enterprise.com", "password": "StrongPassword123!"})
    headers_b = {"Authorization": f"Bearer {login_b.json()['access_token']}"}

    # Create Org A decision
    decision_a = await response_decision_service.create_response_decision(
        organization_id=org_a,
        recommended_action="MONITOR",
        incident_id=incident_id
    )
    dec_a_id = decision_a["_id"]

    # 1. Org B user requests Org A's approval -> Should fail 404/403
    cross_req = await client.post(f"/api/v1/response-intelligence/decisions/{dec_a_id}/approval", headers=headers_b)
    assert cross_req.status_code in [400, 403, 404]

    # 2. Org B user tries to fetch Org A's approval -> Should return 404
    cross_get = await client.get(f"/api/v1/response-intelligence/decisions/{dec_a_id}/approval", headers=headers_b)
    assert cross_get.status_code == 404





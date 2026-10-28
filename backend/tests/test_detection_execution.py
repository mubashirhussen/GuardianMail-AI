import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from app.services.detection_execution_service import detection_execution_service
from app.repositories.data_platform_repo import TelemetryRepository
from app.repositories.detection_repo import DetectionRuleRepository, DetectionVersionRepository
from app.repositories.detection_execution_repo import DetectionFindingRepository
from app.repositories.incident_repo import IncidentRepository
from app.database.connection import db_manager

@pytest.fixture
async def admin_token_headers(client: AsyncClient):
    """Fixture to register, authorize, and return token headers for test requests."""
    db = db_manager.db
    email = "analyst-exec@enterprise.com"
    await db["users"].delete_many({"email": email})
    
    await client.post("/api/v1/auth/register", json={
        "email": email,
        "password": "StrongPassword123!",
        "full_name": "SOC Analyst"
    })
    user = await db["users"].find_one({"email": email})
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "organization_id": "org_a_tenant"}})
    
    await db["organization_memberships"].delete_many({"user_id": str(user["_id"])})
    await db["organization_memberships"].insert_one({
        "organization_id": "org_a_tenant",
        "user_id": str(user["_id"]),
        "role": "admin",
        "soft_delete": False
    })
    
    login_res = await client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "StrongPassword123!"
    })
    return {"Authorization": f"Bearer {login_res.json()['access_token']}"}

@pytest.fixture
async def setup_execution_data():
    """Setup test rule, version, and telemetry event data partitions."""
    db = db_manager.db
    rule_repo = DetectionRuleRepository(db)
    version_repo = DetectionVersionRepository(db)
    telemetry_repo = TelemetryRepository(db)
    finding_repo = DetectionFindingRepository(db)
    incident_repo = IncidentRepository(db)

    # Clean collections
    await rule_repo.collection.delete_many({})
    await version_repo.collection.delete_many({})
    await telemetry_repo.collection.delete_many({})
    await finding_repo.collection.delete_many({})
    await incident_repo.collection.delete_many({})

    org_a = "org_a_tenant"
    org_b = "org_b_tenant"

    # ACTIVE rule for Org A
    active_rule = {
        "organization_id": org_a,
        "rule_id": "RULE-001",
        "name": "Admin Login Detection",
        "description": "Detects login activities from admin user context.",
        "status": "ACTIVE",
        "severity": "HIGH",
        "confidence": "HIGH",
        "author": "analyst_a",
        "data_sources": ["login"],
        "conditions": {"user": "admin", "event_type": "login"},
        "time_window": 60,
        "mitre_attack_techniques": ["T1078"],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "soft_delete": False
    }
    await rule_repo.collection.insert_one(active_rule)

    version_doc = {
        "organization_id": org_a,
        "rule_id": "RULE-001",
        "version_number": 1,
        "conditions": {"user": "admin", "event_type": "login"},
        "author": "analyst_a",
        "change_info": "Initial version",
        "created_at": datetime.now(timezone.utc),
        "soft_delete": False
    }
    await version_repo.collection.insert_one(version_doc)

    # DRAFT rule for Org A (should be skipped in production execution)
    draft_rule = {
        "organization_id": org_a,
        "rule_id": "RULE-002",
        "name": "Draft Rule",
        "description": "Draft rule that should not execute.",
        "status": "DRAFT",
        "severity": "LOW",
        "conditions": {"event_type": "syslog"},
        "data_sources": ["syslog"],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "soft_delete": False
    }
    await rule_repo.collection.insert_one(draft_rule)

    # Telemetry events
    matching_event = {
        "organization_id": org_a,
        "event_id": "EVT-100",
        "event_type": "login",
        "timestamp": datetime.now(timezone.utc),
        "severity": "medium",
        "source": "127.0.0.1",
        "payload": {
            "user": "admin",
            "auth_token": "secret_session_token_xyz"
        },
        "partition_key": "2026-08-14",
        "soft_delete": False
    }
    await telemetry_repo.collection.insert_one(matching_event)

    non_matching_event = {
        "organization_id": org_a,
        "event_id": "EVT-200",
        "event_type": "login",
        "timestamp": datetime.now(timezone.utc),
        "severity": "low",
        "source": "127.0.0.1",
        "payload": {
            "user": "regular_user"
        },
        "partition_key": "2026-08-14",
        "soft_delete": False
    }
    await telemetry_repo.collection.insert_one(non_matching_event)

    return {
        "org_a": org_a,
        "org_b": org_b,
        "evt_match_id": "EVT-100",
        "evt_nomatch_id": "EVT-200"
    }

@pytest.mark.asyncio
async def test_production_eligibility_and_evaluation(setup_execution_data):
    """Verify that only ACTIVE detection rules match eligible events."""
    data = setup_execution_data
    org_id = data["org_a"]

    # Evaluate matching event
    findings = await detection_execution_service.execute_telemetry_detections(org_id, data["evt_match_id"])
    assert len(findings) == 1
    finding = findings[0]
    assert finding["detection_id"] == "RULE-001"
    assert finding["severity"] == "HIGH"

    # Evaluate non-matching event
    no_findings = await detection_execution_service.execute_telemetry_detections(org_id, data["evt_nomatch_id"])
    assert len(no_findings) == 0

@pytest.mark.asyncio
async def test_idempotency_gate(setup_execution_data):
    """Verify that repeated executions for the same event do not create duplicate findings."""
    data = setup_execution_data
    org_id = data["org_a"]

    # First run
    findings1 = await detection_execution_service.execute_telemetry_detections(org_id, data["evt_match_id"])
    assert len(findings1) == 1

    # Second run (retry simulation)
    findings2 = await detection_execution_service.execute_telemetry_detections(org_id, data["evt_match_id"])
    assert len(findings2) == 1
    assert findings1[0]["_id"] == findings2[0]["_id"]

    # Verify that only 1 finding is stored in DB
    total = await detection_execution_service.finding_repo.collection.count_documents({
        "organization_id": org_id,
        "event_id": data["evt_match_id"]
    })
    assert total == 1

@pytest.mark.asyncio
async def test_tenant_isolation_safeguard(setup_execution_data):
    """Verify that a rule from Org A cannot be evaluated against Org B's telemetry."""
    data = setup_execution_data
    
    # Run Org A detection query on Org B event
    # Create Org B event containing Org A's rule trigger payload
    db = db_manager.db
    org_b_evt = {
        "organization_id": data["org_b"],
        "event_id": "EVT-B-100",
        "event_type": "login",
        "timestamp": datetime.now(timezone.utc),
        "severity": "medium",
        "source": "127.0.0.1",
        "payload": {
            "user": "admin"
        },
        "partition_key": "2026-08-14",
        "soft_delete": False
    }
    await TelemetryRepository(db).collection.insert_one(org_b_evt)

    # Executing for Org B should find 0 matches because Org A's rule is partition isolated
    findings = await detection_execution_service.execute_telemetry_detections(data["org_b"], "EVT-B-100")
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_credentials_leakage_redaction(setup_execution_data):
    """Verify that sensitive credentials keys are redacted from the findings evidence block."""
    data = setup_execution_data
    org_id = data["org_a"]

    findings = await detection_execution_service.execute_telemetry_detections(org_id, data["evt_match_id"])
    assert len(findings) == 1
    evidence_payload = findings[0]["evidence"]["payload"]
    assert evidence_payload["auth_token"] == "[REDACTED]"
    assert evidence_payload["user"] == "admin"

@pytest.mark.asyncio
async def test_case_incident_correlation(setup_execution_data):
    """Verify findings escalate to new incidents, and correlate/append to existing incidents within 2 hours."""
    data = setup_execution_data
    org_id = data["org_a"]

    # 1. First match -> Escalates to new incident
    findings1 = await detection_execution_service.execute_telemetry_detections(org_id, data["evt_match_id"])
    inc_id = findings1[0]["incident_id"]
    assert inc_id is not None

    # Fetch incident
    inc_record = await IncidentRepository(db_manager.db).collection.find_one({"incident_id": inc_id})
    assert inc_record is not None
    assert inc_record["affected_user"] == "admin"

    # 2. Second telemetry event for same user admin (within 2 hours) -> Correlates to same incident
    another_event = {
        "organization_id": org_id,
        "event_id": "EVT-101",
        "event_type": "login",
        "timestamp": datetime.now(timezone.utc),
        "severity": "high",
        "source": "127.0.0.1",
        "payload": {
            "user": "admin"
        },
        "partition_key": "2026-08-14",
        "soft_delete": False
    }
    await TelemetryRepository(db_manager.db).collection.insert_one(another_event)

    findings2 = await detection_execution_service.execute_telemetry_detections(org_id, "EVT-101")
    assert len(findings2) == 1
    assert findings2[0]["incident_id"] == inc_id  # Reused same incident id!

@pytest.mark.asyncio
async def test_findings_and_stats_rest_api(setup_execution_data, client: AsyncClient, admin_token_headers):
    """Verify REST API retrieval of findings and real-time execution statistics."""
    # Execute detection to create a finding and stats
    await detection_execution_service.execute_telemetry_detections("org_a_tenant", "EVT-100")

    # List findings
    res = await client.get("/api/v1/detections/findings", headers=admin_token_headers)
    assert res.status_code == 200
    findings_list = res.json()
    assert isinstance(findings_list, list)
    assert len(findings_list) == 1

    # Get specific finding
    finding_id = findings_list[0]["_id"]
    res_f = await client.get(f"/api/v1/detections/findings/{finding_id}", headers=admin_token_headers)
    assert res_f.status_code == 200
    assert res_f.json()["_id"] == finding_id

    # Fetch stats
    res_stats = await client.get("/api/v1/detections/execution-stats", headers=admin_token_headers)
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert "events_processed" in stats
    assert "matches" in stats
    assert "no_matches" in stats

import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient

from app.database.connection import db_manager
from app.services.threat_hunting_service import threat_hunting_service
from app.repositories.data_platform_repo import TelemetryRepository
from app.repositories.threat_hunting_repo import ThreatHuntSessionRepository, HuntFindingRepository
from app.repositories.threat_intelligence_repo import ThreatIndicatorRepository
from app.repositories.detection_execution_repo import DetectionFindingRepository
from app.repositories.incident_repo import IncidentRepository

@pytest.fixture
async def admin_token_headers(client: AsyncClient):
    """Fixture to authorize and return token headers for test requests."""
    db = db_manager.db
    email = "analyst-hunt@enterprise.com"
    await db["users"].delete_many({"email": email})
    
    await client.post("/api/v1/auth/register", json={
        "email": email,
        "password": "StrongPassword123!",
        "full_name": "Hunt Analyst"
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
async def setup_hunting_data():
    """Setup test telemetry, threat indicators, ML features, and findings."""
    db = db_manager.db
    
    # Repositories
    telemetry_repo = TelemetryRepository(db)
    session_repo = ThreatHuntSessionRepository(db)
    finding_repo = HuntFindingRepository(db)
    indicator_repo = ThreatIndicatorRepository(db)
    det_finding_repo = DetectionFindingRepository(db)
    incident_repo = IncidentRepository(db)

    # Clean collections
    await telemetry_repo.collection.delete_many({})
    await session_repo.collection.delete_many({})
    await finding_repo.collection.delete_many({})
    await db["threat_indicators"].delete_many({})
    await db["ml_features"].delete_many({})
    await det_finding_repo.collection.delete_many({})
    await incident_repo.collection.delete_many({})

    org_a = "org_a_tenant"
    org_b = "org_b_tenant"

    # 1. Telemetry Events
    # Event 1 (Org A): login, admin user
    await telemetry_repo.collection.insert_one({
        "organization_id": org_a,
        "event_id": "EVT-ORG-A-1",
        "event_type": "login",
        "severity": "high",
        "source": "10.0.0.1",
        "timestamp": datetime.now(timezone.utc) - timedelta(minutes=5),
        "rolling_rate_60s": 15,
        "user_id": "user_admin",
        "payload": {
            "user": "admin",
            "ip": "10.0.0.1",
            "domain": "phish-brand.com"
        },
        "soft_delete": False
    })

    # Event 2 (Org A): file_access, guest user
    await telemetry_repo.collection.insert_one({
        "organization_id": org_a,
        "event_id": "EVT-ORG-A-2",
        "event_type": "file_access",
        "severity": "low",
        "source": "10.0.0.2",
        "timestamp": datetime.now(timezone.utc) - timedelta(minutes=30),
        "rolling_rate_60s": 2,
        "user_id": "user_guest",
        "payload": {
            "user": "guest",
            "ip": "10.0.0.2",
            "domain": "clean.com"
        },
        "soft_delete": False
    })

    # Event 3 (Org B): login, admin user
    await telemetry_repo.collection.insert_one({
        "organization_id": org_b,
        "event_id": "EVT-ORG-B-1",
        "event_type": "login",
        "severity": "high",
        "source": "10.0.0.3",
        "timestamp": datetime.now(timezone.utc) - timedelta(minutes=5),
        "rolling_rate_60s": 20,
        "user_id": "user_admin",
        "payload": {
            "user": "admin",
            "ip": "10.0.0.3",
            "domain": "phish-brand.com"
        },
        "soft_delete": False
    })

    # 2. E4 Threat Indicators
    await db["threat_indicators"].insert_one({
        "organization_id": org_a,
        "value": "phish-brand.com",
        "normalized_value": "phish-brand.com",
        "indicator_type": "domain",
        "severity": "HIGH",
        "description": "Known phishing domain from threat intel feeds",
        "created_at": datetime.now(timezone.utc),
        "soft_delete": False
    })

    # 3. E9 ML Features (UEBA Anomaly Store)
    await db["ml_features"].insert_one({
        "organization_id": org_a,
        "feature_id": "FEAT-USER-RISK",
        "entity_id": "user_admin",
        "feature_name": "user_risk_score",
        "value": 0.85,
        "updated_at": datetime.now(timezone.utc),
        "soft_delete": False
    })

    # 4. E11.3 Detection Findings
    await det_finding_repo.collection.insert_one({
        "organization_id": org_a,
        "event_id": "EVT-ORG-A-1",
        "detection_id": "RULE-001",
        "severity": "HIGH",
        "status": "NEW",
        "mitre_attack_techniques": ["T1078"],
        "idempotency_key": f"{org_a}:RULE-001:1:EVT-ORG-A-1",
        "created_at": datetime.now(timezone.utc),
        "soft_delete": False
    })

    return {
        "org_a": org_a,
        "org_b": org_b
    }

async def test_query_ast_validation_and_parsing(setup_hunting_data):
    """Verify Query AST safely parses allowed fields/operators and rejects injections."""
    org_a = setup_hunting_data["org_a"]

    # 1. Valid AST Query
    valid_ast = {
        "filters": [
            {"field": "event_type", "operator": "eq", "value": "login"},
            {"field": "severity", "operator": "eq", "value": "high"},
            {"field": "rolling_rate_60s", "operator": "gt", "value": 10}
        ]
    }
    events = await threat_hunting_service.search_telemetry_ast(org_a, valid_ast)
    assert len(events) == 1
    assert events[0]["event_id"] == "EVT-ORG-A-1"

    # 2. Forbidden field query injection validation
    invalid_ast_field = {
        "filters": [
            {"field": "password_hash", "operator": "eq", "value": "xyz"}
        ]
    }
    with pytest.raises(ValueError) as exc:
        await threat_hunting_service.search_telemetry_ast(org_a, invalid_ast_field)
    assert "Unauthorized search field" in str(exc.value)

    # 3. Forbidden operator injection validation
    invalid_ast_operator = {
        "filters": [
            {"field": "event_type", "operator": "$where", "value": "xyz"}
        ]
    }
    with pytest.raises(ValueError) as exc:
        await threat_hunting_service.search_telemetry_ast(org_a, invalid_ast_operator)
    assert "Unauthorized query operator" in str(exc.value)

async def test_tenant_isolation_safeguard(setup_hunting_data):
    """Enforce strict multi-tenant boundary checks in AST compiler search."""
    org_a = setup_hunting_data["org_a"]

    # Query for login events under Org A
    ast = {
        "filters": [
            {"field": "event_type", "operator": "eq", "value": "login"}
        ]
    }
    events = await threat_hunting_service.search_telemetry_ast(org_a, ast)
    
    # Org A search must ONLY return Org A's login telemetry
    assert len(events) == 1
    assert events[0]["event_id"] == "EVT-ORG-A-1"
    assert events[0]["organization_id"] == org_a
    # Ensure Event 3 (Org B's login telemetry) is not returned
    assert not any(e["event_id"] == "EVT-ORG-B-1" for e in events)

async def test_multi_signal_enrichment(setup_hunting_data):
    """Confirm E4 threat intel, E9 UEBA scores, and E11.3 findings enrich results."""
    org_a = setup_hunting_data["org_a"]

    ast = {
        "filters": [
            {"field": "event_id", "operator": "eq", "value": "EVT-ORG-A-1"}
        ]
    }
    events = await threat_hunting_service.search_telemetry_ast(org_a, ast, enrich_intel=True, enrich_ueba=True)
    assert len(events) == 1
    evt = events[0]

    # Verify E4 Enrichment
    assert evt["threat_intel_match"] is True
    assert evt["threat_intel_details"]["type"] == "domain"
    assert "phishing domain" in evt["threat_intel_details"]["description"]

    # Verify E9 Enrichment
    assert evt["user_risk_score"] == 0.85
    assert evt["ueba_anomaly_features"]["user_risk_score"] == 0.85

    # Verify E11.3 Detection Finding Enrichment
    assert evt["active_finding"] is not None
    assert evt["active_finding"]["rule_id"] == "RULE-001"
    assert evt["active_finding"]["status"] == "NEW"

async def test_incident_escalation_flow(setup_hunting_data):
    """Verify manual escalation logs a HuntFinding, registers an incident case, and adds timeline events."""
    org_a = setup_hunting_data["org_a"]

    res = await threat_hunting_service.escalate_event_to_incident(
        org_id=org_a,
        event_id="EVT-ORG-A-1",
        severity="HIGH",
        notes="Suspicious command-line and lookalike domain activity observed.",
        analyst_id="analyst_test_user"
    )

    assert res["event_id"] == "EVT-ORG-A-1"
    assert res["severity"] == "HIGH"
    assert res["flagged_by"] == "analyst_test_user"
    assert res["incident_id"] is not None

    # Inspect Incident repository for Case creation details
    db = db_manager.db
    incident = await db["incidents"].find_one({"incident_id": res["incident_id"]})
    assert incident is not None
    assert incident["status"] == "Detected"
    assert incident["threat_severity"] == "HIGH"
    assert incident["affected_email"] == "EVT-ORG-A-1"
    assert incident["affected_user"] == "user_admin"

    # Inspect Timeline logs
    timeline = await db["incident_timeline"].find_one({"incident_id": res["incident_id"]})
    assert timeline is not None
    assert timeline["event"] == "INCIDENT_DETECTED"
    assert "analyst_test_user" in timeline["description"]

async def test_threat_hunting_rest_api(setup_hunting_data, client: AsyncClient, admin_token_headers):
    """Assert threat hunting REST endpoints run successfully under correct authorization controls."""
    org_a = setup_hunting_data["org_a"]

    # 1. Search endpoint
    search_payload = {
        "query_ast": {
            "filters": [
                {"field": "event_type", "operator": "eq", "value": "login"}
            ]
        },
        "enrich_intel": True,
        "enrich_ueba": True
    }
    res = await client.post("/api/v1/threat-hunting/search", json=search_payload, headers=admin_token_headers)
    assert res.status_code == 200
    events = res.json()
    assert len(events) == 1
    assert events[0]["event_id"] == "EVT-ORG-A-1"

    # 2. Save hunting session
    session_payload = {
        "name": "Admin Logins Hunt Workspace",
        "description": "Hunting active session credentials validation",
        "query_ast": search_payload["query_ast"]
    }
    res = await client.post("/api/v1/threat-hunting/sessions", json=session_payload, headers=admin_token_headers)
    assert res.status_code == 201
    session_data = res.json()
    assert session_data["name"] == "Admin Logins Hunt Workspace"

    # 3. Retrieve sessions list
    res = await client.get("/api/v1/threat-hunting/sessions", headers=admin_token_headers)
    assert res.status_code == 200
    sessions = res.json()
    assert len(sessions) == 1
    assert sessions[0]["name"] == "Admin Logins Hunt Workspace"

    # 4. Escalate finding endpoint
    escalate_payload = {
        "event_id": "EVT-ORG-A-2",
        "severity": "MEDIUM",
        "notes": "Escalated file_access anomalies from endpoint search"
    }
    res = await client.post("/api/v1/threat-hunting/escalate", json=escalate_payload, headers=admin_token_headers)
    assert res.status_code == 201
    escalation_data = res.json()
    assert escalation_data["incident_id"] is not None

    # 5. Retrieve findings
    res = await client.get("/api/v1/threat-hunting/findings", headers=admin_token_headers)
    assert res.status_code == 200
    findings = res.json()
    assert len(findings) == 1  # Only one created in this isolated test execution context

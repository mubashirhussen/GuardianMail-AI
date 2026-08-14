import pytest
from httpx import AsyncClient
from datetime import datetime, timedelta
from app.database.connection import db_manager
from app.services.detection_service import detection_service
from app.services.data_platform_service import data_platform_service
from app.services.integration_service import integration_service
from app.core.tenant_context import TenantContext

@pytest.mark.asyncio
async def test_rule_creation_initial_draft(client: AsyncClient):
    """Verify rules are initialized in DRAFT state with Version 1 and audit logging."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_a"

    # Reset
    await db["users"].delete_many({"email": "admin@enterprise.com"})
    await db["detection_rules"].delete_many({"organization_id": org_id})
    await db["detection_versions"].delete_many({"organization_id": org_id})
    await db["audit_logs"].delete_many({"organization_id": org_id})

    # Register & Login
    await client.post("/api/v1/auth/register", json={
        "email": "admin@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Org Admin"
    })
    user = await db["users"].find_one({"email": "admin@enterprise.com"})
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "organization_id": org_id}})
    
    await db["organization_memberships"].delete_many({"user_id": str(user["_id"])})
    await db["organization_memberships"].insert_one({
        "organization_id": org_id,
        "user_id": str(user["_id"]),
        "role": "admin",
        "soft_delete": False
    })

    login_res = await client.post("/api/v1/auth/login", json={
        "email": "admin@enterprise.com",
        "password": "StrongPassword123!"
    })
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # Create Rule
    res = await client.post("/api/v1/detections", json={
        "rule_id": "RULE-DRAFT-01",
        "name": "Draft Rule Name",
        "description": "Rule Description",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "data_sources": ["syslog"],
        "conditions": {"event_type": "login"},
        "time_window": 60,
        "mitre_attack_techniques": ["T1566"],
        "false_positive_guidance": "Ignore test alerts"
    }, headers=headers)

    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "DRAFT"
    assert data["severity"] == "HIGH"
    assert data["confidence"] == "MEDIUM"

    # Verify version 1 created
    versions = await db["detection_versions"].find({"organization_id": org_id, "rule_id": "RULE-DRAFT-01"}).to_list(length=10)
    assert len(versions) == 1
    assert versions[0]["version_number"] == 1

    # Verify Audit logged
    audits = await db["audit_logs"].find({"organization_id": org_id, "action": "DETECTION_CREATED"}).to_list(length=10)
    assert len(audits) == 1
    assert audits[0]["details"]["rule_id"] == "RULE-DRAFT-01"

@pytest.mark.asyncio
async def test_rule_versioning_and_updates(client: AsyncClient):
    """Verify that editing a rule preserves history and increments the version number."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_a"

    # Setup User Headers
    login_res = await client.post("/api/v1/auth/login", json={
        "email": "admin@enterprise.com",
        "password": "StrongPassword123!"
    })
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # Update Rule
    update_res = await client.patch("/api/v1/detections/RULE-DRAFT-01", json={
        "name": "Updated Rule Name",
        "description": "Updated Description",
        "change_info": "Updated conditions schema"
    }, headers=headers)

    assert update_res.status_code == 200
    
    # Verify version 2 created, version 1 preserved
    versions = await db["detection_versions"].find({"organization_id": org_id, "rule_id": "RULE-DRAFT-01"}).sort("version_number", 1).to_list(length=10)
    assert len(versions) == 2
    assert versions[0]["version_number"] == 1
    assert versions[1]["version_number"] == 2
    assert versions[1]["change_info"] == "Updated conditions schema"

    # Verify get history route
    details_res = await client.get("/api/v1/detections/RULE-DRAFT-01", headers=headers)
    assert details_res.status_code == 200
    assert len(details_res.json()["versions"]) == 2
    assert len(details_res.json()["audits"]) >= 2

@pytest.mark.asyncio
async def test_rule_lifecycle_transitions(client: AsyncClient):
    """Verify that valid transitions (DRAFT -> TESTING -> REVIEW -> ACTIVE) pass successfully."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_a"

    login_res = await client.post("/api/v1/auth/login", json={
        "email": "admin@enterprise.com",
        "password": "StrongPassword123!"
    })
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # DRAFT -> TESTING
    res1 = await client.post("/api/v1/detections/RULE-DRAFT-01/status", json={"status": "TESTING"}, headers=headers)
    assert res1.status_code == 200
    assert res1.json()["status"] == "TESTING"

    # TESTING -> REVIEW
    res2 = await client.post("/api/v1/detections/RULE-DRAFT-01/status", json={"status": "REVIEW"}, headers=headers)
    assert res2.status_code == 200
    assert res2.json()["status"] == "REVIEW"

    # REVIEW -> ACTIVE
    res3 = await client.post("/api/v1/detections/RULE-DRAFT-01/status", json={"status": "ACTIVE"}, headers=headers)
    assert res3.status_code == 200
    assert res3.json()["status"] == "ACTIVE"

    # Check ENABLED Audit Logged
    audits = await db["audit_logs"].find({"organization_id": org_id, "action": "DETECTION_ENABLED"}).to_list(length=10)
    assert len(audits) == 1

@pytest.mark.asyncio
async def test_rule_invalid_lifecycle_transition(client: AsyncClient):
    """Verify invalid transition pathways (e.g. DRAFT -> ACTIVE or RETIRED -> ACTIVE) are blocked."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_a"

    login_res = await client.post("/api/v1/auth/login", json={
        "email": "admin@enterprise.com",
        "password": "StrongPassword123!"
    })
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # Reset rule back to DRAFT
    await db["detection_rules"].update_one(
        {"organization_id": org_id, "rule_id": "RULE-DRAFT-01"},
        {"$set": {"status": "DRAFT"}}
    )

    # Attempt invalid DRAFT -> ACTIVE
    res = await client.post("/api/v1/detections/RULE-DRAFT-01/status", json={"status": "ACTIVE"}, headers=headers)
    assert res.status_code == 400
    assert "Invalid transition" in res.json()["detail"]

    # Verify rejected attempt logged to Audits
    audits = await db["audit_logs"].find({"organization_id": org_id, "action": "DETECTION_STATUS_CHANGE_REJECTED"}).to_list(length=10)
    assert len(audits) == 1

@pytest.mark.asyncio
async def test_rule_query_filters_and_search(client: AsyncClient):
    """Verify search and filters match rules correctly."""
    if db_manager.db is None:
        await db_manager.connect()

    login_res = await client.post("/api/v1/auth/login", json={
        "email": "admin@enterprise.com",
        "password": "StrongPassword123!"
    })
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # Test filtering by status
    res = await client.get("/api/v1/detections?status=draft", headers=headers)
    assert res.status_code == 200
    assert len(res.json()) >= 1

    # Test search query
    res_search = await client.get("/api/v1/detections?search=draft", headers=headers)
    assert res_search.status_code == 200
    assert len(res_search.json()) >= 1

@pytest.mark.asyncio
async def test_multi_tenant_rule_isolation(client: AsyncClient):
    """Verify strict multi-tenant boundary checks across Org A and Org B rules."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db

    # Register Org B User
    await db["users"].delete_many({"email": "deb@enterprise.com"})
    await client.post("/api/v1/auth/register", json={
        "email": "deb@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Org B Administrator"
    })
    user_b = await db["users"].find_one({"email": "deb@enterprise.com"})
    await db["users"].update_one({"_id": user_b["_id"]}, {"$set": {"role": "admin", "organization_id": "org_b"}})

    await db["organization_memberships"].delete_many({"user_id": str(user_b["_id"])})
    await db["organization_memberships"].insert_one({
        "organization_id": "org_b",
        "user_id": str(user_b["_id"]),
        "role": "admin",
        "soft_delete": False
    })

    b_login = await client.post("/api/v1/auth/login", json={
        "email": "deb@enterprise.com",
        "password": "StrongPassword123!"
    })
    b_headers = {"Authorization": f"Bearer {b_login.json()['access_token']}"}

    # Org B lists Org A's rule (should get empty/denied outcome)
    res = await client.get("/api/v1/detections", headers=b_headers)
    assert res.status_code == 200
    assert not any(r["rule_id"] == "RULE-DRAFT-01" for r in res.json())

    # Direct ID retrieval access attempts
    res_get = await client.get("/api/v1/detections/RULE-DRAFT-01", headers=b_headers)
    assert res_get.status_code == 404

    # Direct Patch transition access attempts
    res_patch = await client.patch("/api/v1/detections/RULE-DRAFT-01", json={"name": "Org B Hack"}, headers=b_headers)
    assert res_patch.status_code == 400

@pytest.mark.asyncio
async def test_rule_engine_historical_replay():
    """Verify that rule threshold condition engines evaluate matching events accurately."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_de_test"

    # Reset
    await db["detection_rules"].delete_many({"organization_id": org_id})
    await db["security_telemetry"].delete_many({"organization_id": org_id})

    # Seed ACTIVE threshold rule
    await db["detection_rules"].insert_one({
        "organization_id": org_id,
        "rule_id": "DE-TH-01",
        "name": "Multiple Logins Threshold",
        "description": "Trigger when syslog logins exceed 1",
        "status": "ACTIVE",
        "severity": "HIGH",
        "confidence": "HIGH",
        "author": "tester",
        "rule_type": "threshold",
        "conditions": {"event_type": "login"},
        "time_window": 60,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "soft_delete": False
    })

    # Ingest 2 events
    await data_platform_service.ingest_telemetry(org_id, "login", "high", "host-a", {"user": "admin"})
    await data_platform_service.ingest_telemetry(org_id, "login", "high", "host-b", {"user": "admin"})

    res = await detection_service.execute_rule_historical(org_id, "DE-TH-01")
    assert len(res) >= 2

@pytest.mark.asyncio
async def test_attack_graph_generation():
    """Verify dynamic node-link attack graph traversal and campaigns overlays."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_de_test"

    await db["investigations"].delete_many({"organization_id": org_id})
    await db["campaigns"].delete_many({"organization_id": org_id})

    # Seed case file
    await db["investigations"].insert_one({
        "organization_id": org_id,
        "investigation_id": "INV-100",
        "title": "Suspected Brute Force Attack",
        "priority": "high",
        "status": "OPEN",
        "entities": [
            {"type": "USER", "value": "victim@enterprise.com"},
            {"type": "IP", "value": "198.51.100.5"}
        ],
        "evidence": [],
        "timeline": [],
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "soft_delete": False
    })

    # Seed related campaign
    await db["campaigns"].insert_one({
        "organization_id": org_id,
        "campaign_id": "CAMP-PHISH",
        "name": "Co-related Malicious Campaign A",
        "description": "Uses overlapping IP addresses",
        "confidence": "high",
        "indicators": ["198.51.100.5"],
        "created_at": datetime.utcnow(),
        "soft_delete": False
    })

    graph = await detection_service.generate_attack_graph(org_id, "INV-100")
    
    # Assert nodes and edges list counts
    assert any("INV-100" in n["id"] for n in graph["nodes"])
    assert any("IP-198.51.100.5" in n["id"] for n in graph["nodes"])
    assert any("CAMP-PHISH" in n["id"] for n in graph["nodes"])

@pytest.mark.asyncio
async def test_ai_summary_cites_grounding():
    """Verify that Copilot summary clearly separates facts/observations from inferences."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_de_test"
    
    await db["investigations"].delete_many({"organization_id": org_id})
    await db["investigations"].insert_one({
        "organization_id": org_id,
        "investigation_id": "INV-200",
        "title": "Email Phish Alert",
        "priority": "medium",
        "status": "OPEN",
        "entities": [{"type": "USER", "value": "user@enterprise.com"}],
        "evidence": [{"type": "regex", "description": "Matched phish link", "confidence": "high"}],
        "timeline": [],
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "soft_delete": False
    })

    summary = await detection_service.generate_ai_investigation_summary(org_id, "INV-200")
    assert len(summary["observed_facts"]) >= 2
    assert len(summary["model_inferences"]) >= 2
    assert "model_inferences" in summary

@pytest.mark.asyncio
async def test_end_to_end_threat_remediation_lifecycle(client: AsyncClient):
    """Verify full threat flow: E4 -> E9 -> E10 -> E11 -> Graph -> E5 -> E6 -> E7 -> E8."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_a"

    # 1. Clean collections
    await db["detection_rules"].delete_many({"organization_id": org_id})
    await db["security_telemetry"].delete_many({"organization_id": org_id})
    await db["investigations"].delete_many({"organization_id": org_id})
    await db["integrations"].delete_many({"organization_id": org_id})
    await db["integration_deliveries"].delete_many({"organization_id": org_id})

    # Register user & Login to get token
    await db["users"].delete_many({"email": "hunter@enterprise.com"})
    await client.post("/api/v1/auth/register", json={
        "email": "hunter@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "E2E Threat Hunter"
    })
    user = await db["users"].find_one({"email": "hunter@enterprise.com"})
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "organization_id": org_id}})
    
    await db["organization_memberships"].delete_many({"user_id": str(user["_id"])})
    await db["organization_memberships"].insert_one({
        "organization_id": org_id,
        "user_id": str(user["_id"]),
        "role": "admin",
        "soft_delete": False
    })

    login_res = await client.post("/api/v1/auth/login", json={
        "email": "hunter@enterprise.com",
        "password": "StrongPassword123!"
    })
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # 2. Ingest threat telemetry logs (E10 Ingestion)
    await data_platform_service.ingest_telemetry(
        org_id=org_id,
        event_type="login",
        severity="high",
        source="192.168.1.10",
        payload={"indicator": "malicious-phish-domain.com", "user": "hunter@enterprise.com"}
    )

    # 3. Seed Rule and test Rule matching (E11 Detection)
    rule_doc = {
        "organization_id": org_id,
        "rule_id": "RULE-E2E",
        "name": "E2E Rule Correlation",
        "description": "Correlates phish logs",
        "status": "ACTIVE",
        "severity": "HIGH",
        "confidence": "HIGH",
        "author": "hunter@enterprise.com",
        "data_sources": ["syslog"],
        "conditions": {"event_type": "login"},
        "time_window": 300,
        "soft_delete": False,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    await db["detection_rules"].insert_one(rule_doc)
    
    test_res = await client.post("/api/v1/detections/RULE-E2E/test", headers=headers)
    assert test_res.status_code == 200
    assert len(test_res.json()) >= 1

    # 4. Initiate Case Investigation file
    inv_res = await client.post("/api/v1/investigations", json={
        "investigation_id": "INV-E2E",
        "title": "Malicious E2E correlation alert",
        "priority": "high",
        "entities": [
            {"type": "USER", "value": "hunter@enterprise.com"},
            {"type": "DOMAIN", "value": "malicious-phish-domain.com"}
        ],
        "evidence": [
            {"type": "threat_intel", "description": "High reputation threat risk", "confidence": "high"}
        ]
    }, headers=headers)
    assert inv_res.status_code == 201

    # 5. Attack Graph Node-Link construction
    graph_res = await client.get("/api/v1/investigations/INV-E2E/graph", headers=headers)
    assert graph_res.status_code == 200
    assert any("INV-E2E" in n["id"] for n in graph_res.json()["nodes"])

    # 6. E5 Copilot summary citation
    copilot_res = await client.get("/api/v1/investigations/INV-E2E/ai-summary", headers=headers)
    assert copilot_res.status_code == 200
    assert "observed_facts" in copilot_res.json()

    # 7. E6 SOAR response trigger
    soar_res = await client.post("/api/v1/investigations/INV-E2E/soar", headers=headers)
    assert soar_res.status_code == 200
    assert soar_res.json()["status"] == "triggered"

    # 8. E7 GRC compliance evidence export
    grc_res = await client.post("/api/v1/investigations/INV-E2E/grc", headers=headers)
    assert grc_res.status_code == 200
    assert grc_res.json()["status"] == "exported"

    # 9. E8 SIEM integrations event export
    # Ingest SIEM receiver config
    await db["integrations"].insert_one({
        "organization_id": org_id,
        "integration_id": "SIEM-E2E",
        "provider": "siem",
        "status": "ACTIVE",
        "auth_method": "api_key",
        "config": {"url": "https://example.com/siem"},
        "created_by": str(user["_id"]),
        "created_at": datetime.utcnow(),
        "health_status": "healthy",
        "soft_delete": False
    })
    # Dispatch event
    deliveries = await integration_service.dispatch_security_event(
        org_id=org_id,
        event_type="INCIDENT_CREATED",
        severity="high",
        details={"case_id": "INV-E2E", "remediation": "Mitigated"}
    )
    assert len(deliveries) == 1
    assert deliveries[0]["status"] == "SENT"

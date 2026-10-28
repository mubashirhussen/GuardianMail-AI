import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient

from app.database.connection import db_manager
from app.services.investigation_service import investigation_service
from app.repositories.data_platform_repo import TelemetryRepository
from app.repositories.threat_intelligence_repo import ThreatIndicatorRepository
from app.repositories.detection_execution_repo import DetectionFindingRepository
from app.repositories.investigation_repo import (
    InvestigationRepository, InvestigationEvidenceRepository,
    InvestigationNoteRepository, InvestigationRelationshipRepository
)
from app.services.copilot_service import copilot_service, ContextBuilder
from app.core.tenant_context import TenantContext

@pytest.fixture
async def analyst_token_headers(client: AsyncClient):
    """Fixture to authorize and return token headers for test requests."""
    db = db_manager.db
    email = "analyst-inv@enterprise.com"
    await db["users"].delete_many({"email": email})
    
    await client.post("/api/v1/auth/register", json={
        "email": email,
        "password": "StrongPassword123!",
        "full_name": "SOC Analyst"
    })
    user = await db["users"].find_one({"email": email})
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"role": "soc_analyst", "organization_id": "org_a_tenant"}})
    
    await db["organization_memberships"].delete_many({"user_id": str(user["_id"])})
    await db["organization_memberships"].insert_one({
        "organization_id": "org_a_tenant",
        "user_id": str(user["_id"]),
        "role": "soc_analyst",
        "soft_delete": False
    })
    
    login_res = await client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "StrongPassword123!"
    })
    return {"Authorization": f"Bearer {login_res.json()['access_token']}"}

@pytest.fixture
async def setup_investigation_data():
    """Setup test telemetry, threat indicators, ML features, and findings."""
    db = db_manager.db
    
    # Repositories
    telemetry_repo = TelemetryRepository(db)
    inv_repo = InvestigationRepository(db)
    evidence_repo = InvestigationEvidenceRepository(db)
    note_repo = InvestigationNoteRepository(db)
    relation_repo = InvestigationRelationshipRepository(db)
    det_finding_repo = DetectionFindingRepository(db)

    # Clean collections
    await telemetry_repo.collection.delete_many({})
    await inv_repo.collection.delete_many({})
    await evidence_repo.collection.delete_many({})
    await note_repo.collection.delete_many({})
    await relation_repo.collection.delete_many({})
    await db["threat_indicators"].delete_many({})
    await db["ml_features"].delete_many({})
    await det_finding_repo.collection.delete_many({})
    await db["incidents"].delete_many({})

    org_a = "org_a_tenant"
    org_b = "org_b_tenant"

    # 1. Telemetry Events
    # Event 1 (Org A): login, admin user
    await telemetry_repo.collection.insert_one({
        "organization_id": org_a,
        "event_id": "EVT-INV-A-1",
        "event_type": "login",
        "severity": "high",
        "source": "10.0.0.1",
        "timestamp": datetime.now(timezone.utc) - timedelta(minutes=5),
        "rolling_rate_60s": 15,
        "user_id": "user_admin",
        "payload": {
            "user": "admin",
            "ip": "10.0.0.1",
            "domain": "malicious-phish.com",
            "device_id": "DEV-001"
        },
        "soft_delete": False
    })

    # Event 2 (Org B): login, admin user
    await telemetry_repo.collection.insert_one({
        "organization_id": org_b,
        "event_id": "EVT-INV-B-1",
        "event_type": "login",
        "severity": "high",
        "source": "10.0.0.2",
        "timestamp": datetime.now(timezone.utc) - timedelta(minutes=5),
        "rolling_rate_60s": 20,
        "user_id": "user_admin",
        "payload": {
            "user": "admin",
            "ip": "10.0.0.2"
        },
        "soft_delete": False
    })

    # 2. E4 Threat Indicators
    await db["threat_indicators"].insert_one({
        "organization_id": org_a,
        "value": "malicious-phish.com",
        "normalized_value": "malicious-phish.com",
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
        "event_id": "EVT-INV-A-1",
        "detection_id": "RULE-001",
        "severity": "HIGH",
        "status": "NEW",
        "created_at": datetime.now(timezone.utc),
        "soft_delete": False
    })

    # 5. Insert mock user document
    await db["users"].insert_one({
        "email": "user_admin",
        "organization_id": org_a,
        "role": "admin",
        "soft_delete": False
    })

    return {
        "org_a": org_a,
        "org_b": org_b
    }

async def test_investigation_creation_and_lifecycle_transitions(setup_investigation_data):
    """Validate creating investigations in DRAFT status and enforcing transitions state-machine."""
    org_a = setup_investigation_data["org_a"]

    # 1. Create DRAFT Investigation
    inv = await investigation_service.create_investigation(
        org_id=org_a,
        title="Suspicious Admin Auth Overlap",
        description="Correlating logins and UEBA signals",
        priority="HIGH",
        severity="HIGH",
        created_by="analyst_test_user"
    )
    assert inv["status"] == "DRAFT"
    assert inv["priority"] == "HIGH"
    assert inv["title"] == "Suspicious Admin Auth Overlap"

    inv_id = inv["_id"]

    # 2. Allowed Transition: DRAFT -> OPEN
    updated = await investigation_service.update_investigation(
        org_id=org_a,
        investigation_id=inv_id,
        update_data={"status": "OPEN"},
        analyst_id="analyst_test_user"
    )
    assert updated["status"] == "OPEN"

    # 3. Invalid Transition: OPEN -> RESOLVED (must go OPEN -> INVESTIGATING -> RESOLVED)
    with pytest.raises(ValueError) as exc:
        await investigation_service.update_investigation(
            org_id=org_a,
            investigation_id=inv_id,
            update_data={"status": "RESOLVED"},
            analyst_id="analyst_test_user"
        )
    assert "Unauthorized state transition" in str(exc.value)

async def test_multi_tenant_isolation_safeguards(setup_investigation_data):
    """Enforce strict multi-tenant partitions across investigations, evidence, and notes."""
    org_a = setup_investigation_data["org_a"]
    org_b = setup_investigation_data["org_b"]

    # 1. Create Org A Investigation
    inv_a = await investigation_service.create_investigation(
        org_id=org_a,
        title="Org A Investigation Case",
        description="Org A scope",
        priority="MEDIUM",
        severity="MEDIUM",
        created_by="analyst_test_user"
    )
    inv_a_id = inv_a["_id"]

    # 2. Try to add Org B telemetry event as evidence to Org A investigation
    with pytest.raises(ValueError) as exc:
        await investigation_service.add_evidence(
            org_id=org_a,
            investigation_id=inv_a_id,
            evidence_type="SECURITY_EVENT",
            source_id="EVT-INV-B-1",  # Belongs to Org B
            analyst_id="analyst_test_user"
        )
    assert "Unauthorized" in str(exc.value) or "not found" in str(exc.value)

    # 3. Try to access Org A investigation under Org B tenant context
    workspace = await investigation_service.get_investigation_workspace(
        org_id=org_b,
        investigation_id=inv_a_id
    )
    assert workspace == {}  # Returns empty dict, block access

async def test_multi_signal_correlation_generation(setup_investigation_data):
    """Assert E4 threat indicators, E9 UEBA score, and E11.3 findings populate correct relationships."""
    org_a = setup_investigation_data["org_a"]

    # 1. Create Case and Link Seed Evidence (IP & User)
    inv = await investigation_service.create_investigation(
        org_id=org_a,
        title="Auth Correlation Case",
        description="IP and User links",
        priority="HIGH",
        severity="HIGH",
        created_by="analyst_test_user"
    )
    inv_id = inv["_id"]

    # Link USER evidence
    await investigation_service.add_evidence(
        org_id=org_a,
        investigation_id=inv_id,
        evidence_type="USER",
        source_id="user_admin",
        analyst_id="analyst_test_user"
    )

    # Link IP evidence
    await investigation_service.add_evidence(
        org_id=org_a,
        investigation_id=inv_id,
        evidence_type="IP",
        source_id="10.0.0.1",
        analyst_id="analyst_test_user"
    )

    # Link DOMAIN evidence
    await investigation_service.add_evidence(
        org_id=org_a,
        investigation_id=inv_id,
        evidence_type="DOMAIN",
        source_id="malicious-phish.com",
        analyst_id="analyst_test_user"
    )

    # Link Event evidence to trigger detection finding checks
    await investigation_service.add_evidence(
        org_id=org_a,
        investigation_id=inv_id,
        evidence_type="SECURITY_EVENT",
        source_id="EVT-INV-A-1",
        analyst_id="analyst_test_user"
    )

    # 2. Run Correlation Engine
    res = await investigation_service.correlate_investigation(org_a, inv_id)
    assert res["status"] == "SUCCESS"
    assert res["relationships_created"] >= 1

    # 3. Retrieve Workspace Details and check Relationships and Timeline
    workspace = await investigation_service.get_investigation_workspace(org_a, inv_id)
    
    # Assert entities dynamically extracted
    entities = workspace["entities"]
    assert any(ent["id"] == "user_admin" for ent in entities)
    assert any(ent["id"] == "10.0.0.1" for ent in entities)

    # Assert relationships populated
    rels = workspace["relationships"]
    assert len(rels) >= 1
    # Check E4 indicator match relationship exists
    assert any(r["relationship_type"] == "IOC_MATCHED_EVENT" for r in rels)
    # Check E9 UEBA flagged user relationship exists
    assert any(r["relationship_type"] == "UEBA_FLAGGED_USER" for r in rels)
    # Check E11.3 Detection matched event relationship exists
    assert any(r["relationship_type"] == "DETECTION_MATCHED_EVENT" for r in rels)
    # Check connected IP relationship exists
    assert any(r["relationship_type"] == "USER_CONNECTED_TO_IP" for r in rels)

    # Assert dynamic timeline sorted
    timeline = workspace["timeline"]
    assert len(timeline) >= 4
    assert timeline[0]["type"] == "EVIDENCE_ADDED"

async def test_resource_limits_safeguards(setup_investigation_data):
    """Enforce correlation engine aborts safely if evidence count exceeds maximum thresholds."""
    org_a = setup_investigation_data["org_a"]

    inv = await investigation_service.create_investigation(
        org_id=org_a,
        title="Limits Case",
        description="Exceed limits test",
        priority="LOW",
        severity="LOW",
        created_by="analyst_test_user"
    )
    inv_id = inv["_id"]

    # Insert 101 evidence records directly into collection (bypassing service check)
    db = db_manager.db
    evidence_docs = []
    for i in range(105):
        evidence_docs.append({
            "organization_id": org_a,
            "investigation_id": inv_id,
            "evidence_type": "IP",
            "source_id": f"10.0.0.{i}",
            "timestamp": datetime.now(timezone.utc),
            "metadata": {},
            "added_by": "analyst_test_user",
            "soft_delete": False
        })
    for doc in evidence_docs:
        await db["investigation_evidence"].insert_one(doc)

    # Trigger correlate_investigation, verify it aborts with ValueError (resource limits exceeded)
    with pytest.raises(ValueError) as exc:
        await investigation_service.correlate_investigation(org_a, inv_id)
    assert "limits exceeded" in str(exc.value)

async def test_copilot_grounding_context_builder(setup_investigation_data):
    """Assert E5 grounding context correctly extracts investigation metadata."""
    org_a = setup_investigation_data["org_a"]

    inv = await investigation_service.create_investigation(
        org_id=org_a,
        title="Copilot Grounding Case",
        description="Grounding workspace metadata test",
        priority="HIGH",
        severity="HIGH",
        created_by="analyst_test_user"
    )
    inv_id = str(inv["_id"])

    # Query build_context with INVESTIGATION_SUMMARY intent
    context = TenantContext(organization_id=org_a, user_id="analyst_test_user", role="admin", permissions=[])
    data = await ContextBuilder.build_context(
        intent="INVESTIGATION_SUMMARY",
        context=context,
        query=f"Explain what is happening in investigation {inv_id}"
    )

    assert "investigation_evidence" in data
    details = data["investigation_evidence"]
    assert details["title"] == "Copilot Grounding Case"
    assert details["status"] == "DRAFT"
    assert details["priority"] == "HIGH"

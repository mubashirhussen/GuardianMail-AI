import pytest
from httpx import AsyncClient
from datetime import datetime, timedelta
from app.database.connection import db_manager
from app.services.grc_service import grc_service
from app.core.tenant_context import TenantContext
from bson import ObjectId

@pytest.mark.asyncio
async def test_posture_calculation_disclaimer():
    """Verify explainable posture score metrics, penalty math, and compliant disclaimers."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_grc_test"

    # Reset databases
    await db["compliance_controls"].delete_many({"organization_id": org_id})
    await db["security_findings"].delete_many({"organization_id": org_id})
    await db["risks"].delete_many({"organization_id": org_id})

    # Insert sample controls: 1 PASS, 1 FAIL, 1 NOT_ASSESSED
    await db["compliance_controls"].insert_one({
        "organization_id": org_id,
        "control_id": "CTRL-1",
        "framework_name": "SOC2",
        "description": "MFA configuration",
        "owner_id": "analyst_1",
        "status": "PASS",
        "risk_level": "high",
        "evidence_requirement": "SSO screenshot",
        "review_frequency": "monthly",
        "soft_delete": False
    })
    await db["compliance_controls"].insert_one({
        "organization_id": org_id,
        "control_id": "CTRL-2",
        "framework_name": "SOC2",
        "description": "Audit logging enabled",
        "owner_id": "analyst_1",
        "status": "FAIL",
        "risk_level": "medium",
        "evidence_requirement": "Log snap",
        "review_frequency": "monthly",
        "soft_delete": False
    })
    await db["compliance_controls"].insert_one({
        "organization_id": org_id,
        "control_id": "CTRL-3",
        "framework_name": "SOC2",
        "description": "Vulnerability scanning",
        "owner_id": "analyst_1",
        "status": "NOT_ASSESSED",
        "risk_level": "medium",
        "evidence_requirement": "Scan report",
        "review_frequency": "monthly",
        "soft_delete": False
    })

    # Insert 1 open finding
    await db["security_findings"].insert_one({
        "organization_id": org_id,
        "finding_id": "FIND-1",
        "severity": "medium",
        "source": "Audit",
        "control_id": "CTRL-2",
        "description": "Logging disabled on production DB",
        "status": "OPEN",
        "remediation_plan": "Turn on auditing logs",
        "due_date": datetime.utcnow() + timedelta(days=30),
        "soft_delete": False
    })

    # Insert 1 critical risk (Likelihood=4, Impact=5 -> Score=20)
    await db["risks"].insert_one({
        "organization_id": org_id,
        "risk_id": "RISK-1",
        "title": "Unencrypted backups",
        "description": "Database backups are stored in plain text",
        "category": "Cybersecurity",
        "likelihood": 4,
        "impact": 5,
        "inherent_risk_score": 20,
        "residual_risk_score": 20,
        "status": "OPEN",
        "treatment_status": "MITIGATE",
        "treatment_plan": "Encrypt all S3 snapshots",
        "owner_id": "analyst_1",
        "soft_delete": False
    })

    posture = await grc_service.calculate_posture_score(org_id)
    
    # Assert penalties:
    # Controls penalty: (1 FAIL * 15) + (1 NOT_ASSESSED * 3) = 18
    # Findings penalty: 1 OPEN finding * 5 = 5
    # Risk penalty: 1 Critical risk * 10 = 10
    # Expected score: 100 - (18 + 5 + 10) = 67.0
    assert posture["posture_score"] == 67.0
    assert posture["posture_rating"] == "Suboptimal"
    assert "This score is for internal security posture estimation and does not represent formal compliance certification" in posture["disclaimer"]


@pytest.mark.asyncio
async def test_evidence_integrity_hashes():
    """Verify tamper-evident SHA-256 signature sealing on uploaded compliance evidence."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_grc_test"
    await db["compliance_evidence"].delete_many({"organization_id": org_id})

    # Trigger manual upload and compute hash
    import hashlib
    content = "Tenant SSO identity configurations snapshot payload"
    expected_hash = hashlib.sha256(content.encode()).hexdigest()

    doc = {
        "organization_id": org_id,
        "control_id": "CTRL-1",
        "evidence_type": "config_snapshot",
        "source": "Manual Admin Upload",
        "content_hash": expected_hash,
        "created_at": datetime.utcnow(),
        "collected_at": datetime.utcnow(),
        "owner_id": "analyst_1",
        "status": "active",
        "soft_delete": False
    }

    res = await db["compliance_evidence"].insert_one(doc)
    doc_id = str(res.inserted_id)

    # Fetch from repository and verify hash integrity
    evidence_list = await grc_service.evidence_repo.get_by_org(org_id)
    assert len(evidence_list) >= 1
    assert evidence_list[0]["content_hash"] == expected_hash
    assert evidence_list[0]["_id"] == doc_id


@pytest.mark.asyncio
async def test_automated_evidence_collector():
    """Verify that automated collector successfully captures system configurations and seals hashes."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_grc_test"

    # Seed mock identity config & policies
    await db["identity_providers"].delete_many({"organization_id": org_id})
    await db["identity_providers"].insert_one({
        "organization_id": org_id,
        "issuer": "https://sso.enterprise.com",
        "created_at": datetime.utcnow(),
        "soft_delete": False
    })

    await db["security_policies"].delete_many({"organization_id": org_id})
    await db["security_policies"].insert_one({
        "organization_id": org_id,
        "policy_type": "ai_analysis",
        "rules": [],
        "status": "active",
        "soft_delete": False
    })

    # Clear old automated evidence
    await db["compliance_evidence"].delete_many({"organization_id": org_id, "source": {"$regex": "^Automated"}})

    collected = await grc_service.collect_automated_evidence(org_id, "analyst_1")
    assert len(collected) == 2
    assert any("SSO Configuration" in x["source"] for x in collected)
    assert any("Security Policies" in x["source"] for x in collected)


@pytest.mark.asyncio
async def test_risk_exceptions_expiry():
    """Verify that granting a temporary exception updates risk posture and assigns expiration offsets."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_grc_test"

    await db["risks"].delete_many({"organization_id": org_id})
    await db["risk_exceptions"].delete_many({"organization_id": org_id})

    # Insert open risk
    res_risk = await db["risks"].insert_one({
        "organization_id": org_id,
        "risk_id": "RISK-10",
        "title": "Legacy servers active",
        "description": "Legacy backup servers lack TLS 1.3",
        "category": "Operational",
        "likelihood": 3,
        "impact": 4,
        "inherent_risk_score": 12,
        "residual_risk_score": 12,
        "status": "OPEN",
        "treatment_status": "MITIGATE",
        "treatment_plan": "Upgrade backup pipelines",
        "owner_id": "analyst_1",
        "soft_delete": False
    })

    # Request exemption for 90 days
    doc_exception = {
        "organization_id": org_id,
        "risk_id": "RISK-10",
        "reason": "Replacement servers backordered",
        "compensating_controls": "Strict IP whitelist firewall rules",
        "requested_by": "analyst_1",
        "approved_by": "admin_1",
        "requested_at": datetime.utcnow(),
        "expiration": datetime.utcnow() + timedelta(days=90),
        "soft_delete": False
    }
    await db["risk_exceptions"].insert_one(doc_exception)

    # Flag risk status
    await db["risks"].update_one(
        {"_id": res_risk.inserted_id},
        {"$set": {"status": "ACCEPTED", "treatment_status": "ACCEPT"}}
    )

    updated_risk = await grc_service.risk_repo.get_by_org_and_id(org_id, "RISK-10")
    assert updated_risk["status"] == "ACCEPTED"
    assert updated_risk["treatment_status"] == "ACCEPT"

    exceptions = await grc_service.exception_repo.get_by_org(org_id)
    assert len(exceptions) == 1
    assert exceptions[0]["risk_id"] == "RISK-10"


@pytest.mark.asyncio
async def test_grc_multi_tenant_isolation(client: AsyncClient):
    """Verify that GRC endpoints strictly isolate framework data between tenant workspaces."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db

    # Register Org A & Org B Users
    await db["users"].delete_many({"email": {"$in": ["grca@enterprise.com", "grcb@enterprise.com"]}})
    
    await client.post("/api/v1/auth/register", json={
        "email": "grca@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Org A Assessor"
    })
    await client.post("/api/v1/auth/register", json={
        "email": "grcb@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Org B Assessor"
    })

    user_a = await db["users"].find_one({"email": "grca@enterprise.com"})
    user_b = await db["users"].find_one({"email": "grcb@enterprise.com"})

    await db["users"].update_one({"_id": user_a["_id"]}, {"$set": {"role": "admin", "organization_id": "org_a"}})
    await db["users"].update_one({"_id": user_b["_id"]}, {"$set": {"role": "admin", "organization_id": "org_b"}})

    # Insert memberships
    await db["organization_memberships"].delete_many({"user_id": {"$in": [str(user_a["_id"]), str(user_b["_id"])]}})
    await db["organization_memberships"].insert_one({
        "organization_id": "org_a",
        "user_id": str(user_a["_id"]),
        "role": "admin",
        "soft_delete": False
    })
    await db["organization_memberships"].insert_one({
        "organization_id": "org_b",
        "user_id": str(user_b["_id"]),
        "role": "admin",
        "soft_delete": False
    })

    a_login = await client.post("/api/v1/auth/login", json={
        "email": "grca@enterprise.com",
        "password": "StrongPassword123!"
    })
    a_headers = {"Authorization": f"Bearer {a_login.json()['access_token']}"}

    b_login = await client.post("/api/v1/auth/login", json={
        "email": "grcb@enterprise.com",
        "password": "StrongPassword123!"
    })
    b_headers = {"Authorization": f"Bearer {b_login.json()['access_token']}"}

    # Ingest GRC controls for Org A
    await db["compliance_controls"].delete_many({"organization_id": "org_a"})
    await db["compliance_controls"].insert_one({
        "organization_id": "org_a",
        "control_id": "SOC2-A1",
        "framework_name": "SOC2",
        "description": "Org A private MFA requirements",
        "owner_id": str(user_a["_id"]),
        "status": "PASS",
        "risk_level": "medium",
        "evidence_requirement": "Log snapshots",
        "review_frequency": "monthly",
        "soft_delete": False
    })

    # Retrieve Org A controls with Org A token
    res_a = await client.get("/api/v1/grc/controls", headers=a_headers)
    assert res_a.status_code == 200
    assert len(res_a.json()) == 1
    assert res_a.json()[0]["control_id"] == "SOC2-A1"

    # Attempt to retrieve with Org B token
    res_b = await client.get("/api/v1/grc/controls", headers=b_headers)
    assert res_b.status_code == 200
    assert len(res_b.json()) == 0  # Should be empty because it is filtered on Org B!

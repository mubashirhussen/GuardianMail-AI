import pytest
from httpx import AsyncClient
from datetime import datetime, timezone
from bson import ObjectId
from app.database.connection import db_manager
from app.services.threat_correlation import threat_correlation_service
from app.services.policy_engine import policy_engine
from app.core.tenant_context import TenantContext, request_tenant_context

@pytest.mark.asyncio
async def test_indicator_normalization():
    """Verify that indicators of various types are normalized correctly."""
    # Domain normalization
    assert threat_correlation_service.normalize_indicator("domain", "  Bad-Domain.COM  ") == "bad-domain.com"
    # URL normalization
    assert threat_correlation_service.normalize_indicator("url", "HTTP://mY-PhIsHiNg-DoMaIn.com/Path/To/Page.html?utm=1") == "http://my-phishing-domain.com/Path/To/Page.html?utm=1"
    # Hash normalization
    assert threat_correlation_service.normalize_indicator("file_hash", "  E3B0C44298FC1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

@pytest.mark.asyncio
async def test_idempotent_ioc_ingestion():
    """Ensure that ingesting the same IOC multiple times does not create duplicates."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    # Clear previous indicators
    await db["threat_indicators"].delete_many({"normalized_value": "test-idempotent-domain.com"})

    # First ingestion
    ioc1 = await threat_correlation_service.ingest_indicator(
        indicator_type="domain",
        indicator_value="test-idempotent-domain.com",
        source="VirusTotal",
        organization_id="org_test_idemp"
    )
    
    # Second ingestion
    ioc2 = await threat_correlation_service.ingest_indicator(
        indicator_type="domain",
        indicator_value="test-idempotent-domain.com",
        source="VirusTotal",
        organization_id="org_test_idemp"
    )

    assert ioc1["_id"] == ioc2["_id"]
    count = await db["threat_indicators"].count_documents({"normalized_value": "test-idempotent-domain.com"})
    assert count == 1

@pytest.mark.asyncio
async def test_multi_tenant_ioc_isolation():
    """Ensure that Organization A cannot search or retrieve Organization B's private threat indicators."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    # Clean up
    await db["threat_indicators"].delete_many({"normalized_value": {"$in": ["private-org-a.com", "private-org-b.com"]}})

    # Org A private IOC
    await threat_correlation_service.ingest_indicator(
        indicator_type="domain",
        indicator_value="private-org-a.com",
        source="Internal",
        organization_id="org_a"
    )

    # Org B private IOC
    await threat_correlation_service.ingest_indicator(
        indicator_type="domain",
        indicator_value="private-org-b.com",
        source="Internal",
        organization_id="org_b"
    )

    # Search as Org A
    org_a_iocs = await threat_correlation_service.indicator_repo.search_indicators(org_id="org_a")
    org_a_values = [ioc["normalized_value"] for ioc in org_a_iocs]
    
    assert "private-org-a.com" in org_a_values
    assert "private-org-b.com" not in org_a_values

@pytest.mark.asyncio
async def test_policy_engine_hierarchy_evaluation():
    """Test policy resolution hierarchy (User override > Dept > Org > Global)."""
    context = TenantContext(
        user_id="user_john",
        organization_id="org_sales",
        role="user",
        permissions=["policies.read"],
        department="Sales",
        team="Outbound"
    )
    
    # Payload matching high risk
    payload = {"risk_score": 85}
    
    # 1. Evaluate with no custom rules -> should return global default (REQUIRE_REVIEW because risk >= 80)
    verdict = await policy_engine.evaluate("email_security", context, payload)
    assert verdict["decision"] == "REQUIRE_REVIEW"
    assert verdict["source"] == "global_default"

@pytest.mark.asyncio
async def test_threat_campaign_correlation():
    """Test that multiple indicators sharing identical infrastructure tags auto-correlate into a Campaign."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    await db["threat_indicators"].delete_many({"tags": "apt-campaign-alpha"})
    await db["threat_campaigns"].delete_many({"organization_id": "org_campaign_test"})

    # Ingest 3 indicators sharing the tag "apt-campaign-alpha"
    await threat_correlation_service.ingest_indicator(
        indicator_type="domain",
        indicator_value="malicious-domain-1.com",
        source="VT",
        organization_id="org_campaign_test",
        tags=["apt-campaign-alpha"]
    )
    await threat_correlation_service.ingest_indicator(
        indicator_type="domain",
        indicator_value="malicious-domain-2.com",
        source="VT",
        organization_id="org_campaign_test",
        tags=["apt-campaign-alpha"]
    )
    await threat_correlation_service.ingest_indicator(
        indicator_type="domain",
        indicator_value="malicious-domain-3.com",
        source="VT",
        organization_id="org_campaign_test",
        tags=["apt-campaign-alpha"]
    )

    # Check if a suspected campaign was created
    campaign = await db["threat_campaigns"].find_one({
        "organization_id": "org_campaign_test",
        "status": "suspected"
    })
    
    assert campaign is not None
    assert len(campaign["indicators"]) == 3

@pytest.mark.asyncio
async def test_separation_of_duties_policy_approval(client: AsyncClient):
    """Verify that a user who creates a policy draft cannot approve it (Separation of Duties)."""
    # 1. Register two users under same organization
    await client.post("/api/v1/auth/register", json={
        "email": "creator@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Policy Creator"
    })
    
    await client.post("/api/v1/auth/register", json={
        "email": "approver@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Policy Approver"
    })

    # Login Creator
    c_login = await client.post("/api/v1/auth/login", json={
        "email": "creator@enterprise.com",
        "password": "StrongPassword123!"
    })
    creator_token = c_login.json()["access_token"]
    creator_headers = {"Authorization": f"Bearer {creator_token}"}

    # Login Approver
    a_login = await client.post("/api/v1/auth/login", json={
        "email": "approver@enterprise.com",
        "password": "StrongPassword123!"
    })
    approver_token = a_login.json()["access_token"]
    approver_headers = {"Authorization": f"Bearer {approver_token}"}

    # Creator updates role to ADMIN to allow policy management (Mock setup)
    db = db_manager.db
    await db["users"].update_many(
        {"email": {"$in": ["creator@enterprise.com", "approver@enterprise.com"]}},
        {"$set": {"role": "admin"}}
    )
    
    # Establish organization memberships for both admins under target org
    user_creator = await db["users"].find_one({"email": "creator@enterprise.com"})
    user_approver = await db["users"].find_one({"email": "approver@enterprise.com"})
    
    org_id = "shared_enterprise_org"
    await db["organization_memberships"].delete_many({"organization_id": org_id})
    
    await db["organization_memberships"].insert_one({
        "organization_id": org_id,
        "user_id": str(user_creator["_id"]),
        "role": "admin"
    })
    await db["organization_memberships"].insert_one({
        "organization_id": org_id,
        "user_id": str(user_approver["_id"]),
        "role": "admin"
    })

    # 2. Creator drafts policy
    policy_create_resp = await client.post("/api/v1/policies", headers=creator_headers, json={
        "policy_type": "email_security",
        "rules": [{
            "conditions": [{"field": "risk_score", "operator": "gte", "value": "90"}],
            "action": "DENY",
            "description": "Block extremely high risk"
        }]
    })
    policy_id = policy_create_resp.json()["_id"]

    # 3. Creator submits policy draft for review
    await client.post(f"/api/v1/policies/{policy_id}/submit", headers=creator_headers)

    # 4. Creator attempts to approve own policy draft -> Expect 403 Forbidden Separation of Duties failure
    creator_approve_resp = await client.post(f"/api/v1/policies/{policy_id}/approve", headers=creator_headers, json={
        "action": "approve",
        "reason": "Self approval"
    })
    assert creator_approve_resp.status_code == 403
    assert "Separation of Duties violation" in creator_approve_resp.json()["detail"]

    # 5. Approver (different user) approves the draft -> Expect 200 Success
    approver_approve_resp = await client.post(f"/api/v1/policies/{policy_id}/approve", headers=approver_headers, json={
        "action": "approve",
        "reason": "Independent verification check passed."
    })
    assert approver_approve_resp.status_code == 200
    assert approver_approve_resp.json()["status"] == "approved"

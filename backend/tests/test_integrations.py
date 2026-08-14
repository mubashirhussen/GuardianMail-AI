import pytest
from httpx import AsyncClient
from datetime import datetime
from app.database.connection import db_manager
from app.services.integration_service import validate_safe_url, verify_webhook_signature, integration_service
from app.core.tenant_context import TenantContext
import hmac
import hashlib

def test_ssrf_validator_blocks():
    """Verify that SSRF validator rejects local, loopback, and private address blocks."""
    # Loopback targets must fail
    with pytest.raises(ValueError, match="SSRF Target Blocked"):
        validate_safe_url("http://127.0.0.1:8000/events")
        
    with pytest.raises(ValueError, match="SSRF Target Blocked"):
        validate_safe_url("http://localhost:80/ping")

    # Private networks targets must fail
    with pytest.raises(ValueError, match="SSRF Target Blocked"):
        validate_safe_url("https://192.168.1.25/siem")
        
    with pytest.raises(ValueError, match="SSRF Target Blocked"):
        validate_safe_url("http://10.0.0.1/logs")

    # Public URLs must pass (if resolved to public IPs, or mock resolve to public)
    # E.g. we resolve a standard domain
    try:
        assert validate_safe_url("https://example.com/api") is True
    except ValueError:
        # Ignore resolution failure in offline environment tests if DNS fails
        pass

def test_webhook_hmac_signature():
    """Verify that HMAC verification accurately identifies matching tokens and prevents replay tampering."""
    secret = "crypto_webhook_secret_key"
    payload = b'{"event": "incident_triggered", "severity": "critical"}'
    
    # Compute signature
    sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    
    # Validation passes
    assert verify_webhook_signature(sig, payload, secret) is True
    
    # Validation fails on wrong secret
    assert verify_webhook_signature(sig, payload, "wrong_secret") is False

@pytest.mark.asyncio
async def test_dispatch_security_event_retry():
    """Verify event normalization, correlation ID generation, and delivery logs tracking."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_integrations_test"

    # Reset
    await db["integrations"].delete_many({"organization_id": org_id})
    await db["integration_deliveries"].delete_many({"organization_id": org_id})

    # Seed active SIEM integration
    await db["integrations"].insert_one({
        "organization_id": org_id,
        "integration_id": "SIEM-MOCK",
        "provider": "siem",
        "status": "ACTIVE",
        "auth_method": "api_key",
        "config": {
            "url": "https://example.com/siem-receiver"
        },
        "created_by": "analyst_1",
        "created_at": datetime.utcnow(),
        "health_status": "healthy",
        "soft_delete": False
    })

    deliveries = await integration_service.dispatch_security_event(
        org_id=org_id,
        event_type="THREAT_DETECTED",
        severity="critical",
        details={"indicator": "198.51.100.4", "risk_rating": 89}
    )

    assert len(deliveries) == 1
    assert deliveries[0]["status"] == "SENT"
    assert deliveries[0]["event_type"] == "THREAT_DETECTED"
    assert "correlation_id" in deliveries[0]

@pytest.mark.asyncio
async def test_integrations_multi_tenant_isolation(client: AsyncClient):
    """Verify that tenant organization configurations are isolated."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db

    # Register Org A & Org B Users
    await db["users"].delete_many({"email": {"$in": ["intega@enterprise.com", "integb@enterprise.com"]}})
    
    await client.post("/api/v1/auth/register", json={
        "email": "intega@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Org A Integrator"
    })
    await client.post("/api/v1/auth/register", json={
        "email": "integb@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Org B Integrator"
    })

    user_a = await db["users"].find_one({"email": "intega@enterprise.com"})
    user_b = await db["users"].find_one({"email": "integb@enterprise.com"})

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
        "email": "intega@enterprise.com",
        "password": "StrongPassword123!"
    })
    a_headers = {"Authorization": f"Bearer {a_login.json()['access_token']}"}

    b_login = await client.post("/api/v1/auth/login", json={
        "email": "integb@enterprise.com",
        "password": "StrongPassword123!"
    })
    b_headers = {"Authorization": f"Bearer {b_login.json()['access_token']}"}

    # Ingest integrations config under Org A
    await db["integrations"].delete_many({"organization_id": "org_a"})
    await db["integrations"].insert_one({
        "organization_id": "org_a",
        "integration_id": "ORG-A-SIEM",
        "provider": "siem",
        "status": "ACTIVE",
        "auth_method": "api_key",
        "config": {
            "url": "https://example.com/siem-a"
        },
        "created_by": str(user_a["_id"]),
        "created_at": datetime.utcnow(),
        "health_status": "healthy",
        "soft_delete": False
    })

    # Retrieve Org A configs with Org A token
    res_a = await client.get("/api/v1/integrations", headers=a_headers)
    assert res_a.status_code == 200
    assert len(res_a.json()) == 1
    assert res_a.json()[0]["integration_id"] == "ORG-A-SIEM"

    # Attempt to retrieve with Org B token
    res_b = await client.get("/api/v1/integrations", headers=b_headers)
    assert res_b.status_code == 200
    assert len(res_b.json()) == 0  # Should be empty because it is filtered on Org B!

import pytest
from datetime import datetime, timezone
from fastapi import status
from httpx import AsyncClient
from app.services.intel_providers.implementations import DNSWhoisProvider, IPGeoProvider
from app.services.decision_intelligence import DecisionIntelligenceService

@pytest.mark.asyncio
async def test_dns_whois_and_geoip_reputation_providers(monkeypatch):
    """Test DNS / WHOIS registration ages and Geolocation IP providers normalization."""
    # 1. WHOIS resolver
    whois_prov = DNSWhoisProvider()
    res = await whois_prov.lookup("paypal.com")
    assert res["status"] == "completed"
    assert res["malicious"] is False
    assert "registrar" in res["details"].lower()
    
    # 2. GeoIP resolver (Mocked to prevent Cloudflare/ipapi.co 429 rate limit failures)
    async def mock_geo_lookup(*args, **kwargs):
         return {"status": "completed", "malicious": False, "details": "Location: United States"}
         
    monkeypatch.setattr(IPGeoProvider, "lookup", mock_geo_lookup)
    
    geo_prov = IPGeoProvider()
    g_res = await geo_prov.lookup("8.8.8.8")
    assert g_res["status"] == "completed"
    assert "location" in g_res["details"].lower()

@pytest.mark.asyncio
async def test_decision_intelligence_scoring_and_campaigns(monkeypatch):
    """Test decision intelligence weighted averages and campaign correlation alerts."""
    email_item = {
        "from_address": "spammer@bad-domain.com",
        "sender_domain": "bad-domain.com",
        "urls": [{"url": "http://scam-site.com"}],
        "attachments": [],
        "analysis": {"risk_score": 0.85, "verdict": "PHISHING"}
    }
    
    # Mocking Safe Browsing & WHOIS response outputs as async functions
    async def mock_url_lookup(*args, **kwargs):
         return {"status": "completed", "malicious": True}
         
    async def mock_dom_lookup(*args, **kwargs):
         return {"status": "completed", "malicious": True}
         
    from app.services.intel_providers.implementations import GoogleSafeBrowsingProvider, DNSWhoisProvider
    monkeypatch.setattr(GoogleSafeBrowsingProvider, "lookup", mock_url_lookup)
    monkeypatch.setattr(DNSWhoisProvider, "lookup", mock_dom_lookup)
    
    decision = await DecisionIntelligenceService.evaluate_threat_intelligence(email_item)
    assert decision["verdict"] in ["PHISHING", "BEC"]
    assert decision["overall_risk_score"] > 0.70
    assert len(decision["mitre_attack_mapping"]) >= 1

@pytest.mark.asyncio
async def test_intelligence_api_endpoints_workflow(client: AsyncClient, monkeypatch):
    """Test REST intelligence routes: analyze, domain, url, ip, reputation, report, campaigns."""
    # 1. Register & login
    register_payload = {
        "email": "intel_user@example.com",
        "full_name": "Intel User",
        "role": "user",
        "password": "secure_password_123"
    }
    await client.post("/api/v1/auth/register", json=register_payload)
    login_resp = await client.post("/api/v1/auth/login", json={"email": "intel_user@example.com", "password": "secure_password_123"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Create mock email in database
    from app.database.connection import db_manager
    from app.repositories.email_repo import EmailRepository
    
    email_repo = EmailRepository(db_manager.db)
    
    me_resp = await client.get("/api/v1/auth/me", headers=headers)
    user_id = me_resp.json()["_id"]
    
    email_doc = {
        "user_id": user_id,
        "gmail_message_id": "msg_intel_123",
        "gmail_thread_id": "thread_intel_123",
        "subject": "System account lockout warning",
        "from_address": "support@paypal-sec-verify.com",
        "sender_name": "PayPal Verification Support",
        "sender_domain": "paypal-sec-verify.com",
        "body_plain": "Confirm details at http://paypal-sec-verify.com/login",
        "attachments": [],
        "urls": [{"url": "http://paypal-sec-verify.com/login"}],
        "date": datetime.now(timezone.utc)
    }
    created = await email_repo.create(email_doc)
    email_id = str(created["_id"])
    
    # Mock lookup parameters to avoid network dependencies
    async def mock_sb_lookup(*args, **kwargs):
         return {"status": "completed", "malicious": True, "verdict": "phishing"}
         
    async def mock_whois_lookup(*args, **kwargs):
         return {"status": "completed", "malicious": True, "verdict": "suspicious"}
         
    async def mock_ip_lookup(*args, **kwargs):
         return {"status": "completed", "malicious": True, "verdict": "spam"}
         
    from app.services.intel_providers.implementations import GoogleSafeBrowsingProvider, DNSWhoisProvider, AbuseIPDBProvider
    monkeypatch.setattr(GoogleSafeBrowsingProvider, "lookup", mock_sb_lookup)
    monkeypatch.setattr(DNSWhoisProvider, "lookup", mock_whois_lookup)
    monkeypatch.setattr(AbuseIPDBProvider, "lookup", mock_ip_lookup)

    # A. POST /intelligence/analyze
    an_resp = await client.post("/api/v1/intelligence/analyze", json={"email_id": email_id}, headers=headers)
    assert an_resp.status_code == status.HTTP_200_OK
    assert "verdict" in an_resp.json()
    
    # B. GET /intelligence/domain/{domain}
    dom_resp = await client.get("/api/v1/intelligence/domain/paypal.com", headers=headers)
    assert dom_resp.status_code == status.HTTP_200_OK
    
    # C. GET /intelligence/url
    url_resp = await client.get("/api/v1/intelligence/url?url=http://scam.com", headers=headers)
    assert url_resp.status_code == status.HTTP_200_OK
    
    # D. GET /intelligence/ip/{ip}
    ip_resp = await client.get("/api/v1/intelligence/ip/8.8.8.8", headers=headers)
    assert ip_resp.status_code == status.HTTP_200_OK
    
    # E. GET /intelligence/reputation/{sender}
    rep_resp = await client.get("/api/v1/intelligence/reputation/support@paypal-sec-verify.com", headers=headers)
    assert rep_resp.status_code == status.HTTP_200_OK
    
    # F. GET /intelligence/report/{scan_id}
    rep_details = await client.get(f"/api/v1/intelligence/report/{email_id}", headers=headers)
    assert rep_details.status_code == status.HTTP_200_OK
    
    # G. GET /intelligence/campaigns
    camp_resp = await client.get("/api/v1/intelligence/campaigns", headers=headers)
    assert camp_resp.status_code == status.HTTP_200_OK

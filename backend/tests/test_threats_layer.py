import pytest
from datetime import datetime, timezone
from fastapi import status
from httpx import AsyncClient
from app.services.threat_detector import ThreatDetectorService

@pytest.mark.asyncio
async def test_threat_detector_scoring_and_false_positive_reduction():
    """Test 12-detector scoring pipeline triggers and false positive calibration."""
    # 1. Email with only Social Engineering keywords (urgent style only) -> should be calibrated to safe/suspicious cap
    style_only_email = {
        "subject": "Urgent immediate action required",
        "body_plain": "Your account will be suspended within 24 hours failure to respond immediately",
        "from_address": "legit@safe.com",
        "sender_domain": "safe.com",
        "sender_name": "Safe User",
        "attachments": [],
        "urls": [],
        "raw_msg": None
    }
    
    analysis = await ThreatDetectorService.analyze_email(style_only_email)
    # The score should be capped because there is no hard structural indicator (sender, domain, url, attachment pass)
    assert analysis.risk_score <= 0.45
    assert analysis.verdict in ["SAFE", "SUSPICIOUS", "SPAM"]
    
    # 2. Email with display name spoofing + dangerous attachment -> triggers strong malicious verdict
    phishing_email = {
        "subject": "Security notice update",
        "body_plain": "Verify bank transfer credentials",
        "from_address": "hacker@fraud-domain.com",
        "sender_domain": "fraud-domain.com",
        "sender_name": "Google Support Staff",
        "attachments": [{"filename": "invoice_update.exe", "size_bytes": 1024}],
        "urls": [],
        "raw_msg": None
    }
    
    phish_analysis = await ThreatDetectorService.analyze_email(phishing_email)
    assert phish_analysis.risk_score > 0.60
    assert phish_analysis.verdict in ["PHISHING", "MALWARE", "BEC", "CREDENTIAL_HARVESTING"]
    assert len(phish_analysis.positive_evidence) >= 2

@pytest.mark.asyncio
async def test_threats_api_endpoints_workflow(client: AsyncClient):
    """Test threats endpoints logic mapping: analyze, history, evidence, get, and reanalyze."""
    # 1. Register & login
    register_payload = {
        "email": "threats_user@example.com",
        "full_name": "Threats User",
        "role": "user",
        "password": "secure_password_123"
    }
    await client.post("/api/v1/auth/register", json=register_payload)
    login_resp = await client.post("/api/v1/auth/login", json={"email": "threats_user@example.com", "password": "secure_password_123"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Create mock email record in database
    from app.database.connection import db_manager
    from app.repositories.email_repo import EmailRepository
    
    email_repo = EmailRepository(db_manager.db)
    
    me_resp = await client.get("/api/v1/auth/me", headers=headers)
    user_id = me_resp.json()["_id"]
    
    email_doc = {
        "user_id": user_id,
        "gmail_message_id": "msg_threat_123",
        "gmail_thread_id": "thread_threat_123",
        "subject": "Wire Transfer Needed Immediately",
        "from_address": "boss@partner-company.com",
        "sender_domain": "partner-company.com",
        "body_plain": "Please process a wire transfer of $10,000 for the vendor invoice.",
        "attachments": [],
        "urls": [],
        "date": datetime.now(timezone.utc)
    }
    created = await email_repo.create(email_doc)
    email_id = str(created["_id"])
    
    # 3. POST /threats/analyze to perform multi-engine checks
    analyze_resp = await client.post("/api/v1/threats/analyze", json={"email_id": email_id}, headers=headers)
    assert analyze_resp.status_code == status.HTTP_200_OK
    data = analyze_resp.json()
    assert "verdict" in data
    assert "positive_evidence" in data
    
    # 4. GET /threats/history
    hist_resp = await client.get("/api/v1/threats/history", headers=headers)
    assert hist_resp.status_code == status.HTTP_200_OK
    
    # 5. GET /threats/evidence/{id}
    ev_resp = await client.get(f"/api/v1/threats/evidence/{email_id}", headers=headers)
    assert ev_resp.status_code == status.HTTP_200_OK
    assert "positive_evidence" in ev_resp.json()
    
    # 6. GET /threats/{id}
    get_resp = await client.get(f"/api/v1/threats/{email_id}", headers=headers)
    assert get_resp.status_code == status.HTTP_200_OK
    assert get_resp.json()["verdict"] == data["verdict"]
    
    # 7. POST /threats/reanalyze
    re_resp = await client.post("/api/v1/threats/reanalyze", json={"email_id": email_id}, headers=headers)
    assert re_resp.status_code == status.HTTP_200_OK
    assert re_resp.json()["status"] == "success"

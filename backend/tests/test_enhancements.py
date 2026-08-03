import pytest
from httpx import AsyncClient
from datetime import datetime, timezone
from app.services.exposure_monitor import IdentityExposureService
from app.services.sender_trust import SenderTrustService
from app.services.domain_intel import DomainIntelService
from app.services.recovery_assistant import CredentialRecoveryService
from app.services.timeline_builder import TimelineBuilderService
from app.services.education_service import CyberSafetyEducationService
from tests.conftest import MockRedis, MockDatabase

@pytest.mark.asyncio
async def test_identity_exposure_monitor():
    # Test checking exposure on victim/test email (should return mock breaches)
    breaches = await IdentityExposureService.check_identity_exposure("victim@example.com")
    assert len(breaches) == 2
    assert "Adobe" in breaches[0]["title"]
    assert "LinkedIn" in breaches[1]["title"]
    
    # Test clean email (should return no breaches)
    clean = await IdentityExposureService.check_identity_exposure("clean_user@example.com")
    assert len(clean) == 0

@pytest.mark.asyncio
async def test_sender_trust_history():
    db = MockDatabase()
    from app.repositories.sender_trust_repo import SenderTrustRepository
    repo = SenderTrustRepository(db)
    
    # First email: score = 0.1 (safe)
    record, anomaly, desc = await SenderTrustService.evaluate_sender_trust(
        sender_email="news@newsletter.com",
        current_risk_score=0.1,
        is_phishing=False,
        repo=repo
    )
    assert record["total_emails_scanned"] == 1
    assert not anomaly
    
    # Second & Third safe emails to establish baseline
    await SenderTrustService.evaluate_sender_trust("news@newsletter.com", 0.08, False, repo)
    await SenderTrustService.evaluate_sender_trust("news@newsletter.com", 0.12, False, repo)
    
    # Fourth email: sudden risk spike (score = 0.85)
    record, anomaly, desc = await SenderTrustService.evaluate_sender_trust(
        sender_email="news@newsletter.com",
        current_risk_score=0.85,
        is_phishing=True,
        repo=repo
    )
    assert record["total_emails_scanned"] == 4
    assert anomaly
    assert "risk score spike" in desc.lower()

@pytest.mark.asyncio
async def test_domain_intelligence():
    # Test paypal.com (should load offline stats)
    intel = await DomainIntelService.get_domain_intelligence("paypal.com")
    assert intel["registrar"] == "MarkMonitor, Inc."
    assert intel["lookalike_analysis"] == []
    
    # Test typosquatting lookalike
    intel_lookalike = await DomainIntelService.get_domain_intelligence("paypa1.com")
    assert len(intel_lookalike["lookalike_analysis"]) == 1
    assert intel_lookalike["lookalike_analysis"][0]["brand"] == "paypal"
    assert intel_lookalike["lookalike_analysis"][0]["similarity"] > 0.75

def test_credential_recovery_and_safety_education():
    # Test checklist mapping
    checklist = CredentialRecoveryService.get_recovery_checklist(
        verdict="CRITICAL",
        indicators=["Social Engineering Credential Harvesting", "SPF Authentication Failure"]
    )
    assert len(checklist) >= 3
    assert any(item["item_id"] == "reset_password" for item in checklist)
    assert any(item["item_id"] == "enable_mfa" for item in checklist)
    
    # Test safety cards mapping
    cards = CyberSafetyEducationService.get_educational_materials(
        indicators=["SPF Authentication Failure", "Domain Typosquatting"]
    )
    assert len(cards) == 2
    assert any("SPF" in c["title"] for c in cards)
    assert any("Typosquatting" in c["title"] for c in cards)

def test_timeline_builder():
    parsed_email = {
        "from_address": "spoofer@paypa1.com",
        "subject": "Reset password",
        "urls": [{"url": "http://paypa1.com"}],
        "attachments": []
    }
    
    timeline = TimelineBuilderService.build_incident_timeline(
        parsed_email=parsed_email,
        analysis_verdict="HIGH",
        risk_score=0.8,
        has_auth_fail=True,
        has_suspicious_urls=True,
        has_suspicious_attachments=False
    )
    
    assert len(timeline) == 4  # RECEIVED, AUTHENTICATION_CHECKS, LINK_VERIFICATION, THREAT_CLASSIFICATION
    assert timeline[0]["event"] == "EMAIL_RECEIVED"
    assert timeline[-1]["event"] == "THREAT_CLASSIFICATION"
    assert "Assigned risk score 80/100" in timeline[-1]["description"]

@pytest.mark.asyncio
async def test_endpoints_workflow(client: AsyncClient):
    # 1. Register and login to authenticate
    email = "user_test@guardianmail.ai"
    password = "SafePassword99!"
    
    reg = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "full_name": "Test User", "role": "user"}
    )
    assert reg.status_code == 201
    
    log = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password}
    )
    assert log.status_code == 200
    token = log.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Test Identity Exposure Monitor endpoint
    exp_resp = await client.get("/api/v1/exposure/check?email=victim@target.com", headers=headers)
    assert exp_resp.status_code == 200
    assert len(exp_resp.json()) == 2
    
    # 3. Test Domain Intelligence Center endpoint
    domain_resp = await client.get("/api/v1/threat-intel/domain/paypal.com", headers=headers)
    assert domain_resp.status_code == 200
    assert domain_resp.json()["registrar"] == "MarkMonitor, Inc."
    
    # 4. Test Observability Metrics endpoint
    met_resp = await client.get("/api/v1/metrics", headers=headers)
    assert met_resp.status_code == 200
    assert "guardianmail_database_healthy" in met_resp.text
    
    # 5. Test JSON Metrics endpoint
    met_json = await client.get("/api/v1/metrics/json", headers=headers)
    assert met_json.status_code == 200
    assert "system_status" in met_json.json()

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.services.advisories_service import ThreatAdvisoriesService, MAJOR_ADVISORIES

@pytest.mark.asyncio
async def test_get_advisories_service():
    """Verify ThreatAdvisoriesService returns all major real-world threat campaigns."""
    all_advisories = ThreatAdvisoriesService.get_all_advisories()
    assert len(all_advisories) >= 7
    
    # Check India Post Smishing
    smishing = ThreatAdvisoriesService.get_advisory_by_id("ADV-2026-IN01")
    assert smishing is not None
    assert "India Post" in smishing["title"]
    assert "1930" in str(smishing["what_to_do_if_affected"])
    assert len(smishing["protection_steps"]) > 0

    # Filter by CRITICAL severity
    critical = ThreatAdvisoriesService.get_all_advisories(severity="CRITICAL")
    assert len(critical) >= 3
    for c in critical:
        assert c["severity"] == "CRITICAL"

@pytest.mark.asyncio
async def test_get_advisories_api_endpoint():
    """Verify GET /api/v1/threats/advisories endpoint works without authentication."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/threats/advisories")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["count"] >= 7
        assert any("India Post" in adv["title"] for adv in data["advisories"])
        assert any("Electricity Bill" in adv["title"] for adv in data["advisories"])
        assert any("Digital Arrest" in adv["title"] for adv in data["advisories"])

@pytest.mark.asyncio
async def test_get_single_advisory_api_endpoint():
    """Verify GET /api/v1/threats/advisories/{id} returns details."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/threats/advisories/ADV-2026-IN01")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["advisory"]["id"] == "ADV-2026-IN01"
        assert len(data["advisory"]["modus_operandi"]) >= 4

@pytest.mark.asyncio
async def test_format_certin_complaint():
    """Verify complaint formatting outputs official Indian cyber crime reference format."""
    text = ThreatAdvisoriesService.format_certin_complaint(
        reporter_name="Mubashir Hussen",
        reporter_email="mubashirsk381@gmail.com",
        reporter_phone="+919876543210",
        incident_type="India Post SMS Phishing",
        suspect_details="Sender: CP-INDPOST, URL: indiapost-parcel.top",
        incident_description="Received SMS regarding package delivery holding fee.",
        financial_loss=25000.0,
        transaction_id="UPI/329482938492/Axis",
        bank_name="State Bank of India",
        evidence_urls=["https://indiapost-parcel.top/update", "https://scam-gateway.com"]
    )
    assert "OFFICIAL CYBERCRIME & CERT-IN INCIDENT REPORT DRAFT" in text
    assert "mubashirsk381@gmail.com" in text
    assert "₹25,000.00" in text
    assert "https://cybercrime.gov.in" in text
    assert "1930" in text


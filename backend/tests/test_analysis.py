import pytest
from app.services.email_parser import EmailParserService
from app.services.threat_detector import ThreatDetectorService
from app.services.recommender import RecommendationService

# Constructing raw EML bytes representing standard phishing email
PHISHING_EML_TEXT = (
    "From: PayPal Support <security@paypa1.com>\n"
    "To: victim@target.com\n"
    "Subject: URGENT: Account locked - Unusual activity detected!\n"
    "Date: Sun, 26 Jul 2026 12:00:00 +0000\n"
    "Received-SPF: fail (domain of paypa1.com does not designate permitted sender IPs)\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "Content-Disposition: inline\n\n"
    "Dear customer, your account has been limited due to suspicious access attempts.\n"
    "Please click here immediately to verify your identity and enter your credentials:\n"
    "http://paypa1.com/login/paypal\n\n"
    "Failure to respond within 24 hours will result in permanent suspension.\n"
)

@pytest.mark.asyncio
async def test_email_threat_engine():
    # 1. Test parsing
    eml_bytes = PHISHING_EML_TEXT.encode("utf-8")
    parsed = EmailParserService.parse_eml_bytes(eml_bytes)
    
    assert parsed["subject"] == "URGENT: Account locked - Unusual activity detected!"
    assert parsed["from_address"] == "security@paypa1.com"
    assert len(parsed["urls"]) == 1
    assert parsed["urls"][0]["domain"] == "paypa1.com"

    # 2. Test threat detection & scoring
    analysis = await ThreatDetectorService.analyze_email(parsed)
    
    # Verdict should be CRITICAL or HIGH due to SPF failure, Typosquatting of PayPal, credential request and urgency keywords
    assert analysis.verdict in ["CRITICAL", "HIGH", "PHISHING"]
    assert analysis.risk_score >= 0.6
    
    # Verify indicators were captured
    indicators = [ind.indicator for ind in analysis.indicators] + [ind.detail for ind in analysis.indicators]
    assert any("SPF" in ind for ind in indicators)
    assert any("urgent" in ind.lower() or "suspicious" in ind.lower() or "harvesting" in ind.lower() or "impersonation" in ind.lower() for ind in indicators)
    assert any("typosquatting" in ind.lower() or "spoof" in ind.lower() for ind in indicators)

    # 3. Test recommendation compiler
    recs = RecommendationService.generate_recommendations(analysis)
    assert recs.action_priority in ["HIGH", "LOW"]
    assert len(recs.suggestions) > 0
    assert "DO NOT" in recs.suggestions[0] or "Treat" in recs.suggestions[0] or "legitimate" in recs.suggestions[0]

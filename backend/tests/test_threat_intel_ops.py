import pytest
from datetime import datetime, timezone, timedelta
import asyncio
from bson import ObjectId

from app.database.connection import db_manager
from app.services.threat_intel import ThreatIntelService
from app.services.threat_correlation import threat_correlation_service
from app.workers.tasks import sweep_expired_indicators_task

@pytest.fixture
async def setup_threat_ops_data():
    db = db_manager.db
    org_a = "org_ops_a"
    org_b = "org_ops_b"

    # Clean old indicators
    await db["threat_indicators"].delete_many({})
    await db["audit_logs"].delete_many({})

    # Ingest baseline Org A active IOC
    ioc_a = await db["threat_indicators"].insert_one({
        "organization_id": org_a,
        "indicator_type": "domain",
        "indicator_value": "malicious-ops-a.com",
        "normalized_value": "malicious-ops-a.com",
        "status": "ACTIVE",
        "severity": "HIGH",
        "confidence": 80,
        "first_seen": datetime.now(timezone.utc),
        "last_seen": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=5),
        "soft_delete": False
    })

    # Ingest baseline Org B active IOC
    ioc_b = await db["threat_indicators"].insert_one({
        "organization_id": org_b,
        "indicator_type": "domain",
        "indicator_value": "malicious-ops-b.com",
        "normalized_value": "malicious-ops-b.com",
        "status": "ACTIVE",
        "severity": "HIGH",
        "confidence": 85,
        "first_seen": datetime.now(timezone.utc),
        "last_seen": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=5),
        "soft_delete": False
    })

    return {
        "org_a": org_a,
        "org_b": org_b,
        "ioc_a_id": str(ioc_a.inserted_id),
        "ioc_b_id": str(ioc_b.inserted_id)
    }

@pytest.mark.anyio
async def test_ioc_validation_rules():
    """Verify that malformed IOCs are rejected and correct indicators are accepted."""
    # IPs
    assert ThreatIntelService.validate_indicator("ipv4", "1.1.1.1") is True
    assert ThreatIntelService.validate_indicator("ipv4", "256.0.0.1") is False
    assert ThreatIntelService.validate_indicator("ipv4", "not-an-ip") is False
    assert ThreatIntelService.validate_indicator("ipv6", "2001:db8::1") is True

    # Domains
    assert ThreatIntelService.validate_indicator("domain", "safe-domain.com") is True
    assert ThreatIntelService.validate_indicator("domain", "xn--lookalike-abc.com") is True
    assert ThreatIntelService.validate_indicator("domain", "a" * 70 + ".com") is False  # Label too long
    assert ThreatIntelService.validate_indicator("domain", "domain-.com") is False      # Invalid boundaries

    # URLs
    assert ThreatIntelService.validate_indicator("url", "https://safe-domain.com/path") is True
    assert ThreatIntelService.validate_indicator("url", "ftp://unsafe-protocol.com") is False
    assert ThreatIntelService.validate_indicator("url", "javascript:alert(1)") is False

    # Hashes
    assert ThreatIntelService.validate_indicator("file_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is True
    assert ThreatIntelService.validate_indicator("file_hash", "e3b0c44298fc1c14") is False  # Too short

    # Ingestion raises ValueError
    with pytest.raises(ValueError):
        await threat_correlation_service.ingest_indicator(
            indicator_type="ipv4",
            indicator_value="999.999.999.999",
            source="Test"
        )

@pytest.mark.anyio
async def test_indicator_central_normalization():
    """Verify indicators are correctly standardized to canonical representations."""
    # Domain trailing dots & casing
    assert ThreatIntelService.normalize_indicator_value("domain", "  MALICIOUS-Domain.COM.  ") == "malicious-domain.com"
    # Email casing
    assert ThreatIntelService.normalize_indicator_value("email_address", "  ATTACKER@Enterprise.COM ") == "attacker@enterprise.com"
    # Hash casing
    assert ThreatIntelService.normalize_indicator_value("file_hash", " ABCDEF12345 ") == "abcdef12345"
    # URL scheme casing & domain lowercase, path case-sensitive
    assert ThreatIntelService.normalize_indicator_value("url", "HTTP://mY-DoMaIn.COM/Path/To/Payload.exe") == "http://my-domain.com/Path/To/Payload.exe"

@pytest.mark.anyio
async def test_ssrf_ip_resolution_blockers():
    """Ensure loopbacks, private networks, cloud metadata, and localhost resolve checks raise ValueError."""
    # Loopback
    assert ThreatIntelService.is_ssrf_blocked_ip("127.0.0.1") is True
    assert ThreatIntelService.is_ssrf_blocked_ip("::1") is True

    # Private ranges
    assert ThreatIntelService.is_ssrf_blocked_ip("192.168.1.50") is True
    assert ThreatIntelService.is_ssrf_blocked_ip("10.0.0.1") is True
    assert ThreatIntelService.is_ssrf_blocked_ip("172.16.2.20") is True

    # Cloud metadata
    assert ThreatIntelService.is_ssrf_blocked_ip("169.254.169.254") is True

    # expansion throws on SSRF targets
    with pytest.raises(ValueError) as exc:
        await ThreatIntelService.expand_short_url("http://127.0.0.1")
    assert "SSRF block" in str(exc.value)

    with pytest.raises(ValueError) as exc:
        await ThreatIntelService.expand_short_url("http://localhost")
    assert "SSRF block" in str(exc.value)

@pytest.mark.anyio
async def test_ioc_expiration_sweep_task(setup_threat_ops_data):
    """Verify task sweep identifies expired indicators and updates statuses."""
    db = db_manager.db
    org_a = setup_threat_ops_data["org_a"]

    # Seed an indicator that is expired
    expired_ioc = await db["threat_indicators"].insert_one({
        "organization_id": org_a,
        "indicator_type": "domain",
        "indicator_value": "already-expired-ioc.com",
        "normalized_value": "already-expired-ioc.com",
        "status": "ACTIVE",
        "severity": "HIGH",
        "confidence": 75,
        "first_seen": datetime.now(timezone.utc) - timedelta(days=10),
        "last_seen": datetime.now(timezone.utc) - timedelta(days=10),
        "expires_at": datetime.now(timezone.utc) - timedelta(days=1),
        "soft_delete": False
    })

    # Run celery Beat task sweep
    res = sweep_expired_indicators_task()
    assert res["status"] == "SUCCESS"
    assert res["expired"] >= 1

    # Verify document in DB has updated status
    doc = await db["threat_indicators"].find_one({"_id": expired_ioc.inserted_id})
    assert doc["status"] == "EXPIRED"

    # Verify audit event logged
    audits = await db["audit_logs"].find({"action": "THREAT_INDICATOR_EXPIRED"}).to_list()
    audit = next((a for a in audits if a.get("details", {}).get("indicator_id") == str(expired_ioc.inserted_id)), None)
    assert audit is not None

@pytest.mark.anyio
async def test_multi_tenant_ioc_isolation(setup_threat_ops_data):
    """Ensure cross-org search or matching rejects unauthorized lookups."""
    org_a = setup_threat_ops_data["org_a"]
    org_b = setup_threat_ops_data["org_b"]

    # Search indicators using Org A context -> should return malicious-ops-a.com but NOT malicious-ops-b.com
    iocs_a = await threat_correlation_service.indicator_repo.search_indicators(org_id=org_a)
    values_a = [ioc["normalized_value"] for iococ in iocs_a for ioc in [iococ]]
    assert "malicious-ops-a.com" in values_a
    assert "malicious-ops-b.com" not in values_a

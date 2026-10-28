import pytest
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

from app.database.connection import db_manager

class StagingThreatIntelService:
    def __init__(self, db):
        self.db = db

    def normalize_indicator(self, raw_indicator: str) -> str:
        """Normalize URL/domain indicators to lowercase canonical host names."""
        raw_indicator = raw_indicator.strip().lower()
        if "://" in raw_indicator:
            parsed = urlparse(raw_indicator)
            return parsed.netloc
        return raw_indicator

    def calculate_confidence(self, base_score: int, created_at: datetime) -> float:
        """Apply staleness controls: decay confidence by 5% per day since creation."""
        now = datetime.now(timezone.utc)
        days_old = (now - created_at).days
        decay = 0.95 ** max(days_old, 0)
        return round(base_score * decay, 2)

    async def ingest_indicator(self, org_id: str, indicator: str, base_score: int, is_shared: bool) -> dict:
        """Ingest threat indicator, enforcing strict tenant context separation on private values."""
        normalized = self.normalize_indicator(indicator)
        doc = {
            "organization_id": org_id if not is_shared else "GLOBAL_SYSTEM",
            "indicator": normalized,
            "base_score": base_score,
            "is_shared": is_shared,
            "created_at": datetime.now(timezone.utc)
        }
        await self.db["threat_indicators"].insert_one(doc)
        return {"status": "INGESTED", "indicator": normalized}

    async def query_indicators(self, org_id: str) -> list:
        """Fetch all globally shared indicators plus org-private indicators."""
        if not org_id:
            raise ValueError("Organization namespace context required")
        
        cursor = self.db["threat_indicators"].find({
            "$or": [
                {"organization_id": org_id},
                {"is_shared": True}
            ]
        })
        return await cursor.to_list(1000)

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e13_9_ti"
    
    # Clean threat indicators
    await db["threat_indicators"].delete_many({})
    
    return {"org_id": org_id, "service": StagingThreatIntelService(db)}

@pytest.mark.anyio
async def test_threat_indicator_normalization(setup_gate_data):
    """Verify canonical domain extraction converts indicators to lowercase hostnames."""
    service = setup_gate_data["service"]
    
    norm1 = service.normalize_indicator("HTTP://MALICIOUS-PHISHING.COM/login?user=1")
    assert norm1 == "malicious-phishing.com"
    
    norm2 = service.normalize_indicator("  Suspicious-Domain.Org  ")
    assert norm2 == "suspicious-domain.org"

@pytest.mark.anyio
async def test_confidence_decay_and_expiration(setup_gate_data):
    """Verify that confidence score decays over time to control staleness."""
    service = setup_gate_data["service"]
    
    # Fresh indicator has zero decay
    now = datetime.now(timezone.utc)
    score_fresh = service.calculate_confidence(80, now)
    assert score_fresh == 80.0
    
    # 5 days old indicator has confidence decayed
    five_days_ago = now - timedelta(days=5)
    score_decayed = service.calculate_confidence(80, five_days_ago)
    assert score_decayed < 80.0
    assert score_decayed == round(80 * (0.95 ** 5), 2)

@pytest.mark.anyio
async def test_tenant_scoped_threat_isolation(setup_gate_data):
    """Verify tenant isolation filters shared from private organization indicators."""
    org_id = setup_gate_data["org_id"]
    service = setup_gate_data["service"]
    
    # Ingest global indicator
    await service.ingest_indicator(org_id, "global-bad.com", 90, is_shared=True)
    # Ingest private indicator
    await service.ingest_indicator(org_id, "private-bad.com", 85, is_shared=False)
    
    # Query under org returns both
    org_list = await service.query_indicators(org_id)
    assert len(org_list) == 2
    
    # Query under different org only returns global one
    other_list = await service.query_indicators("other_org")
    assert len(other_list) == 1
    assert other_list[0]["indicator"] == "global-bad.com"

@pytest.mark.anyio
async def test_e6_boundary_enforcement(setup_gate_data):
    """Verify threat intelligence triggers alarms but cannot directly execute SOAR blocks."""
    # SOAR actions require human-in-the-loop approval or policy decision records
    from app.services.soar_execution_service import soar_execution_service
    
    # Directly running SOAR blocks without approved decision tokens fails closed
    with pytest.raises(ValueError):
        await soar_execution_service.create_execution_request(
            organization_id=setup_gate_data["org_id"],
            decision_id="00000000000000000000dec9",
            token_id="tok_invalid",
            token_secret="sec",
            user_id="ti_auto_agent"
        )

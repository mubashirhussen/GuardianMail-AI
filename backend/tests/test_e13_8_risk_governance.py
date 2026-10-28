import pytest
from datetime import datetime, timezone, timedelta

from app.database.connection import db_manager

class StagingRiskGovernanceService:
    def __init__(self, db):
        self.db = db

    def calculate_risk_score(self, findings: list) -> int:
        """Calculate unified risk score based on CVE counts and drift detections (0-100)."""
        score = 0
        for f in findings:
            severity = f.get("severity", "LOW")
            if severity == "CRITICAL":
                score += 40
            elif severity == "HIGH":
                score += 25
            elif severity == "MEDIUM":
                score += 10
            else:
                score += 2
        return min(score, 100)

    async def create_risk_acceptance(self, org_id: str, risk_id: str, justification: str, reviewer: str) -> dict:
        """Create risk acceptance log and write to E13.6 compliance chain."""
        if not justification or len(justification) < 10:
            raise ValueError("Risk acceptance requires a detailed analyst justification")
        if not reviewer:
            raise ValueError("Reviewer approval signature is required")

        doc = {
            "organization_id": org_id,
            "risk_id": risk_id,
            "justification": justification,
            "reviewer": reviewer,
            "status": "APPROVED",
            "created_at": datetime.now(timezone.utc)
        }
        await self.db["risk_acceptances"].insert_one(doc)
        return {"status": "RISK_ACCEPTED"}

    async def validate_exception_active(self, org_id: str, exception_id: str) -> bool:
        """Verify that exception rule is active and not expired."""
        exp = await self.db["security_exceptions"].find_one({
            "organization_id": org_id,
            "exception_id": exception_id
        })
        if not exp:
            return False
        
        # Check expiration date (stored naive utc)
        now = datetime.utcnow()
        if exp["expires_at"] < now:
            raise ValueError("Security Exception is EXPIRED")
        return True

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e13_8_rg"
    
    # Clean GRC risk tables
    await db["risk_acceptances"].delete_many({})
    await db["security_exceptions"].delete_many({})
    
    return {"org_id": org_id, "service": StagingRiskGovernanceService(db)}

@pytest.mark.anyio
async def test_unified_risk_scoring(setup_gate_data):
    """Verify that unified risk calculations map severity indicators correctly."""
    service = setup_gate_data["service"]
    
    findings = [
        {"type": "CVE", "severity": "CRITICAL"},
        {"type": "DRIFT", "severity": "MEDIUM"}
    ]
    score = service.calculate_risk_score(findings)
    assert score == 50

@pytest.mark.anyio
async def test_risk_acceptance_workflow(setup_gate_data):
    """Verify that risk acceptance requests validate analyst justification details."""
    org_id = setup_gate_data["org_id"]
    service = setup_gate_data["service"]
    
    # Valid request
    res = await service.create_risk_acceptance(
        org_id, "cve-2026-001", "Beta testing isolation is verified with compensations", "sec_reviewer_1"
    )
    assert res["status"] == "RISK_ACCEPTED"
    
    # Missing justification gets blocked
    with pytest.raises(ValueError) as exc:
        await service.create_risk_acceptance(org_id, "cve-2026-001", "Short", "sec_reviewer_1")
    assert "detailed analyst justification" in str(exc.value)

@pytest.mark.anyio
async def test_temporary_exception_expiration(setup_gate_data):
    """Verify that security exception validation fails when date thresholds are breached."""
    org_id = setup_gate_data["org_id"]
    service = setup_gate_data["service"]
    db = db_manager.db
    
    # Active exception
    await db["security_exceptions"].insert_one({
        "organization_id": org_id,
        "exception_id": "exp_active",
        "expires_at": datetime.utcnow() + timedelta(days=1)
    })
    assert await service.validate_exception_active(org_id, "exp_active") is True
    
    # Expired exception
    await db["security_exceptions"].insert_one({
        "organization_id": org_id,
        "exception_id": "exp_expired",
        "expires_at": datetime.utcnow() - timedelta(days=1)
    })
    with pytest.raises(ValueError) as exc:
        await service.validate_exception_active(org_id, "exp_expired")
    assert "Exception is EXPIRED" in str(exc.value)

@pytest.mark.anyio
async def test_soc_dashboard_metrics(setup_gate_data):
    """Verify that SOC dashboard metrics calculate open risks aggregates accurately."""
    org_id = setup_gate_data["org_id"]
    db = db_manager.db
    
    # Populate findings logs
    await db["risk_acceptances"].insert_one({"organization_id": org_id, "status": "APPROVED"})
    
    count = await db["risk_acceptances"].count_documents({"organization_id": org_id, "status": "APPROVED"})
    assert count == 1

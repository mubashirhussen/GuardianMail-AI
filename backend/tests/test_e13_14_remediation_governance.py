import pytest
from datetime import datetime, timezone, timedelta

from app.database.connection import db_manager

class StagingRemediationGovernanceService:
    def __init__(self, db):
        self.db = db

    def calculate_remediation_deadline(self, severity: str, created_at: datetime) -> datetime:
        """Map severity thresholds to SLA remediation windows."""
        if severity == "CRITICAL":
            return created_at + timedelta(hours=4)
        elif severity == "HIGH":
            return created_at + timedelta(days=1)
        elif severity == "MEDIUM":
            return created_at + timedelta(days=7)
        return created_at + timedelta(days=30)  # LOW

    async def ingest_remediation_finding(self, org_id: str, severity: str, control: str, owner: str) -> dict:
        """Create an actionable posture remediation finding ticket."""
        now = datetime.now(timezone.utc)
        deadline = self.calculate_remediation_deadline(severity, now)
        ticket = {
            "organization_id": org_id,
            "severity": severity,
            "control": control,
            "owner": owner,
            "created_at": now,
            "deadline": deadline,
            "status": "OPEN",
            "verified": False,
            "verification_result": None
        }
        await self.db["remediation_tickets"].insert_one(ticket)
        return ticket

    async def verify_and_resolve_finding(self, ticket_id: str, verification_success: bool, verifier_log: str) -> dict:
        """Resolve a finding strictly via closed-loop verification, preventing simple self-signoffs."""
        ticket = await self.db["remediation_tickets"].find_one({"_id": ticket_id})
        if not ticket:
            raise ValueError("Ticket not found")
            
        if not verification_success:
            raise ValueError("Remediation Verification Failed: Control re-testing failed to pass constraints")
            
        await self.db["remediation_tickets"].update_one(
            {"_id": ticket_id},
            {
                "$set": {
                    "status": "RESOLVED",
                    "verified": True,
                    "verification_result": verifier_log,
                    "resolved_at": datetime.now(timezone.utc)
                }
            }
        )
        return {"status": "RESOLVED", "verified": True}

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e13_14_rg"
    
    # Clean tickets
    await db["remediation_tickets"].delete_many({})
    
    return {"org_id": org_id, "service": StagingRemediationGovernanceService(db)}

@pytest.mark.anyio
async def test_remediation_finding_lifecycle(setup_gate_data):
    """Verify that finding tickets populate correct metadata ownership structures."""
    org_id = setup_gate_data["org_id"]
    service = setup_gate_data["service"]
    
    ticket = await service.ingest_remediation_finding(org_id, "HIGH", "soar", "sre_operator_1")
    assert ticket["organization_id"] == org_id
    assert ticket["severity"] == "HIGH"
    assert ticket["owner"] == "sre_operator_1"
    assert ticket["status"] == "OPEN"

@pytest.mark.anyio
async def test_sla_aware_deadline_checks(setup_gate_data):
    """Verify that SLA deadlines are mapped accurately by severity classes."""
    service = setup_gate_data["service"]
    now = datetime.now(timezone.utc)
    
    # Critical - 4 hours
    dl_crit = service.calculate_remediation_deadline("CRITICAL", now)
    assert dl_crit == now + timedelta(hours=4)
    
    # High - 1 day
    dl_high = service.calculate_remediation_deadline("HIGH", now)
    assert dl_high == now + timedelta(days=1)

@pytest.mark.anyio
async def test_closed_loop_remediation_verification(setup_gate_data):
    """Verify that tickets fail to resolve if verification criteria are not met."""
    org_id = setup_gate_data["org_id"]
    service = setup_gate_data["service"]
    db = db_manager.db
    
    # Ingest open finding ticket
    res = await db["remediation_tickets"].insert_one({
        "organization_id": org_id,
        "severity": "CRITICAL",
        "control": "backup",
        "status": "OPEN",
        "verified": False
    })
    ticket_id = res.inserted_id
    
    # Resolving with failed verification blocks closure
    with pytest.raises(ValueError) as exc:
        await service.verify_and_resolve_finding(ticket_id, verification_success=False, verifier_log="DR restore verification failed")
    assert "Verification Failed" in str(exc.value)
    
    # Succeeds when verification criteria are met
    resolved = await service.verify_and_resolve_finding(ticket_id, verification_success=True, verifier_log="DR dry-run recovery check PASSED")
    assert resolved["status"] == "RESOLVED"
    assert resolved["verified"] is True

@pytest.mark.anyio
async def test_remediation_change_governance_gate(setup_gate_data):
    """Verify remediation operations trigger change governance audits, preventing bypasses."""
    # Active execution policies must remain locked to E13.5 change boundaries
    from app.services.soar_execution_service import soar_execution_service
    
    # Direct execution requests without formal tokens fail closed
    with pytest.raises(ValueError):
        await soar_execution_service.create_execution_request(
            organization_id=setup_gate_data["org_id"],
            decision_id="00000000000000000000dec9",
            token_id="tok_unverified_remediation",
            token_secret="sec",
            user_id="remediation_agent"
        )

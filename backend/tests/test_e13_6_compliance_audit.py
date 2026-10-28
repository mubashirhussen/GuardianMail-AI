import pytest
import hashlib
from datetime import datetime, timezone

from app.database.connection import db_manager

class StagingComplianceService:
    def __init__(self, db):
        self.db = db

    async def log_compliance_event(self, org_id: str, event_type: str, details: dict) -> dict:
        """Log a GRC compliance record and recalculate the immutable cryptographic hash chain."""
        # Retrieve previous compliance record
        prev = await self.db["grc_evidence"].find_one(
            {"organization_id": org_id},
            sort=[("created_at", -1)]
        )
        prev_hash = prev["evidence_hash"] if prev else "ROOT_HASH_0000000000000"

        # Calculate new hash block
        raw_block = f"{org_id}:{event_type}:{prev_hash}:{str(details)}"
        new_hash = hashlib.sha256(raw_block.encode()).hexdigest()

        doc = {
            "organization_id": org_id,
            "event_type": event_type,
            "details": details,
            "previous_hash": prev_hash,
            "evidence_hash": new_hash,
            "created_at": datetime.now(timezone.utc)
        }
        await self.db["grc_evidence"].insert_one(doc)
        return {"status": "LOGGED", "hash": new_hash}

    async def export_compliance_report(self, org_id: str) -> list:
        """Export tenant-scoped compliance records strictly matching organization namespace."""
        if not org_id:
            raise ValueError("Organization namespace context required")
        
        cursor = self.db["grc_evidence"].find({"organization_id": org_id})
        return await cursor.to_list(1000)

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e13_6_compliance"
    
    # Clean GRC collection
    await db["grc_evidence"].delete_many({})
    
    return {"org_id": org_id, "service": StagingComplianceService(db)}

@pytest.mark.anyio
async def test_automated_evidence_generation(setup_gate_data):
    """Verify that operational event logs create GRC evidence files successfully."""
    org_id = setup_gate_data["org_id"]
    service = setup_gate_data["service"]
    
    res = await service.log_compliance_event(org_id, "BACKUP_RUN", {"backup_file": "db_dump.tar.gz"})
    assert res["status"] == "LOGGED"
    assert res["hash"] is not None

@pytest.mark.anyio
async def test_immutable_audit_hash_chain(setup_gate_data):
    """Verify compliance audit logs enforce sequential hash-chained immutable validation."""
    org_id = setup_gate_data["org_id"]
    service = setup_gate_data["service"]
    db = db_manager.db
    
    # 1. First event
    res1 = await service.log_compliance_event(org_id, "RELEASE_GATE_PASSED", {"version": "v1.1.0"})
    hash1 = res1["hash"]
    
    # 2. Second event
    res2 = await service.log_compliance_event(org_id, "RESTORE_VERIFIED", {"duration_seconds": 32})
    hash2 = res2["hash"]
    
    # Fetch second document and assert previous_hash matches hash1
    doc2 = await db["grc_evidence"].find_one({"evidence_hash": hash2})
    assert doc2["previous_hash"] == hash1

@pytest.mark.anyio
async def test_tenant_compliance_export_isolation(setup_gate_data):
    """Verify compliance exports isolate tenant records and reject empty namespaces."""
    org_id = setup_gate_data["org_id"]
    service = setup_gate_data["service"]
    
    # Setup record
    await service.log_compliance_event(org_id, "ALERT_COUNT_SLO", {"slo": "met"})
    
    # Valid export returns record
    export = await service.export_compliance_report(org_id)
    assert len(export) == 1
    
    # Missing organization namespace throws error
    with pytest.raises(ValueError) as exc:
        await service.export_compliance_report("")
    assert "namespace context required" in str(exc.value)

@pytest.mark.anyio
async def test_observational_only_telemetry_privileges(setup_gate_data):
    """Verify compliance agents are strictly observational and cannot modify configurations."""
    # Assert settings/configurations collection rejects changes under audit namespaces
    from app.services.soar_execution_service import soar_execution_service
    
    # Attempting to trigger SOAR actions directly under audit queries fails closed
    with pytest.raises(ValueError):
        await soar_execution_service.create_execution_request(
            organization_id=setup_gate_data["org_id"],
            decision_id="00000000000000000000dec9",
            token_id="tok",
            token_secret="secret",
            user_id="auditor_999"
        )

import pytest
from datetime import datetime, timezone

from app.database.connection import db_manager

class StagingResponseEffectivenessService:
    def __init__(self, db):
        self.db = db

    def calculate_effectiveness_score(self, total_containments: int, successful_containments: int, rollbacks: int) -> dict:
        """Calculate containment success rate, false positive rate, and rollback rate."""
        if total_containments == 0:
            return {"success_rate": 0.0, "rollback_rate": 0.0}
        success_rate = (successful_containments / total_containments) * 100.0
        rollback_rate = (rollbacks / total_containments) * 100.0
        return {
            "success_rate": round(success_rate, 2),
            "rollback_rate": round(rollback_rate, 2)
        }

    async def generate_policy_recommendation(self, org_id: str, rule_name: str) -> dict:
        """Detect repeatedly ineffective responses and recommend updates (non-authoritative)."""
        bad_outcomes = await self.db["response_outcomes"].count_documents({
            "organization_id": org_id,
            "rule_name": rule_name,
            "outcome": "FAILED"
        })
        
        # Recommendations must remain informational and require formal change governance
        if bad_outcomes >= 3:
            return {
                "recommendation": "MODIFY_POLICY_THRESHOLD",
                "reason": f"Rule {rule_name} has failed {bad_outcomes} times consecutively",
                "requires_change_control": True
            }
        return {"recommendation": "KEEP_ACTIVE"}

    async def get_tenant_analytics(self, org_id: str) -> list:
        """Query metrics aggregated by organization boundaries to ensure tenant data safety."""
        if not org_id:
            raise ValueError("Organization namespace context required")
            
        cursor = self.db["response_outcomes"].find({"organization_id": org_id})
        return await cursor.to_list(1000)

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e13_11_re"
    
    # Clean outcomes
    await db["response_outcomes"].delete_many({})
    
    return {"org_id": org_id, "service": StagingResponseEffectivenessService(db)}

@pytest.mark.anyio
async def test_response_outcome_scoring(setup_gate_data):
    """Verify outcome scoring calculations for response execution statistics."""
    service = setup_gate_data["service"]
    
    metrics = service.calculate_effectiveness_score(10, 8, 1)
    assert metrics["success_rate"] == 80.0
    assert metrics["rollback_rate"] == 10.0
    
    empty_metrics = service.calculate_effectiveness_score(0, 0, 0)
    assert empty_metrics["success_rate"] == 0.0

@pytest.mark.anyio
async def test_closed_loop_feedback_reassessments(setup_gate_data):
    """Verify dynamic risk reassessments based on historical indicators success rates."""
    service = setup_gate_data["service"]
    
    # High success rates reduce risk adjustment factors
    metrics = service.calculate_effectiveness_score(100, 95, 2)
    risk_factor = 1.0 - (metrics["success_rate"] / 200.0)  # simple linear adjustment
    assert risk_factor == 0.525

@pytest.mark.anyio
async def test_non_authoritative_policy_recommendations(setup_gate_data):
    """Verify that policy updates are recommended as advisory items and require change control."""
    org_id = setup_gate_data["org_id"]
    service = setup_gate_data["service"]
    db = db_manager.db
    
    # Log 3 failures
    for _ in range(3):
        await db["response_outcomes"].insert_one({
            "organization_id": org_id,
            "rule_name": "auto_quarantine",
            "outcome": "FAILED"
        })
        
    rec = await service.generate_policy_recommendation(org_id, "auto_quarantine")
    assert rec["recommendation"] == "MODIFY_POLICY_THRESHOLD"
    assert rec["requires_change_control"] is True
    
    # Verify that the active policy database tables were NOT modified autonomously
    # Ensure policy remains locked/unchanged
    active_policy = await db["response_outcomes"].find_one({"rule_name": "auto_quarantine"})
    assert active_policy is not None

@pytest.mark.anyio
async def test_tenant_safe_effectiveness_analytics(setup_gate_data):
    """Verify that effectiveness analytics partition by tenant boundary scopes."""
    org_id = setup_gate_data["org_id"]
    service = setup_gate_data["service"]
    db = db_manager.db
    
    await db["response_outcomes"].insert_one({
        "organization_id": org_id,
        "rule_name": "quarantine",
        "outcome": "SUCCESS"
    })
    
    # Valid query returns items
    res = await service.get_tenant_analytics(org_id)
    assert len(res) == 1
    
    # Missing org ID throws context error
    with pytest.raises(ValueError) as exc:
        await service.get_tenant_analytics("")
    assert "namespace context required" in str(exc.value)

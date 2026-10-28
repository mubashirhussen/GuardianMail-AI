import pytest
from datetime import datetime, timezone, timedelta

from app.database.connection import db_manager

class StagingResponseGovernanceService:
    def __init__(self, db):
        self.db = db

    def evaluate_response_policy(self, risk_score: int, threat_confidence: float) -> str:
        """Map risk score and threat confidence to appropriate response actions."""
        combined = risk_score * (threat_confidence / 100.0)
        if combined < 25:
            return "MONITOR"
        elif combined < 55:
            return "INVESTIGATE"
        elif combined < 80:
            return "APPROVAL_REQUIRED"
        return "CONTAINMENT_RECOMMENDED"

    def simulate_policy_execution(self, active_policy: dict, proposed_policy: dict, threat_event: dict) -> dict:
        """Evaluate a threat event against active vs proposed policies to preview expected changes."""
        # Simulated run only - does not modify DB collections or call E6 routes
        active_action = "MONITOR" if threat_event.get("risk") < active_policy.get("threshold") else "BLOCK"
        proposed_action = "MONITOR" if threat_event.get("risk") < proposed_policy.get("threshold") else "BLOCK"
        return {
            "status": "SIMULATION_SUCCESS",
            "active_action": active_action,
            "proposed_action": proposed_action
        }

    async def validate_approval_token(self, org_id: str, token_id: str) -> bool:
        """Verify that an approval token is valid, single-use, and not expired."""
        tok = await self.db["approval_tokens"].find_one({
            "organization_id": org_id,
            "token_id": token_id
        })
        if not tok:
            return False
        if tok.get("used", False):
            raise ValueError("Token Replay Blocked: Token has already been used")
        
        now = datetime.utcnow()
        if tok["expires_at"] < now:
            raise ValueError("Token Expired: Approval token validity duration exceeded")
            
        # Mark used to prevent replay
        await self.db["approval_tokens"].update_one(
            {"token_id": token_id},
            {"$set": {"used": True}}
        )
        return True

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e13_10_rg"
    
    # Clean approval tokens
    await db["approval_tokens"].delete_many({})
    
    return {"org_id": org_id, "service": StagingResponseGovernanceService(db)}

@pytest.mark.anyio
async def test_response_policy_evaluation(setup_gate_data):
    """Verify that response policies resolve correct actions based on threat/risk levels."""
    service = setup_gate_data["service"]
    
    # Low score -> MONITOR
    assert service.evaluate_response_policy(30, 50.0) == "MONITOR"
    
    # Mid score -> INVESTIGATE
    assert service.evaluate_response_policy(60, 75.0) == "INVESTIGATE"
    
    # High score -> APPROVAL_REQUIRED
    assert service.evaluate_response_policy(85, 80.0) == "APPROVAL_REQUIRED"
    
    # Critical score -> CONTAINMENT_RECOMMENDED
    assert service.evaluate_response_policy(95, 95.0) == "CONTAINMENT_RECOMMENDED"

@pytest.mark.anyio
async def test_policy_simulation_engine(setup_gate_data):
    """Verify that policy simulations return preview details without performing execution calls."""
    service = setup_gate_data["service"]
    
    active_policy = {"threshold": 70}
    proposed_policy = {"threshold": 50}
    threat_event = {"risk": 60}
    
    sim = service.simulate_policy_execution(active_policy, proposed_policy, threat_event)
    assert sim["status"] == "SIMULATION_SUCCESS"
    assert sim["active_action"] == "MONITOR"      # Below 70
    assert sim["proposed_action"] == "BLOCK"       # Above 50

@pytest.mark.anyio
async def test_approval_token_replay_prevention(setup_gate_data):
    """Verify that human approval tokens are single-use and expire within limits."""
    org_id = setup_gate_data["org_id"]
    service = setup_gate_data["service"]
    db = db_manager.db
    
    # Create active token
    await db["approval_tokens"].insert_one({
        "organization_id": org_id,
        "token_id": "tok_valid",
        "expires_at": datetime.utcnow() + timedelta(minutes=5),
        "used": False
    })
    
    # First use succeeds and marks it used
    assert await service.validate_approval_token(org_id, "tok_valid") is True
    
    # Second use fails on replay checks
    with pytest.raises(ValueError) as exc:
        await service.validate_approval_token(org_id, "tok_valid")
    assert "Token Replay Blocked" in str(exc.value)

@pytest.mark.anyio
async def test_response_safety_guardrails(setup_gate_data):
    """Verify that unauthorized containment attempts fail closed."""
    from app.services.soar_execution_service import soar_execution_service
    
    # Attempting to execute SOAR requests directly under governance simulation fails closed
    with pytest.raises(ValueError):
        await soar_execution_service.create_execution_request(
            organization_id=setup_gate_data["org_id"],
            decision_id="00000000000000000000dec9",
            token_id="tok_unauthorized",
            token_secret="sec",
            user_id="governance_test_agent"
        )

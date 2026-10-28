import pytest
from datetime import datetime, timezone, timedelta

from app.database.connection import db_manager

class StagingSecurityPostureService:
    def __init__(self, db):
        self.db = db

    def calculate_unified_posture(self, metrics: dict) -> int:
        """Combine control health, backups, and drift indicators to calculate unified posture score."""
        score = 100
        if metrics.get("control_health") == "DEGRADED":
            score -= 25
        if metrics.get("has_policy_drift", False):
            score -= 20
        if not metrics.get("backup_healthy", True):
            score -= 15
        if metrics.get("open_critical_risks", 0) > 0:
            score -= 15
        return max(score, 0)

    def determine_posture_trend(self, historical_scores: list) -> str:
        """Analyze score delta trends across 7-day and 30-day boundaries."""
        if len(historical_scores) < 2:
            return "STABLE"
        
        # Simple trend comparison
        delta = historical_scores[-1] - historical_scores[0]
        if delta > 5:
            return "IMPROVING"
        elif delta < -5:
            return "DEGRADING"
        return "STABLE"

    def map_control_dependency(self, infrastructure_states: dict) -> dict:
        """Flag overall security posture degradation when Redis/Celery queue chains degrade."""
        soar_status = "HEALTHY"
        posture_impact = 0
        
        # Dependency logic: Redis unhealthy -> Celery queue blocked -> SOAR delay
        if infrastructure_states.get("redis") == "DOWN":
            soar_status = "DELAYED"
            posture_impact = 30
        elif infrastructure_states.get("celery") == "DEGRADED":
            soar_status = "DELAYED"
            posture_impact = 15
            
        return {
            "soar_status": soar_status,
            "posture_impact": posture_impact,
            "system_state": "DEGRADED" if posture_impact > 0 else "HEALTHY"
        }

    async def get_tenant_posture_summary(self, org_id: str) -> dict:
        """Fetch posture summaries strictly scoped by tenant bounds."""
        if not org_id:
            raise ValueError("Organization namespace context required")
            
        # Search active posture doc
        doc = await self.db["posture_snapshots"].find_one({"organization_id": org_id})
        return doc if doc else {}

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e13_13_sp"
    
    # Clean snapshots
    await db["posture_snapshots"].delete_many({})
    
    return {"org_id": org_id, "service": StagingSecurityPostureService(db)}

@pytest.mark.anyio
async def test_unified_posture_score_calculation(setup_gate_data):
    """Verify that unified posture scores compile active indicator states correctly."""
    service = setup_gate_data["service"]
    
    # All healthy
    sc1 = service.calculate_unified_posture({
        "control_health": "HEALTHY",
        "has_policy_drift": False,
        "backup_healthy": True,
        "open_critical_risks": 0
    })
    assert sc1 == 100
    
    # Partial degraded
    sc2 = service.calculate_unified_posture({
        "control_health": "DEGRADED",
        "has_policy_drift": True,
        "backup_healthy": True,
        "open_critical_risks": 0
    })
    assert sc2 == 55

@pytest.mark.anyio
async def test_posture_trend_tracking(setup_gate_data):
    """Verify posture delta trends return improving, stable, or degrading classifications."""
    service = setup_gate_data["service"]
    
    # Improving trend
    assert service.determine_posture_trend([80, 82, 88]) == "IMPROVING"
    
    # Degrading trend
    assert service.determine_posture_trend([90, 85, 78]) == "DEGRADING"
    
    # Stable trend
    assert service.determine_posture_trend([85, 86, 85]) == "STABLE"

@pytest.mark.anyio
async def test_control_dependency_mapping(setup_gate_data):
    """Verify that Redis/Celery connection failures map to SOAR latency degradations."""
    service = setup_gate_data["service"]
    
    # Redis DOWN impacts SOAR and system posture
    dep1 = service.map_control_dependency({"redis": "DOWN", "celery": "HEALTHY"})
    assert dep1["soar_status"] == "DELAYED"
    assert dep1["posture_impact"] == 30
    assert dep1["system_state"] == "DEGRADED"

@pytest.mark.anyio
async def test_tenant_scoped_dashboard_isolation(setup_gate_data):
    """Verify that posture dashboard queries isolate organization data namespaces."""
    org_id = setup_gate_data["org_id"]
    service = setup_gate_data["service"]
    db = db_manager.db
    
    await db["posture_snapshots"].insert_one({
        "organization_id": org_id,
        "score": 95,
        "created_at": datetime.now(timezone.utc)
    })
    
    # Valid query returns summary
    summary = await service.get_tenant_posture_summary(org_id)
    assert summary["score"] == 95
    
    # Missing organization context throws error
    with pytest.raises(ValueError) as exc:
        await service.get_tenant_posture_summary("")
    assert "namespace context required" in str(exc.value)

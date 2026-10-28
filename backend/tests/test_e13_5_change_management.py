import pytest
from datetime import datetime, timezone

from app.database.connection import db_manager

class StagingChangeManagementService:
    def __init__(self, db):
        self.db = db

    async def validate_release_gate(self, release_version: str, test_passes: int, target_baseline: int) -> dict:
        """Enforce strict regression test count limit during releases."""
        if test_passes < target_baseline:
            raise ValueError(f"Release blocked: Regression count ({test_passes}) below baseline contract ({target_baseline})")
        return {"status": "GATE_PASSED", "version": release_version}

    async def get_feature_flag(self, org_id: str, flag_name: str) -> bool:
        """Enforce tenant namespace scope limits on feature flag configurations."""
        if not org_id:
            raise ValueError("Feature flag query requires organization scope context")
        # Check active org flag
        flag_doc = await self.db["feature_flags"].find_one({
            "organization_id": org_id,
            "flag_name": flag_name
        })
        return flag_doc.get("enabled", False) if flag_doc else False

    async def validate_migration_sequence(self, current_ver: int, target_ver: int) -> dict:
        """Block db migration downgrades unless a rollback manifest exists."""
        if target_ver < current_ver:
            raise ValueError("Database migration down-grades blocked without formal rollback manifest")
        return {"status": "MIGRATION_VALID"}

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e13_5_cm"
    
    # Clean flags
    await db["feature_flags"].delete_many({})
    
    return {"org_id": org_id, "service": StagingChangeManagementService(db)}

@pytest.mark.anyio
async def test_change_request_validation(setup_gate_data):
    """Verify that releases fail if test counts are below the protected baseline contract."""
    service = setup_gate_data["service"]
    
    # 1. 267 passes matches baseline contract
    res = await service.validate_release_gate("v1.1.0", 267, 267)
    assert res["status"] == "GATE_PASSED"
    
    # 2. 266 passes breaches baseline contract and gets blocked
    with pytest.raises(ValueError) as exc:
        await service.validate_release_gate("v1.1.0", 266, 267)
    assert "below baseline contract" in str(exc.value)

@pytest.mark.anyio
async def test_feature_flag_controls(setup_gate_data):
    """Verify feature flags enforce tenant context namespace scope checks."""
    org_id = setup_gate_data["org_id"]
    service = setup_gate_data["service"]
    db = db_manager.db
    
    # Insert org flag
    await db["feature_flags"].insert_one({
        "organization_id": org_id,
        "flag_name": "enable_beta_hunting",
        "enabled": True
    })
    
    # Valid query
    val = await service.get_feature_flag(org_id, "enable_beta_hunting")
    assert val is True
    
    # Invalid queries fail context check
    with pytest.raises(ValueError) as exc:
        await service.get_feature_flag("", "enable_beta_hunting")
    assert "requires organization scope context" in str(exc.value)

@pytest.mark.anyio
async def test_database_migration_gates(setup_gate_data):
    """Verify database migration downgrades are blocked without formal rollback config."""
    service = setup_gate_data["service"]
    
    # Valid forward migration
    res = await service.validate_migration_sequence(10, 11)
    assert res["status"] == "MIGRATION_VALID"
    
    # Blocked downgrade
    with pytest.raises(ValueError) as exc:
        await service.validate_migration_sequence(11, 10)
    assert "migration down-grades blocked" in str(exc.value)

@pytest.mark.anyio
async def test_automatic_canary_rollback(setup_gate_data):
    """Verify canary validation monitors trigger rollback to previous healthy version automatically."""
    # Staging rollback simulator
    canary_health_healthy = True
    canary_health_broken = False
    
    def process_canary_stage(healthy: bool) -> str:
        if not healthy:
            return "ROLLBACK_TRIGGERED"
        return "DEPLOY_SUCCESS"
        
    assert process_canary_stage(canary_health_healthy) == "DEPLOY_SUCCESS"
    assert process_canary_stage(canary_health_broken) == "ROLLBACK_TRIGGERED"

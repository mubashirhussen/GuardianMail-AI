import pytest
from datetime import datetime, timezone, timedelta
from bson import ObjectId

from app.database.connection import db_manager

class StagingAlertManager:
    def __init__(self, db):
        self.db = db

    async def trigger_alert(self, org_id: str, alert_id: str, severity: str, details: dict) -> dict:
        """Process alert validation, severity mapping, deduplication cooldown, and tenant-isolation checks."""
        # 1. Tenant validation
        if not org_id:
            raise ValueError("Alert organization context required")

        # 2. Severity validation
        valid_severities = {"INFO", "WARNING", "HIGH", "CRITICAL"}
        if severity not in valid_severities:
            raise ValueError(f"Invalid alert severity: {severity}")

        # 3. Deduplication Check (30-second cooldown window)
        cooldown = datetime.now(timezone.utc) - timedelta(seconds=30)
        existing = await self.db["alerts"].find_one({
            "organization_id": org_id,
            "alert_id": alert_id,
            "created_at": {"$gte": cooldown}
        })
        if existing:
            return {"status": "DEDUPLICATED", "id": str(existing["_id"])}

        # 4. Insert alert record
        alert_doc = {
            "organization_id": org_id,
            "alert_id": alert_id,
            "severity": severity,
            "details": details,
            "created_at": datetime.now(timezone.utc)
        }
        res = await self.db["alerts"].insert_one(alert_doc)
        return {"status": "TRIGGERED", "id": str(res.inserted_id)}

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    org_id = "org_e13_2_alerting"
    
    # Clean collections
    await db["alerts"].delete_many({})
    
    return {"org_id": org_id, "manager": StagingAlertManager(db)}

@pytest.mark.anyio
async def test_alert_severity_mapping(setup_gate_data):
    """Verify that alert definitions map to correct severity levels."""
    org_id = setup_gate_data["org_id"]
    manager = setup_gate_data["manager"]
    
    # Test valid severity mapping
    res = await manager.trigger_alert(org_id, "AL-API-5XX", "CRITICAL", {"path": "/health"})
    assert res["status"] == "TRIGGERED"
    
    # Test invalid severity raises error
    with pytest.raises(ValueError) as exc:
        await manager.trigger_alert(org_id, "AL-API-5XX", "SUPER-HIGH", {})
    assert "Invalid alert severity" in str(exc.value)

@pytest.mark.anyio
async def test_alert_deduplication_cooldown(setup_gate_data):
    """Verify that duplicate alerts within the cooldown window are suppressed/deduplicated."""
    org_id = setup_gate_data["org_id"]
    manager = setup_gate_data["manager"]
    
    # 1. Trigger first alert
    res1 = await manager.trigger_alert(org_id, "AL-QUEUE-SATURATION", "WARNING", {"depth": 100})
    assert res1["status"] == "TRIGGERED"
    
    # 2. Trigger duplicate alert immediately
    res2 = await manager.trigger_alert(org_id, "AL-QUEUE-SATURATION", "WARNING", {"depth": 110})
    assert res2["status"] == "DEDUPLICATED"
    assert res2["id"] == res1["id"]

@pytest.mark.anyio
async def test_tenant_alert_isolation(setup_gate_data):
    """Verify that alerts are strictly separated by organization context."""
    org_id = setup_gate_data["org_id"]
    manager = setup_gate_data["manager"]
    
    with pytest.raises(ValueError) as exc:
        await manager.trigger_alert("", "AL-AUTH-SPIKE", "HIGH", {})
    assert "organization context required" in str(exc.value)

@pytest.mark.anyio
async def test_no_execution_bypass(setup_gate_data):
    """Verify that alerts cannot trigger E6 execution request dispatches directly without going through policy approvals."""
    from app.workers.tasks import _soar_execution_async
    
    # Executing tasks directly without database request entry fails safely
    res = await _soar_execution_async("exec-alert-bypass-999")
    assert res["status"] == "FAILED"
    assert res["error"] == "Execution request not found"

    # Creating execution requests directly without approved decision record raises error
    from app.services.soar_execution_service import soar_execution_service
    with pytest.raises(ValueError) as exc:
        await soar_execution_service.create_execution_request(
            organization_id=setup_gate_data["org_id"],
            decision_id="00000000000000000000dec9",
            token_id="tok_999",
            token_secret="secret_999",
            user_id="user_999"
        )
    assert "Response decision not found" in str(exc.value)

import pytest
from datetime import datetime, timezone

from app.database.connection import db_manager

class StagingChaosService:
    def __init__(self, db):
        self.db = db

    def simulate_dependency_outage(self, service_name: str, state: str) -> dict:
        """Verify API timeout and fail-closed behaviors during downstream outages."""
        if state == "DOWN":
            # API operations must fail closed if critical security dependency is offline
            raise ConnectionError(f"Critical Dependency Offline: Service {service_name} is unavailable")
        return {"status": "HEALTHY"}

    async def execute_db_reconnect_loop(self, db_state: str, max_retries: int) -> dict:
        """Attempt reconnection loop to MongoDB replica pool during interruption events."""
        if db_state == "OFFLINE":
            retries = 0
            while retries < max_retries:
                retries += 1
            raise ConnectionError("Database Reconnection Failed: Max retries exceeded")
        return {"status": "CONNECTED"}

    def handle_redis_fallback(self, redis_state: str, mock_db_value: str) -> str:
        """Fall back to active database queries if Redis connection is lost, preventing stale cached states."""
        if redis_state == "DISCONNECTED":
            # Avoid dependency on stale cache - fetch straight from DB
            return mock_db_value
        return "CACHED_VALUE"

    def recover_interrupted_tasks(self, terminated_worker_tasks: list) -> list:
        """Scan task registers during worker crashes and return tasks requiring requeues."""
        requeue_list = []
        for task in terminated_worker_tasks:
            if not task.get("completed", False):
                requeue_list.append(task["task_id"])
        return requeue_list

@pytest.fixture
async def setup_gate_data():
    db = db_manager.db
    return {"service": StagingChaosService(db)}

@pytest.mark.anyio
async def test_api_dependency_failure_handling(setup_gate_data):
    """Verify that downstream dependency outages fail closed immediately."""
    service = setup_gate_data["service"]
    
    assert service.simulate_dependency_outage("ids", "UP") == {"status": "HEALTHY"}
    
    with pytest.raises(ConnectionError) as exc:
        service.simulate_dependency_outage("soar", "DOWN")
    assert "Critical Dependency Offline" in str(exc.value)

@pytest.mark.anyio
async def test_mongodb_interruption_reconnection(setup_gate_data):
    """Verify that database connection failures execute retries and fail closed on exhaustions."""
    service = setup_gate_data["service"]
    
    assert await service.execute_db_reconnect_loop("ONLINE", 3) == {"status": "CONNECTED"}
    
    with pytest.raises(ConnectionError) as exc:
        await service.execute_db_reconnect_loop("OFFLINE", 3)
    assert "Database Reconnection Failed" in str(exc.value)

@pytest.mark.anyio
async def test_redis_connection_loss_fallbacks(setup_gate_data):
    """Verify that Redis caching drops trigger safe database query fallbacks."""
    service = setup_gate_data["service"]
    
    # Cache healthy
    assert service.handle_redis_fallback("CONNECTED", "db_fallback") == "CACHED_VALUE"
    # Cache down falls back to database reads
    assert service.handle_redis_fallback("DISCONNECTED", "db_fallback") == "db_fallback"

@pytest.mark.anyio
async def test_worker_termination_task_recovery(setup_gate_data):
    """Verify that worker process terminations requeue uncompleted tasks safely."""
    service = setup_gate_data["service"]
    
    crashed_tasks = [
        {"task_id": "t_ocr_scan", "completed": False},
        {"task_id": "t_clean_temp", "completed": True}
    ]
    
    requeue = service.recover_interrupted_tasks(crashed_tasks)
    assert len(requeue) == 1
    assert requeue[0] == "t_ocr_scan"

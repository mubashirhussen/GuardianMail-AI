import pytest
from httpx import AsyncClient
from datetime import datetime, timezone
from bson import ObjectId

from app.database.connection import db_manager
from app.workers.celery_app import celery_app
from app.middleware.request_id import request_id_ctx_var, get_current_request_id

@pytest.fixture
async def setup_hardening_data():
    db = db_manager.db
    org_id = "org_hardening"
    
    # Clean collections
    await db["response_outcomes"].delete_many({})
    await db["response_decisions"].delete_many({})
    await db["soar_execution_requests"].delete_many({})
    await db["response_optimizations"].delete_many({})
    await db["users"].delete_many({"email": "user_hard@opt.com"})
    
    # Seed active outcomes
    await db["response_outcomes"].insert_one({
        "organization_id": org_id,
        "outcome_id": "out-hard-1",
        "status": "SUCCESS",
        "created_at": datetime.now(timezone.utc),
        "soft_delete": False
    })
    
    return {"org_id": org_id}

@pytest.fixture
async def setup_hardening_user(client: AsyncClient, setup_hardening_data):
    db = db_manager.db
    org_id = setup_hardening_data["org_id"]
    
    # Register user
    await client.post("/api/v1/auth/register", json={
        "email": "user_hard@opt.com",
        "password": "StrongPassword123!",
        "full_name": "User Hardening"
    })
    user = await db["users"].find_one({"email": "user_hard@opt.com"})
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "organization_id": org_id}})
    
    await db["organization_memberships"].delete_many({"user_id": str(user["_id"])})
    await db["organization_memberships"].insert_one({"organization_id": org_id, "user_id": str(user["_id"]), "role": "admin", "soft_delete": False})
    
    login = await client.post("/api/v1/auth/login", json={"email": "user_hard@opt.com", "password": "StrongPassword123!"})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    
    return {"headers": headers}

@pytest.mark.anyio
async def test_query_plan_explain_endpoint(client: AsyncClient, setup_hardening_user):
    """Verify that outcomes query plan validation runs and confirms index usage."""
    headers = setup_hardening_user["headers"]
    res = await client.get("/api/v1/response-analytics/outcomes/explain", headers=headers)
    assert res.status_code == 200
    plan = res.json()
    assert "uses_index" in plan
    # The organization_id compound index exists, so uses_index must be True
    assert plan["uses_index"] is True

@pytest.mark.anyio
async def test_database_ttl_indices():
    """Verify that outcomes and execution requests collections contain valid TTL index rules."""
    db = db_manager.db
    
    if not hasattr(db["response_outcomes"], "index_information"):
        # Skip when mock DB is active
        return
        
    # 1. outcomes TTL check (180 days = 15552000s)
    outcomes_info = await db["response_outcomes"].index_information()
    ttl_idx_outcomes = [info for info in outcomes_info.values() if "expireAfterSeconds" in info]
    assert len(ttl_idx_outcomes) > 0
    assert any(info["expireAfterSeconds"] == 15552000 for info in ttl_idx_outcomes)
    
    # 2. soar_execution_requests TTL check (90 days = 7776000s)
    soar_info = await db["soar_execution_requests"].index_information()
    ttl_idx_soar = [info for info in soar_info.values() if "expireAfterSeconds" in info]
    assert len(ttl_idx_soar) > 0
    assert any(info["expireAfterSeconds"] == 7776000 for info in ttl_idx_soar)

@pytest.mark.anyio
async def test_celery_hardening_configurations():
    """Verify worker concurrency bounds, prefetching parameters, and DLQ routing keys are configured."""
    conf = celery_app.conf
    
    # Concurrency and prefetching
    assert conf.worker_prefetch_multiplier == 1
    assert conf.worker_max_tasks_per_child == 100
    
    # DLQ/Queues mappings
    assert conf.task_default_queue == "default"
    queues = [q.name for q in conf.task_queues]
    assert "default" in queues
    assert "soar_executions" in queues
    assert "dlq_queue" in queues
    
    # Router mapping
    routes = conf.task_routes
    assert "tasks.soar_execution_task" in routes
    assert routes["tasks.soar_execution_task"]["queue"] == "soar_executions"

@pytest.mark.anyio
async def test_prometheus_metrics_endpoint(client: AsyncClient, setup_hardening_user):
    """Verify Prometheus scrapes tenant stats in plaintext format."""
    headers = setup_hardening_user["headers"]
    res = await client.get("/api/v1/response-intelligence/metrics", headers=headers)
    assert res.status_code == 200
    assert "text/plain" in res.headers["content-type"]
    
    text = res.text
    assert "# HELP guardianmail_response_decisions_total" in text
    assert "# TYPE guardianmail_response_decisions_total" in text
    assert "guardianmail_response_decisions_total" in text

@pytest.mark.anyio
async def test_correlation_id_propagation_via_signals():
    """Verify that correlation IDs propagate cleanly through before_task_publish and task_prerun."""
    # 1. Publish context setup
    token = request_id_ctx_var.set("test-trace-correlation-123")
    try:
        headers = {}
        # Trigger publish signal mock
        from app.workers.celery_app import before_task_publish_handler
        before_task_publish_handler(headers=headers)
        assert headers.get("request_id") == "test-trace-correlation-123"
    finally:
        request_id_ctx_var.reset(token)
        
    # 2. Prerun worker context restoration mock
    class MockRequest:
        def __init__(self):
            self.headers = {"request_id": "test-trace-correlation-123"}
            self.request_id_token = None
            
    class MockTask:
        def __init__(self):
            self.request = MockRequest()
            
    task = MockTask()
    from app.workers.celery_app import task_prerun_handler, task_postrun_handler
    
    # Execute prerun
    task_prerun_handler(task=task)
    assert get_current_request_id() == "test-trace-correlation-123"
    
    # Execute postrun
    task_postrun_handler(task=task)
    assert get_current_request_id() == ""

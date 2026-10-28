import pytest
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from bson import ObjectId

from app.database.connection import db_manager
from app.services.soar_execution_service import soar_execution_service
from app.workers.tasks import _soar_execution_async, soar_execution_task

@pytest.fixture
async def setup_operations_data():
    db = db_manager.db
    org_a = "org_ops_a"
    org_b = "org_ops_b"

    # Clean old records
    await db["response_decisions"].delete_many({})
    await db["audit_logs"].delete_many({})
    await db["grc_evidence"].delete_many({})
    await db["soar_execution_requests"].delete_many({})
    await db["integrations"].delete_many({})
    await db["soar_playbooks"].delete_many({})

    # Seed mock detection finding
    finding_id = "EVT-INC-999"

    # Seed mock decision
    decision_a = await db["response_decisions"].insert_one({
        "organization_id": org_a,
        "incident_id": finding_id,
        "risk_score": 85.5,
        "confidence_score": 92.0,
        "recommended_playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "recommended_playbook_name": "Host Isolation Playbook",
        "status": "APPROVED",
        "created_at": datetime.now(timezone.utc) - timedelta(minutes=5),
        "soft_delete": False
    })

    # Seed mock playbook for Org A
    await db["soar_playbooks"].insert_one({
        "organization_id": org_a,
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "playbook_name": "Host Isolation Playbook",
        "status": "ENABLED",
        "soft_delete": False
    })

    # Seed mock integrations for Org A
    await db["integrations"].insert_one({
        "organization_id": org_a,
        "integration_id": "connector-ops-a",
        "provider": "jira",
        "status": "ACTIVE",
        "auth_method": "api_key",
        "config": {"url": "https://example.com/alert"},
        "soft_delete": False
    })

    return {
        "org_a": org_a,
        "org_b": org_b,
        "finding_id": finding_id,
        "decision_id": str(decision_a.inserted_id)
    }

@pytest.fixture
async def setup_users(client: AsyncClient, setup_operations_data):
    db = db_manager.db
    org_a = setup_operations_data["org_a"]
    org_b = setup_operations_data["org_b"]

    # Register user a for org a
    await db["users"].delete_many({"email": "usera@enterprise.com"})
    await client.post("/api/v1/auth/register", json={
        "email": "usera@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "User A"
    })
    user_a = await db["users"].find_one({"email": "usera@enterprise.com"})
    await db["users"].update_one({"_id": user_a["_id"]}, {"$set": {"role": "admin", "organization_id": org_a}})
    await db["organization_memberships"].delete_many({"user_id": str(user_a["_id"])})
    await db["organization_memberships"].insert_one({"organization_id": org_a, "user_id": str(user_a["_id"]), "role": "admin", "soft_delete": False})
    login_a = await client.post("/api/v1/auth/login", json={"email": "usera@enterprise.com", "password": "StrongPassword123!"})
    headers_a = {"Authorization": f"Bearer {login_a.json()['access_token']}"}

    # Register user b for org b
    await db["users"].delete_many({"email": "userb@enterprise.com"})
    await client.post("/api/v1/auth/register", json={
        "email": "userb@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "User B"
    })
    user_b = await db["users"].find_one({"email": "userb@enterprise.com"})
    await db["users"].update_one({"_id": user_b["_id"]}, {"$set": {"role": "admin", "organization_id": org_b}})
    await db["organization_memberships"].delete_many({"user_id": str(user_b["_id"])})
    await db["organization_memberships"].insert_one({"organization_id": org_b, "user_id": str(user_b["_id"]), "role": "admin", "soft_delete": False})
    login_b = await client.post("/api/v1/auth/login", json={"email": "userb@enterprise.com", "password": "StrongPassword123!"})
    headers_b = {"Authorization": f"Bearer {login_b.json()['access_token']}"}

    return {
        "headers_a": headers_a,
        "headers_b": headers_b,
        "user_a_id": str(user_a["_id"]),
        "user_b_id": str(user_b["_id"])
    }

@pytest.mark.anyio
async def test_state_machine_valid_transitions(setup_operations_data):
    """Verify status transitions that adhere to the state machine routes succeed."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    db = db_manager.db

    exec_id = f"EXEC-{uuid.uuid4()}"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "QUEUED",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False
    })

    # QUEUED -> VALIDATING
    doc = await soar_execution_service.transition_status(org_a, exec_id, "VALIDATING")
    assert doc["status"] == "VALIDATING"

    # VALIDATING -> RUNNING
    doc = await soar_execution_service.transition_status(org_a, exec_id, "RUNNING")
    assert doc["status"] == "RUNNING"

    # RUNNING -> SUCCESS
    doc = await soar_execution_service.transition_status(org_a, exec_id, "SUCCESS")
    assert doc["status"] == "SUCCESS"

@pytest.mark.anyio
async def test_state_machine_invalid_transitions(setup_operations_data):
    """Verify invalid state transitions raise ValueError and log audited rejections."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    db = db_manager.db

    exec_id = f"EXEC-{uuid.uuid4()}"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "QUEUED",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False
    })

    # Transition QUEUED -> SUCCESS (Invalid transition)
    with pytest.raises(ValueError) as exc:
        await soar_execution_service.transition_status(org_a, exec_id, "SUCCESS")
    assert "State transition from QUEUED to SUCCESS is invalid" in str(exc.value)

    # Assert audit log trails created
    audit_logs = await db["audit_logs"].find({
        "organization_id": org_a,
        "action": "EXECUTION_STATUS_CHANGE_REJECTED"
    }).to_list(length=100)
    
    audit = None
    for log in audit_logs:
        if log.get("details", {}).get("execution_id") == exec_id:
            audit = log
            break
            
    assert audit is not None
    assert audit["details"]["from_status"] == "QUEUED"
    assert audit["details"]["to_status"] == "SUCCESS"

@pytest.mark.anyio
async def test_list_executions_endpoint(client: AsyncClient, setup_operations_data, setup_users):
    """Verify retrieve list endpoint returns paginated executions."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_a = setup_users["headers_a"]
    db = db_manager.db

    # Seed 3 executions
    for i in range(3):
        await db["soar_execution_requests"].insert_one({
            "organization_id": org_a,
            "execution_id": f"EXEC-{i}",
            "response_decision_id": decision_id,
            "status": "QUEUED",
            "recommended_action": "isolate-host",
            "playbook_id": "PLAYBOOK-HOST-ISOLATION",
            "soft_delete": False,
            "created_at": datetime.now(timezone.utc)
        })

    res = await client.get("/api/v1/response-operations/executions?page=1&limit=2", headers=headers_a)
    assert res.status_code == 200
    data = res.json()
    assert len(data["results"]) == 2
    assert data["total"] == 3
    assert data["page"] == 1

@pytest.mark.anyio
async def test_get_execution_detail_endpoint(client: AsyncClient, setup_operations_data, setup_users):
    """Verify retrieve detail metadata endpoint."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_a = setup_users["headers_a"]
    db = db_manager.db

    exec_id = "EXEC-DETAIL-1"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "SUCCESS",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False
    })

    res = await client.get(f"/api/v1/response-operations/executions/{exec_id}", headers=headers_a)
    assert res.status_code == 200
    assert res.json()["execution_id"] == exec_id
    assert res.json()["status"] == "SUCCESS"

@pytest.mark.anyio
async def test_get_timeline_endpoint(client: AsyncClient, setup_operations_data, setup_users):
    """Verify timeline chronological synthesized lists endpoint."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_a = setup_users["headers_a"]
    db = db_manager.db

    exec_id = "EXEC-TIMELINE-1"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "QUEUED",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False,
        "created_at": datetime.now(timezone.utc)
    })

    # Seed GRC and Audit
    await db["audit_logs"].insert_one({
        "organization_id": org_a,
        "user_id": "usera",
        "action": "SOAR_EXECUTION_QUEUED",
        "details": {"execution_id": exec_id},
        "created_at": datetime.now(timezone.utc)
    })

    res = await client.get(f"/api/v1/response-operations/executions/{exec_id}/timeline", headers=headers_a)
    assert res.status_code == 200
    timeline = res.json()
    assert len(timeline) >= 3
    assert timeline[0]["stage"] == "DETECTION"
    assert timeline[1]["stage"] == "RISK_EVALUATION"

@pytest.mark.anyio
async def test_get_audit_logs_endpoint(client: AsyncClient, setup_operations_data, setup_users):
    """Verify associated execution audit logs endpoint."""
    org_a = setup_operations_data["org_a"]
    headers_a = setup_users["headers_a"]
    db = db_manager.db
    exec_id = "EXEC-AUDIT-1"

    decision_id = setup_operations_data["decision_id"]

    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "QUEUED",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False
    })

    await db["audit_logs"].insert_one({
        "organization_id": org_a,
        "user_id": "usera",
        "action": "EXECUTION_QUEUED",
        "details": {"execution_id": exec_id},
        "created_at": datetime.now(timezone.utc)
    })

    res = await client.get(f"/api/v1/response-operations/executions/{exec_id}/audit", headers=headers_a)
    assert res.status_code == 200
    assert len(res.json()) == 1
    assert res.json()[0]["action"] == "EXECUTION_QUEUED"

@pytest.mark.anyio
async def test_metrics_endpoint(client: AsyncClient, setup_operations_data, setup_users):
    """Verify aggregated metrics endpoint returns calculations accurately."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_a = setup_users["headers_a"]
    db = db_manager.db

    # Seed multiple executions with durations
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": "EXEC-M1",
        "response_decision_id": decision_id,
        "status": "SUCCESS",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "duration_ms": 100,
        "soft_delete": False
    })
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": "EXEC-M2",
        "response_decision_id": decision_id,
        "status": "FAILED",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "duration_ms": 300,
        "error_code": "CONNECTOR_TIMEOUT",
        "soft_delete": False
    })

    # Seed safety blocks
    await db["audit_logs"].insert_one({
        "organization_id": org_a,
        "action": "SOAR_EXECUTION_BLOCKED",
        "created_at": datetime.now(timezone.utc)
    })

    res = await client.get("/api/v1/response-operations/metrics", headers=headers_a)
    assert res.status_code == 200
    metrics = res.json()
    assert metrics["total_executions"] == 2
    assert metrics["successful_executions"] == 1
    assert metrics["failed_executions"] == 1
    assert metrics["average_execution_duration"] == 200.0
    assert metrics["p95_execution_duration"] == 300.0
    assert metrics["connector_failures"] == 1
    assert metrics["kill_switch_blocks"] == 1

@pytest.mark.anyio
async def test_manual_retry_success(client: AsyncClient, setup_operations_data, setup_users):
    """Verify manual retry resets execution count, transitions back to QUEUED and triggers task."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_a = setup_users["headers_a"]
    db = db_manager.db

    exec_id = "EXEC-RETRY-1"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "FAILED",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "attempt_count": 3,
        "max_attempts": 3,
        "soft_delete": False
    })

    res = await client.post(f"/api/v1/response-operations/executions/{exec_id}/retry", headers=headers_a)
    assert res.status_code == 200
    assert res.json()["status"] == "QUEUED"
    assert res.json()["attempt_count"] == 0

    updated = await db["soar_execution_requests"].find_one({"execution_id": exec_id})
    assert updated["status"] == "SUCCESS"
    assert updated["attempt_count"] == 0

@pytest.mark.anyio
async def test_manual_retry_invalid_states(client: AsyncClient, setup_operations_data, setup_users):
    """Verify manual retry fails if state is not FAILED or EXHAUSTED."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_a = setup_users["headers_a"]
    db = db_manager.db

    exec_id = "EXEC-RETRY-INVALID"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "SUCCESS",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False
    })

    res = await client.post(f"/api/v1/response-operations/executions/{exec_id}/retry", headers=headers_a)
    assert res.status_code == 400
    assert "Manual retry is only allowed for FAILED or EXHAUSTED" in res.json()["detail"]

@pytest.mark.anyio
async def test_cancellation_queued(client: AsyncClient, setup_operations_data, setup_users):
    """Verify cancelling executions in QUEUED status transitions to CANCELLED."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_a = setup_users["headers_a"]
    db = db_manager.db

    exec_id = "EXEC-CANCEL-Q"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "QUEUED",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False
    })

    res = await client.post(f"/api/v1/response-operations/executions/{exec_id}/cancel", headers=headers_a)
    assert res.status_code == 200
    assert res.json()["status"] == "CANCELLED"

@pytest.mark.anyio
async def test_cancellation_validating(client: AsyncClient, setup_operations_data, setup_users):
    """Verify cancelling executions in VALIDATING status transitions to CANCELLED."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_a = setup_users["headers_a"]
    db = db_manager.db

    exec_id = "EXEC-CANCEL-VAL"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "VALIDATING",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False
    })

    res = await client.post(f"/api/v1/response-operations/executions/{exec_id}/cancel", headers=headers_a)
    assert res.status_code == 200
    assert res.json()["status"] == "CANCELLED"

@pytest.mark.anyio
async def test_cancellation_invalid_states(client: AsyncClient, setup_operations_data, setup_users):
    """Verify cancelling running or success executions is rejected."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_a = setup_users["headers_a"]
    db = db_manager.db

    exec_id = "EXEC-CANCEL-INV"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "SUCCESS",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False
    })

    res = await client.post(f"/api/v1/response-operations/executions/{exec_id}/cancel", headers=headers_a)
    assert res.status_code == 400
    assert "cannot be cancelled" in res.json()["detail"]

@pytest.mark.anyio
async def test_tenant_isolation_list(client: AsyncClient, setup_operations_data, setup_users):
    """Verify tenant B cannot view or list executions from tenant A."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_b = setup_users["headers_b"]
    db = db_manager.db

    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": "EXEC-ISOLATE-LIST",
        "response_decision_id": decision_id,
        "status": "QUEUED",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False
    })

    res = await client.get("/api/v1/response-operations/executions", headers=headers_b)
    assert res.status_code == 200
    assert len(res.json()["results"]) == 0

@pytest.mark.anyio
async def test_tenant_isolation_detail(client: AsyncClient, setup_operations_data, setup_users):
    """Verify tenant B cannot view details of tenant A's execution request."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_b = setup_users["headers_b"]
    db = db_manager.db

    exec_id = "EXEC-ISOLATE-DETAIL"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "SUCCESS",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False
    })

    res = await client.get(f"/api/v1/response-operations/executions/{exec_id}", headers=headers_b)
    assert res.status_code == 404

@pytest.mark.anyio
async def test_tenant_isolation_timeline(client: AsyncClient, setup_operations_data, setup_users):
    """Verify tenant B cannot view timeline of tenant A's execution request."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_b = setup_users["headers_b"]
    db = db_manager.db

    exec_id = "EXEC-ISOLATE-TIMELINE"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "SUCCESS",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False
    })

    res = await client.get(f"/api/v1/response-operations/executions/{exec_id}/timeline", headers=headers_b)
    assert res.status_code == 404

@pytest.mark.anyio
async def test_tenant_isolation_cancel(client: AsyncClient, setup_operations_data, setup_users):
    """Verify tenant B cannot cancel tenant A's execution request."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_b = setup_users["headers_b"]
    db = db_manager.db

    exec_id = "EXEC-ISOLATE-CANCEL"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "QUEUED",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False
    })

    res = await client.post(f"/api/v1/response-operations/executions/{exec_id}/cancel", headers=headers_b)
    assert res.status_code == 404

@pytest.mark.anyio
async def test_tenant_isolation_retry(client: AsyncClient, setup_operations_data, setup_users):
    """Verify tenant B cannot retry tenant A's execution request."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_b = setup_users["headers_b"]
    db = db_manager.db

    exec_id = "EXEC-ISOLATE-RETRY"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "FAILED",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "soft_delete": False
    })

    res = await client.post(f"/api/v1/response-operations/executions/{exec_id}/retry", headers=headers_b)
    assert res.status_code == 404

@pytest.mark.anyio
async def test_secrets_redaction(client: AsyncClient, setup_operations_data, setup_users):
    """Verify API responses redact credentials, secrets, or raw token configurations."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    headers_a = setup_users["headers_a"]
    db = db_manager.db

    exec_id = "EXEC-SECRETS-1"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "SUCCESS",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "authorization_reference": "SECRET_RAW_TOKEN_AAA",
        "soft_delete": False
    })

    res = await client.get(f"/api/v1/response-operations/executions/{exec_id}", headers=headers_a)
    assert res.status_code == 200
    data = res.json()
    # Check authorization reference exposes metadata but not raw token contents or keys
    assert "SECRET_RAW_TOKEN_AAA" not in str(data)

@pytest.mark.anyio
async def test_failure_classification_timeout(setup_operations_data):
    """Verify transient socket timeouts trigger retry states and Celery schedules."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    db = db_manager.db

    exec_id = f"EXEC-T-{uuid.uuid4()}"
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "QUEUED",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-HOST-ISOLATION",
        "attempt_count": 0,
        "max_attempts": 3,
        "soft_delete": False
    })

    # Update active integration to use a timeout trigger url
    await db["integrations"].update_one(
        {"organization_id": org_a, "status": "ACTIVE"},
        {"$set": {"config": {"url": "https://timeout-trigger.com"}}}
    )

    # Run the worker directly
    res = await _soar_execution_async(exec_id)
    assert res["status"] == "RETRYING"
    assert res["attempt"] == 1

    updated = await db["soar_execution_requests"].find_one({"execution_id": exec_id})
    assert updated["status"] == "EXHAUSTED"
    assert updated["error_code"] == "CONNECTOR_TIMEOUT"
    assert updated["attempt_count"] == 3
    assert updated["retryable"] is False

@pytest.mark.anyio
async def test_failure_classification_permanent(setup_operations_data):
    """Verify permanent validation failures immediately exhaust attempts."""
    org_a = setup_operations_data["org_a"]
    decision_id = setup_operations_data["decision_id"]
    db = db_manager.db

    exec_id = f"EXEC-P-{uuid.uuid4()}"
    # Target a non-existent playbook to trigger validation failure
    await db["soar_execution_requests"].insert_one({
        "organization_id": org_a,
        "execution_id": exec_id,
        "response_decision_id": decision_id,
        "status": "QUEUED",
        "recommended_action": "isolate-host",
        "playbook_id": "PLAYBOOK-INVALID-NONEXISTENT",
        "attempt_count": 0,
        "max_attempts": 3,
        "soft_delete": False
    })

    res = await _soar_execution_async(exec_id)
    assert res["status"] == "FAILED"

    updated = await db["soar_execution_requests"].find_one({"execution_id": exec_id})
    assert updated["status"] == "EXHAUSTED"
    assert updated["error_code"] == "VALIDATION_FAILURE"
    assert updated["retryable"] is False

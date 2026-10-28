import pytest
import asyncio
from httpx import AsyncClient
from datetime import datetime, timedelta, timezone
from app.database.connection import db_manager
from bson import ObjectId

async def setup_test_auth_and_rule(client: AsyncClient, db, org_id="org_a", rule_id="RULE-TEST-01"):
    """Helper to register user, set admin role, and create a detection rule."""
    await db["users"].delete_many({"email": "analyst@enterprise.com"})
    await db["detection_rules"].delete_many({"organization_id": org_id})
    await db["detection_versions"].delete_many({"organization_id": org_id})
    await db["detection_tests"].delete_many({"organization_id": org_id})
    await db["detection_test_results"].delete_many({"organization_id": org_id})
    await db["detection_test_matches"].delete_many({"organization_id": org_id})
    await db["audit_logs"].delete_many({"organization_id": org_id})

    await client.post("/api/v1/auth/register", json={
        "email": "analyst@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "SOC Analyst"
    })
    user = await db["users"].find_one({"email": "analyst@enterprise.com"})
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "organization_id": org_id}})
    
    await db["organization_memberships"].delete_many({"user_id": str(user["_id"])})
    await db["organization_memberships"].insert_one({
        "organization_id": org_id,
        "user_id": str(user["_id"]),
        "role": "admin",
        "soft_delete": False
    })

    login_res = await client.post("/api/v1/auth/login", json={
        "email": "analyst@enterprise.com",
        "password": "StrongPassword123!"
    })
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # Create Rule
    await client.post("/api/v1/detections", json={
        "rule_id": rule_id,
        "name": "Auth Failure Rule",
        "description": "Rule to test auth failures",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "data_sources": ["auth"],
        "conditions": {"event_type": "login", "severity": "high"},
        "time_window": 60,
        "mitre_attack_techniques": ["T1110"],
        "false_positive_guidance": "Ignore test alerts"
    }, headers=headers)

    return headers

@pytest.mark.asyncio
async def test_create_and_list_detection_tests(client: AsyncClient):
    """Verify creating a detection test config registers in PENDING status."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_a"
    rule_id = "RULE-TEST-01"

    headers = await setup_test_auth_and_rule(client, db, org_id, rule_id)

    # Create Test Configuration
    res = await client.post(f"/api/v1/detections/{rule_id}/tests", json={
        "name": "Auth Failure Controlled Test",
        "description": "Verify rule with mock logins",
        "test_type": "controlled_event",
        "version_number": 1,
        "test_cases": [
            {
                "input_event": {"event_type": "login", "severity": "high", "payload": {"user": "admin"}},
                "expected_match": True
            },
            {
                "input_event": {"event_type": "login", "severity": "low", "payload": {"user": "normal"}},
                "expected_match": False
            }
        ]
    }, headers=headers)

    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Auth Failure Controlled Test"
    assert data["status"] == "PENDING"
    assert len(data["test_cases"]) == 2

    # Verify List Tests endpoint
    list_res = await client.get(f"/api/v1/detections/{rule_id}/tests", headers=headers)
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1
    assert list_res.json()[0]["rule_id"] == rule_id

@pytest.mark.asyncio
async def test_run_controlled_event_test_metrics_calculation(client: AsyncClient):
    """Verify test run calculates Precision, Recall, F1, and result classifications (TP/FP/TN/FN)."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_a"
    rule_id = "RULE-TEST-01"

    headers = await setup_test_auth_and_rule(client, db, org_id, rule_id)

    # Create Test Configuration
    test_res = await client.post(f"/api/v1/detections/{rule_id}/tests", json={
        "name": "Auth Failure Controlled Test",
        "description": "Verify rule with mock logins",
        "test_type": "controlled_event",
        "version_number": 1,
        "test_cases": [
            {
                "input_event": {"event_type": "login", "severity": "high", "payload": {"user": "admin"}},
                "expected_match": True
            },
            {
                "input_event": {"event_type": "login", "severity": "low", "payload": {"user": "normal"}},
                "expected_match": False
            }
        ]
    }, headers=headers)
    test_id = test_res.json()["_id"]

    # Run Test
    run_res = await client.post(f"/api/v1/detections/{rule_id}/tests/{test_id}/run", headers=headers)
    assert run_res.status_code == 200
    data = run_res.json()
    assert data["status"] == "PASSED"
    assert data["true_positives"] == 1
    assert data["true_negatives"] == 1
    assert data["false_positives"] == 0
    assert data["false_negatives"] == 0
    assert data["precision"] == 1.0
    assert data["recall"] == 1.0
    assert data["f1_score"] == 1.0

    # Verify results stored
    res_list = await client.get(f"/api/v1/detections/{rule_id}/tests/{test_id}/results", headers=headers)
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1
    assert res_list.json()[0]["status"] == "PASSED"

    # Verify matches stored
    matches_res = await client.get(f"/api/v1/detections/{rule_id}/tests/{test_id}/matches", headers=headers)
    assert matches_res.status_code == 200
    assert len(matches_res.json()) >= 1
    assert matches_res.json()[0]["status"] == "TP"

@pytest.mark.asyncio
async def test_zero_denominator_safety(client: AsyncClient):
    """Verify that metrics calculate safely without division-by-zero errors when matches are empty."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_a"
    rule_id = "RULE-TEST-01"

    headers = await setup_test_auth_and_rule(client, db, org_id, rule_id)

    # Create test where no cases trigger matches and expected matches are also zero
    test_res = await client.post(f"/api/v1/detections/{rule_id}/tests", json={
        "name": "Zero Denominator Test",
        "test_type": "controlled_event",
        "version_number": 1,
        "test_cases": [
            {
                "input_event": {"event_type": "login", "severity": "low", "payload": {"user": "guest"}},
                "expected_match": False
            }
        ]
    }, headers=headers)
    test_id = test_res.json()["_id"]

    # Run Test
    run_res = await client.post(f"/api/v1/detections/{rule_id}/tests/{test_id}/run", headers=headers)
    assert run_res.status_code == 200
    data = run_res.json()
    assert data["status"] == "PASSED"
    assert data["true_positives"] == 0
    assert data["false_positives"] == 0
    assert data["precision"] == 0.0
    assert data["recall"] == 0.0
    assert data["f1_score"] == 0.0

@pytest.mark.asyncio
async def test_test_failure_on_unexpected_match(client: AsyncClient):
    """Verify test status is FAILED when actual outcomes deviate from expected outcomes."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_a"
    rule_id = "RULE-TEST-01"

    headers = await setup_test_auth_and_rule(client, db, org_id, rule_id)

    # Create test where matching event is marked as expected_match=False (False Positive test)
    test_res = await client.post(f"/api/v1/detections/{rule_id}/tests", json={
        "name": "False Positive Inducing Test",
        "test_type": "controlled_event",
        "version_number": 1,
        "test_cases": [
            {
                "input_event": {"event_type": "login", "severity": "high", "payload": {"user": "admin"}},
                "expected_match": False  # We expect NO match, but it will match!
            }
        ]
    }, headers=headers)
    test_id = test_res.json()["_id"]

    # Run Test
    run_res = await client.post(f"/api/v1/detections/{rule_id}/tests/{test_id}/run", headers=headers)
    assert run_res.status_code == 200
    data = run_res.json()
    assert data["status"] == "FAILED"
    assert data["false_positives"] == 1
    assert data["precision"] == 0.0

@pytest.mark.asyncio
async def test_multi_tenant_test_isolation_idor(client: AsyncClient):
    """Verify Organization B cannot access, run, or cancel Organization A's test configurations."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_a"
    rule_id = "RULE-TEST-01"

    headers_a = await setup_test_auth_and_rule(client, db, org_id, rule_id)

    # Create Org A Test Configuration
    test_res = await client.post(f"/api/v1/detections/{rule_id}/tests", json={
        "name": "Org A Test",
        "test_type": "controlled_event",
        "version_number": 1,
        "test_cases": []
    }, headers=headers_a)
    test_id = test_res.json()["_id"]

    # Register Org B User
    await db["users"].delete_many({"email": "hacker@enterprise.com"})
    await client.post("/api/v1/auth/register", json={
        "email": "hacker@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Org B Malicious Analyst"
    })
    user_b = await db["users"].find_one({"email": "hacker@enterprise.com"})
    await db["users"].update_one({"_id": user_b["_id"]}, {"$set": {"role": "admin", "organization_id": "org_b"}})

    await db["organization_memberships"].delete_many({"user_id": str(user_b["_id"])})
    await db["organization_memberships"].insert_one({
        "organization_id": "org_b",
        "user_id": str(user_b["_id"]),
        "role": "admin",
        "soft_delete": False
    })

    b_login = await client.post("/api/v1/auth/login", json={
        "email": "hacker@enterprise.com",
        "password": "StrongPassword123!"
    })
    b_headers = {"Authorization": f"Bearer {b_login.json()['access_token']}"}

    # Attempt GET from Org B
    res_get = await client.get(f"/api/v1/detections/RULE-TEST-01/tests/{test_id}", headers=b_headers)
    assert res_get.status_code == 404

    # Attempt RUN from Org B
    res_run = await client.post(f"/api/v1/detections/RULE-TEST-01/tests/{test_id}/run", headers=b_headers)
    assert res_run.status_code == 404

@pytest.mark.asyncio
async def test_historical_replay_async_dispatch(client: AsyncClient):
    """Verify historical replay triggers Celery async dispatch and bounds time ranges."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_a"
    rule_id = "RULE-TEST-01"

    headers = await setup_test_auth_and_rule(client, db, org_id, rule_id)

    # Create Historical Test
    res = await client.post(f"/api/v1/detections/{rule_id}/tests", json={
        "name": "Historical Replay Test Run",
        "test_type": "historical_replay",
        "max_events": 500,
        "time_range_start": str(datetime.now(timezone.utc) - timedelta(days=5)),
        "time_range_end": str(datetime.now(timezone.utc))
    }, headers=headers)
    assert res.status_code == 201
    test_id = res.json()["_id"]

    # Ingest mock telemetry event
    await db["security_telemetry"].insert_one({
        "organization_id": org_id,
        "event_id": "evt-1234",
        "event_type": "login",
        "severity": "high",
        "source": "10.0.0.1",
        "payload": {"user": "admin"},
        "timestamp": datetime.now(timezone.utc),
        "partition_key": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "soft_delete": False
    })

    # Run Test
    run_res = await client.post(f"/api/v1/detections/{rule_id}/tests/{test_id}/run", headers=headers)
    assert run_res.status_code == 200
    assert run_res.json()["status"] == "queued"

    # Wait for Celery eager execution completion
    await asyncio.sleep(0.5)
    test_status = await db["detection_tests"].find_one({"_id": ObjectId(test_id)})
    assert test_status["status"] == "PASSED"

@pytest.mark.asyncio
async def test_version_comparison_stats(client: AsyncClient):
    """Verify comparing rule versions returns matched delta."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_a"
    rule_id = "RULE-TEST-01"

    headers = await setup_test_auth_and_rule(client, db, org_id, rule_id)

    # Insert mock results for v1 and v2
    await db["detection_test_results"].insert_one({
        "organization_id": org_id,
        "test_id": "test-1",
        "rule_id": rule_id,
        "version_number": 1,
        "status": "PASSED",
        "created_at": datetime.now(timezone.utc) - timedelta(hours=1),
        "match_count": 10,
        "false_positives": 1,
        "precision": 0.9,
        "recall": 1.0,
        "soft_delete": False
    })

    await db["detection_test_results"].insert_one({
        "organization_id": org_id,
        "test_id": "test-2",
        "rule_id": rule_id,
        "version_number": 2,
        "status": "PASSED",
        "created_at": datetime.now(timezone.utc),
        "match_count": 5,
        "false_positives": 0,
        "precision": 1.0,
        "recall": 1.0,
        "soft_delete": False
    })

    compare_res = await client.post(f"/api/v1/detections/{rule_id}/compare-versions", json={
        "v1": 1,
        "v2": 2
    }, headers=headers)
    assert compare_res.status_code == 200
    data = compare_res.json()
    assert data["v1"]["match_count"] == 10
    assert data["v2"]["match_count"] == 5
    assert data["comparison"]["match_count_delta"] == -5
    assert data["comparison"]["precision_delta"] == pytest.approx(0.1)

@pytest.mark.asyncio
async def test_cancellation_lifecycle_transitions(client: AsyncClient):
    """Verify test transitions to CANCELLED state and audits."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_a"
    rule_id = "RULE-TEST-01"

    headers = await setup_test_auth_and_rule(client, db, org_id, rule_id)

    # Create Test Configuration
    test_res = await client.post(f"/api/v1/detections/{rule_id}/tests", json={
        "name": "Auth Failure Controlled Test",
        "test_type": "controlled_event",
        "version_number": 1,
        "test_cases": []
    }, headers=headers)
    test_id = test_res.json()["_id"]

    # Reset status to RUNNING to allow cancellation
    await db["detection_tests"].update_one(
        {"_id": ObjectId(test_id)},
        {"$set": {"status": "RUNNING"}}
    )

    # Cancel
    cancel_res = await client.post(f"/api/v1/detections/{rule_id}/tests/{test_id}/cancel", headers=headers)
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"

    # Verify Audit logged
    audit = await db["audit_logs"].find_one({"organization_id": org_id, "action": "DETECTION_TEST_CANCELLED"})
    assert audit is not None

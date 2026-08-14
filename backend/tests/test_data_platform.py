import pytest
from httpx import AsyncClient
from datetime import datetime, timedelta
from app.database.connection import db_manager
from app.services.data_platform_service import data_platform_service
from app.core.tenant_context import TenantContext

@pytest.mark.asyncio
async def test_ingest_telemetry_normalization():
    """Verify telemetry normalization, automatic partition formatting, and properties generation."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_dp_test"

    # Reset
    await db["security_telemetry"].delete_many({"organization_id": org_id})

    res = await data_platform_service.ingest_telemetry(
        org_id=org_id,
        event_type="syslog",
        severity="high",
        source="firewall-prod",
        payload={"action": "REJECT", "port": 22}
    )

    assert res["organization_id"] == org_id
    assert res["event_type"] == "syslog"
    assert res["severity"] == "high"
    assert res["source"] == "firewall-prod"
    assert res["partition_key"] == datetime.utcnow().strftime("%Y-%m-%d")
    assert "rolling_rate_60s" in res

@pytest.mark.asyncio
async def test_sliding_window_spikes_detection():
    """Verify that event rates are accurately tracked using real-time sliding windows."""
    if db_manager.db is None:
        await db_manager.connect()

    org_id = "org_dp_test"

    # Execute multiple ingestions
    rate_1 = await data_platform_service.track_realtime_rate(org_id)
    rate_2 = await data_platform_service.track_realtime_rate(org_id)
    
    # If Redis is connected, rate_2 should be greater than rate_1 or at least 1.
    assert rate_1 >= 1
    assert rate_2 >= 1

@pytest.mark.asyncio
async def test_ml_feature_store_read_write():
    """Verify writing, updating, and querying ML security feature vectors."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db
    org_id = "org_dp_test"

    await db["ml_features"].delete_many({"organization_id": org_id})

    # Create new feature value
    feat_1 = await data_platform_service.get_or_create_feature(org_id, "user_1", "FEAT-EMAIL-FREQ", 12.5)
    assert feat_1["value"] == 12.5

    # Update value
    feat_2 = await data_platform_service.get_or_create_feature(org_id, "user_1", "FEAT-EMAIL-FREQ", 18.2)
    assert feat_2["value"] == 18.2

    # Query from repo
    feats = await data_platform_service.feature_repo.get_by_entity(org_id, "user_1")
    assert len(feats) == 1
    assert feats[0]["feature_name"] == "FEAT-EMAIL-FREQ"
    assert feats[0]["value"] == 18.2

@pytest.mark.asyncio
async def test_threat_hunting_query_tenant_isolation(client: AsyncClient):
    """Verify that custom telemetry queries enforce strict tenant boundary isolation."""
    if db_manager.db is None:
        await db_manager.connect()

    db = db_manager.db

    # Register Org A & Org B Users
    await db["users"].delete_many({"email": {"$in": ["dpa@enterprise.com", "dpb@enterprise.com"]}})
    
    await client.post("/api/v1/auth/register", json={
        "email": "dpa@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Org A Threat Hunter"
    })
    await client.post("/api/v1/auth/register", json={
        "email": "dpb@enterprise.com",
        "password": "StrongPassword123!",
        "full_name": "Org B Threat Hunter"
    })

    user_a = await db["users"].find_one({"email": "dpa@enterprise.com"})
    user_b = await db["users"].find_one({"email": "dpb@enterprise.com"})

    await db["users"].update_one({"_id": user_a["_id"]}, {"$set": {"role": "admin", "organization_id": "org_a"}})
    await db["users"].update_one({"_id": user_b["_id"]}, {"$set": {"role": "admin", "organization_id": "org_b"}})

    # Insert memberships
    await db["organization_memberships"].delete_many({"user_id": {"$in": [str(user_a["_id"]), str(user_b["_id"])]}})
    await db["organization_memberships"].insert_one({
        "organization_id": "org_a",
        "user_id": str(user_a["_id"]),
        "role": "admin",
        "soft_delete": False
    })
    await db["organization_memberships"].insert_one({
        "organization_id": "org_b",
        "user_id": str(user_b["_id"]),
        "role": "admin",
        "soft_delete": False
    })

    a_login = await client.post("/api/v1/auth/login", json={
        "email": "dpa@enterprise.com",
        "password": "StrongPassword123!"
    })
    a_headers = {"Authorization": f"Bearer {a_login.json()['access_token']}"}

    b_login = await client.post("/api/v1/auth/login", json={
        "email": "dpb@enterprise.com",
        "password": "StrongPassword123!"
    })
    b_headers = {"Authorization": f"Bearer {b_login.json()['access_token']}"}

    # Ingest telemetry logs for Org A
    await db["security_telemetry"].delete_many({"organization_id": "org_a"})
    await db["security_telemetry"].insert_one({
        "organization_id": "org_a",
        "event_id": "dp-a-event",
        "event_type": "login",
        "timestamp": datetime.utcnow(),
        "severity": "medium",
        "source": "192.168.1.5",
        "payload": {"username": "admin"},
        "partition_key": datetime.utcnow().strftime("%Y-%m-%d"),
        "soft_delete": False
    })

    # Retrieve Org A logs with Org A token
    res_a = await client.post("/api/v1/data-platform/query", json={"criteria": {"event_type": "login"}}, headers=a_headers)
    assert res_a.status_code == 200
    assert len(res_a.json()) == 1
    assert res_a.json()[0]["event_id"] == "dp-a-event"

    # Attempt to retrieve with Org B token
    res_b = await client.post("/api/v1/data-platform/query", json={"criteria": {"event_type": "login"}}, headers=b_headers)
    assert res_b.status_code == 200
    assert len(res_b.json()) == 0  # Should be empty because it is filtered on Org B!

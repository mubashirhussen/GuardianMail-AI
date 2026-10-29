import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timezone, timedelta
from app.main import app
from app.database.connection import db_manager
from app.security.jwt import create_access_token, create_refresh_token
from app.repositories.user_repo import UserRepository
from app.repositories.organization_membership_repo import OrganizationMembershipRepository
from app.core.security import get_password_hash

@pytest.fixture
async def setup_grc_environment():
    """Seed test user, tenant organization, and membership for GRC workflows."""
    db = db_manager.db
    user_repo = UserRepository(db)
    membership_repo = OrganizationMembershipRepository(db)

    # Clean existing test artifacts
    email = "grc_auditor@guardianmail.corp"
    await db["users"].delete_many({"email": email})
    
    hashed = get_password_hash("AuditSecret123!")
    user_doc = {
        "email": email,
        "hashed_password": hashed,
        "full_name": "Senior GRC Auditor",
        "role": "user",
        "is_active": True,
        "is_verified": True,
        "soft_delete": False,
        "created_at": datetime.now(timezone.utc)
    }
    res_user = await db["users"].insert_one(user_doc)
    user_id = str(res_user.inserted_id)

    # Create Organization
    org_doc = {
        "name": "Audit Security Corp",
        "slug": f"audit-corp-{uuid.uuid4().hex[:6]}",
        "owner_id": user_id,
        "is_active": True,
        "soft_delete": False,
        "created_at": datetime.now(timezone.utc)
    }
    res_org = await db["organizations"].insert_one(org_doc)
    org_id = str(res_org.inserted_id)

    # Organization membership
    await db["organization_memberships"].insert_one({
        "organization_id": org_id,
        "user_id": user_id,
        "role": "admin",
        "is_active": True,
        "soft_delete": False,
        "created_at": datetime.now(timezone.utc)
    })

    # Generate tokens and active session
    token_id = str(uuid.uuid4())
    access_token = create_access_token(subject=user_id, jti=token_id, expires_delta=timedelta(minutes=15))
    refresh_token = create_refresh_token(subject=user_id, jti=token_id, expires_delta=timedelta(days=7))
    expired_token = create_access_token(subject=user_id, jti=str(uuid.uuid4()), expires_delta=timedelta(seconds=-10))

    await db["sessions"].insert_one({
        "token_id": token_id,
        "user_id": user_id,
        "is_active": True,
        "ip_address": "127.0.0.1",
        "created_at": datetime.now(timezone.utc),
        "last_activity": datetime.now(timezone.utc)
    })

    yield {
        "user_id": user_id,
        "org_id": org_id,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expired_token": expired_token,
    }

    # Cleanup
    await db["users"].delete_many({"_id": res_user.inserted_id})
    await db["organizations"].delete_many({"_id": res_org.inserted_id})
    await db["organization_memberships"].delete_many({"organization_id": org_id})
    await db["sessions"].delete_many({"user_id": user_id})
    await db["compliance_controls"].delete_many({"organization_id": org_id})
    await db["compliance_evidence"].delete_many({"organization_id": org_id})
    await db["grc_sync_logs"].delete_many({"organization_id": org_id})

@pytest.mark.asyncio
async def test_expired_token_is_rejected_with_401(setup_grc_environment):
    env = setup_grc_environment
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        headers = {
            "Authorization": f"Bearer {env['expired_token']}",
            "X-Organization-ID": env["org_id"]
        }
        res = await ac.get("/api/v1/grc/posture", headers=headers)
        assert res.status_code == 401
        assert "expired" in res.json().get("detail", "").lower()

@pytest.mark.asyncio
async def test_refresh_token_rotation_succeeds(setup_grc_environment):
    env = setup_grc_environment
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Refresh with json body
        res = await ac.post("/api/v1/auth/refresh", json={"refresh_token": env["refresh_token"]})
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

        # Using the renewed access token succeeds on GRC posture
        new_headers = {
            "Authorization": f"Bearer {data['access_token']}",
            "X-Organization-ID": env["org_id"]
        }
        res_posture = await ac.get("/api/v1/grc/posture", headers=new_headers)
        assert res_posture.status_code == 200

@pytest.mark.asyncio
async def test_system_sync_seeds_baseline_controls_and_evidence(setup_grc_environment):
    env = setup_grc_environment
    headers = {
        "Authorization": f"Bearer {env['access_token']}",
        "X-Organization-ID": env["org_id"]
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Trigger System Sync
        res_sync = await ac.post("/api/v1/grc/sync", headers=headers)
        assert res_sync.status_code == 200
        sync_data = res_sync.json()
        assert sync_data["status"] == "completed"
        assert sync_data["items_synced"] > 0
        assert "summary" in sync_data

        # Verify controls are mapped
        res_controls = await ac.get("/api/v1/grc/controls", headers=headers)
        assert res_controls.status_code == 200
        controls_list = res_controls.json()
        assert len(controls_list) >= 8

        # Verify sync status is returned
        res_status = await ac.get("/api/v1/grc/sync/status", headers=headers)
        assert res_status.status_code == 200
        assert res_status.json()["status"] == "completed"

@pytest.mark.asyncio
async def test_evidence_collection_and_integrity_verification(setup_grc_environment):
    env = setup_grc_environment
    headers = {
        "Authorization": f"Bearer {env['access_token']}",
        "X-Organization-ID": env["org_id"]
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Collect system evidence
        res_ev = await ac.post("/api/v1/grc/evidence/collect", headers=headers)
        assert res_ev.status_code == 200
        ev_items = res_ev.json()
        assert len(ev_items) > 0

        first_ev = ev_items[0]
        ev_id = first_ev["_id"]

        # Verify cryptographic integrity seal
        res_verify = await ac.post(f"/api/v1/grc/evidence/{ev_id}/verify", headers=headers)
        assert res_verify.status_code == 200
        verify_data = res_verify.json()
        assert verify_data["is_valid"] is True
        assert verify_data["status"] == "VERIFIED"
        assert verify_data["algorithm"] == "SHA-256"

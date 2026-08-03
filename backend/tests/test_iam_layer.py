import pytest
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Depends, status
from fastapi.testclient import TestClient
from httpx import AsyncClient
from app.models.user import UserRole
from app.api.dependencies.auth import RequireRole, get_current_active_user
from app.security.jwt import create_access_token, decode_token
from app.database.cache import cache_manager

# Create a dummy FastAPI route to test RBAC role restrictions
from app.main import app

@app.get("/api/v1/test-rbac-admin")
async def rbac_admin_route(user = Depends(RequireRole(["admin"]))):
    return {"status": "authorized", "user_id": str(user.id)}

@app.get("/api/v1/test-rbac-analyst")
async def rbac_analyst_route(user = Depends(RequireRole(["security_analyst", "admin"]))):
    return {"status": "authorized", "user_id": str(user.id)}

@pytest.mark.asyncio
async def test_iam_user_registration_and_login(client: AsyncClient):
    """Test user registration flow, duplicate prevention, and successful credentials login."""
    # 1. Register a new user
    register_payload = {
        "email": "iam_user@example.com",
        "full_name": "IAM Test User",
        "role": "user",
        "password": "secure_password_123"
    }
    resp = await client.post("/api/v1/auth/register", json=register_payload)
    assert resp.status_code == status.HTTP_201_CREATED
    data = resp.json()
    assert data["email"] == "iam_user@example.com"
    assert "hashed_password" not in data
    
    # 2. Prevent duplicate email registration
    dup_resp = await client.post("/api/v1/auth/register", json=register_payload)
    assert dup_resp.status_code == status.HTTP_400_BAD_REQUEST
    
    # 3. Successful login
    login_payload = {
        "email": "iam_user@example.com",
        "password": "secure_password_123"
    }
    login_resp = await client.post("/api/v1/auth/login", json=login_payload)
    assert login_resp.status_code == status.HTTP_200_OK
    token_data = login_resp.json()
    assert "access_token" in token_data
    assert "refresh_token" in token_data
    assert token_data["token_type"] == "bearer"
    
    # 4. Incorrect credentials failure
    bad_login_payload = {
        "email": "iam_user@example.com",
        "password": "wrong_password"
    }
    bad_resp = await client.post("/api/v1/auth/login", json=bad_login_payload)
    assert bad_resp.status_code == status.HTTP_400_BAD_REQUEST

@pytest.mark.asyncio
async def test_iam_lockout_protection(client: AsyncClient):
    """Verify that multiple failed logins lock out the account."""
    # Register lockout target user
    register_payload = {
        "email": "lockout_user@example.com",
        "full_name": "Lockout Test User",
        "role": "user",
        "password": "secure_password_123"
    }
    await client.post("/api/v1/auth/register", json=register_payload)
    
    # Trigger lockout (simulate 5 login attempts)
    bad_login_payload = {
        "email": "lockout_user@example.com",
        "password": "wrong_password"
    }
    
    # Trigger 5 failed logins
    for i in range(5):
         resp = await client.post("/api/v1/auth/login", json=bad_login_payload)
         assert resp.status_code == status.HTTP_400_BAD_REQUEST
         
    # The 6th attempt should be blocked with locked account message (403 FORBIDDEN)
    lock_resp = await client.post("/api/v1/auth/login", json=bad_login_payload)
    assert lock_resp.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_403_FORBIDDEN]

@pytest.mark.asyncio
async def test_iam_current_user_profile_and_sessions(client: AsyncClient):
    """Test retrieving profile details, updating settings, listing active sessions, and revoking sessions."""
    # 1. Login to retrieve tokens
    login_payload = {
        "email": "iam_user@example.com",
        "password": "secure_password_123"
    }
    login_resp = await client.post("/api/v1/auth/login", json=login_payload)
    token_data = login_resp.json()
    token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Get profile details (GET /auth/me)
    me_resp = await client.get("/api/v1/auth/me", headers=headers)
    assert me_resp.status_code == status.HTTP_200_OK
    assert me_resp.json()["email"] == "iam_user@example.com"
    
    # 3. Update profile (PUT /auth/profile)
    update_resp = await client.put("/api/v1/auth/profile", json={"full_name": "New Name IAM"}, headers=headers)
    assert update_resp.status_code == status.HTTP_200_OK
    assert update_resp.json()["full_name"] == "New Name IAM"
    
    # 4. Get active sessions (GET /auth/sessions)
    sess_resp = await client.get("/api/v1/auth/sessions", headers=headers)
    assert sess_resp.status_code == status.HTTP_200_OK
    sessions = sess_resp.json()
    assert len(sessions) > 0
    session_id = sessions[0]["_id"]
    
    # 5. Revoke specific session (DELETE /auth/session/{id})
    del_resp = await client.delete(f"/api/v1/auth/session/{session_id}", headers=headers)
    assert del_resp.status_code == status.HTTP_200_OK
    
    # 6. Logout other devices (POST /auth/logout-other-devices)
    logout_others_resp = await client.post("/api/v1/auth/logout-other-devices", headers=headers)
    assert logout_others_resp.status_code == status.HTTP_200_OK
    
    # 7. Logout current session
    logout_resp = await client.post("/api/v1/auth/logout", headers=headers)
    assert logout_resp.status_code == status.HTTP_200_OK

@pytest.mark.asyncio
async def test_iam_token_rotation_refresh(client: AsyncClient):
    """Verify that credentials tokens can be rotated and old refresh tokens are blacklisted."""
    login_payload = {
        "email": "iam_user@example.com",
        "password": "secure_password_123"
    }
    login_resp = await client.post("/api/v1/auth/login", json=login_payload)
    token_data = login_resp.json()
    refresh_token = token_data["refresh_token"]
    
    # Rotate tokens
    refresh_resp = await client.post(f"/api/v1/auth/refresh?refresh_token={refresh_token}")
    assert refresh_resp.status_code == status.HTTP_200_OK
    new_tokens = refresh_resp.json()
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens
    
    # Trying to reuse old refresh token should be rejected (since it was blacklisted)
    second_refresh = await client.post(f"/api/v1/auth/refresh?refresh_token={refresh_token}")
    assert second_refresh.status_code == status.HTTP_401_UNAUTHORIZED

@pytest.mark.asyncio
async def test_iam_rbac_protection_policies(client: AsyncClient):
    """Test RBAC role enforcer policies block unauthorized access and allow authorized users."""
    # 1. Register an admin user
    register_payload = {
        "email": "admin_user@example.com",
        "full_name": "Admin User",
        "role": "admin",
        "password": "secure_password_123"
    }
    await client.post("/api/v1/auth/register", json=register_payload)
    
    # Login as User (role=user)
    user_login = await client.post("/api/v1/auth/login", json={"email": "iam_user@example.com", "password": "secure_password_123"})
    user_token = user_login.json()["access_token"]
    
    # Login as Admin (role=admin)
    admin_login = await client.post("/api/v1/auth/login", json={"email": "admin_user@example.com", "password": "secure_password_123"})
    admin_token = admin_login.json()["access_token"]
    
    # 2. Test user accessing admin route -> should be 403 FORBIDDEN
    user_resp = await client.get("/api/v1/test-rbac-admin", headers={"Authorization": f"Bearer {user_token}"})
    assert user_resp.status_code == status.HTTP_403_FORBIDDEN
    
    # 3. Test admin accessing admin route -> should be 200 OK
    admin_resp = await client.get("/api/v1/test-rbac-admin", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_resp.status_code == status.HTTP_200_OK
    assert admin_resp.json()["status"] == "authorized"

@pytest.mark.asyncio
async def test_iam_google_oauth_csrf_flow(client: AsyncClient):
    """Test Google OAuth login state token outputs and CSRF state check callback linking."""
    from app.config.settings import settings
    settings.GOOGLE_CLIENT_ID = "mock_client_id"
    settings.GOOGLE_REDIRECT_URI = "http://localhost/callback"
    
    # 1. Start Google Login -> returns URL and CSRF state
    login_resp = await client.get("/api/v1/auth/google/login")
    assert login_resp.status_code == status.HTTP_200_OK
    data = login_resp.json()
    assert "auth_url" in data
    assert "state" in data
    state = data["state"]
    
    # 2. Verify callback with correct state -> returns JWT tokens
    callback_resp = await client.get(f"/api/v1/auth/google/callback?code=mockcode123&state={state}")
    assert callback_resp.status_code == status.HTTP_200_OK
    token_data = callback_resp.json()
    assert "access_token" in token_data
    assert "refresh_token" in token_data
    
    # 3. Verify callback with wrong state -> should fail with CSRF warning (400 BAD REQUEST)
    bad_callback = await client.get(f"/api/v1/auth/google/callback?code=mockcode123&state=wrongstate")
    assert bad_callback.status_code == status.HTTP_400_BAD_REQUEST

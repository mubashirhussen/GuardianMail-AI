import pytest
from httpx import AsyncClient
from datetime import datetime, timezone, timedelta
from app.auth.oauth import GoogleOAuthService
from app.exceptions.custom import AuthError

@pytest.mark.asyncio
async def test_google_config_endpoint(client: AsyncClient):
    """Verify /api/v1/auth/google/config returns public client_id for GIS initialization."""
    response = await client.get("/api/v1/auth/google/config")
    assert response.status_code == 200
    data = response.json()
    assert "client_id" in data
    assert len(data["client_id"]) > 0

@pytest.mark.asyncio
async def test_google_login_authorization_url(client: AsyncClient):
    """
    Verify /api/v1/auth/google/login builds OIDC sign-in URL.
    CRITICAL: Must ONLY request 'openid email profile' scopes and NOT Gmail read scopes.
    """
    response = await client.get("/api/v1/auth/google/login")
    assert response.status_code == 200
    data = response.json()
    assert "auth_url" in data
    assert "accounts.google.com" in data["auth_url"]
    assert "scope=openid" in data["auth_url"]
    assert "gmail.readonly" not in data["auth_url"], "Sign-in URL must NOT request Gmail permissions!"

@pytest.mark.asyncio
async def test_first_time_google_registration(client: AsyncClient):
    """Verify first-time sign-in registers user with verified Google identity and returns session."""
    token = "mock_google_id_token:sub_new_user_101:newanalyst@guardianmail.ai:Alice Security"
    response = await client.post(
        "/api/v1/auth/google/verify-token",
        json={"credential": token}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_new_user"] is True
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["email"] == "newanalyst@guardianmail.ai"
    assert data["user"]["full_name"] == "Alice Security"
    assert data["user"]["google_id"] == "sub_new_user_101"

@pytest.mark.asyncio
async def test_returning_google_user_login(client: AsyncClient):
    """Verify returning user with existing Google sub is authenticated into their account."""
    # Register first
    token = "mock_google_id_token:sub_returning_202:returning@guardianmail.ai:Bob Analyst"
    await client.post("/api/v1/auth/google/verify-token", json={"credential": token})

    # Sign in again with same Google account
    response = await client.post(
        "/api/v1/auth/google/verify-token",
        json={"credential": token}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_new_user"] is False
    assert data["user"]["email"] == "returning@guardianmail.ai"
    assert data["user"]["google_id"] == "sub_returning_202"
    assert "access_token" in data

@pytest.mark.asyncio
async def test_account_linking_by_verified_email(client: AsyncClient):
    """Verify password user is linked when signing in with verified matching Google email."""
    # 1. Register traditional password user
    email = "charlie@guardianmail.ai"
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "StrongPassword123!",
            "full_name": "Charlie Defender",
            "role": "user"
        }
    )

    # 2. Authenticate via Google with same verified email
    token = f"mock_google_id_token:sub_charlie_303:{email}:Charlie Defender"
    response = await client.post(
        "/api/v1/auth/google/verify-token",
        json={"credential": token}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["email"] == email
    assert data["user"]["google_id"] == "sub_charlie_303"

@pytest.mark.asyncio
async def test_account_linking_conflict_prevention(client: AsyncClient):
    """Prevent hijacking: an account linked to Google ID A cannot be claimed by Google ID B."""
    email = "linked_user@guardianmail.ai"
    # Link to Google sub 1
    token1 = f"mock_google_id_token:sub_original_401:{email}:User Original"
    await client.post("/api/v1/auth/google/verify-token", json={"credential": token1})

    # Attempt to sign in with same email but DIFFERENT Google sub 2
    token2 = f"mock_google_id_token:sub_attacker_402:{email}:Attacker"
    response = await client.post(
        "/api/v1/auth/google/verify-token",
        json={"credential": token2}
    )
    assert response.status_code == 409
    assert "already linked to a different Google identity" in response.json()["detail"]

@pytest.mark.asyncio
async def test_invalid_google_token_rejection(client: AsyncClient):
    """Verify invalid token signature is rejected with 401."""
    response = await client.post(
        "/api/v1/auth/google/verify-token",
        json={"credential": "invalid_token"}
    )
    assert response.status_code == 401
    assert "verification failed" in response.json()["detail"]

@pytest.mark.asyncio
async def test_expired_google_token_rejection(client: AsyncClient):
    """Verify expired token is rejected with 401."""
    response = await client.post(
        "/api/v1/auth/google/verify-token",
        json={"credential": "expired_token"}
    )
    assert response.status_code == 401
    assert "expired" in response.json()["detail"]

@pytest.mark.asyncio
async def test_unverified_email_rejection(client: AsyncClient):
    """Verify Google token with unverified email is rejected."""
    response = await client.post(
        "/api/v1/auth/google/verify-token",
        json={"credential": "unverified_email_token"}
    )
    assert response.status_code == 401
    assert "not verified" in response.json()["detail"]

@pytest.mark.asyncio
async def test_audience_mismatch_rejection(client: AsyncClient):
    """Verify Google token with wrong audience is rejected."""
    response = await client.post(
        "/api/v1/auth/google/verify-token",
        json={"credential": "wrong_audience_token"}
    )
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_gmail_permissions_disclosure(client: AsyncClient):
    """Verify /api/v1/gmail/permissions explicitly describes what data is accessed and why."""
    response = await client.get("/api/v1/gmail/permissions")
    assert response.status_code == 200
    data = response.json()
    assert "gmail.readonly" in data["scope"]
    assert len(data["data_accessed"]) > 0
    assert "purpose" in data
    assert "user_control" in data

@pytest.mark.asyncio
async def test_gmail_requires_authentication(client: AsyncClient):
    """Verify accessing Gmail connection endpoints requires active user session."""
    response = await client.get("/api/v1/gmail/auth-url")
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_gmail_connect_and_disconnect_flow(client: AsyncClient):
    """Verify authenticated user can connect and disconnect Gmail independently from sign-in."""
    # 1. Sign in with Google
    token = "mock_google_id_token:sub_gmail_test_501:gtest@guardianmail.ai:Gmail Tester"
    login_res = await client.post("/api/v1/auth/google/verify-token", json={"credential": token})
    access_token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    # 2. Get separate Gmail auth URL
    auth_url_res = await client.get("/api/v1/gmail/auth-url", headers=headers)
    assert auth_url_res.status_code == 200
    assert "gmail.readonly" in auth_url_res.json()["scope"]

    # 3. Connect Gmail account
    connect_res = await client.post(
        "/api/v1/gmail/connect",
        json={"code": "mock_gmail_auth_code_123"},
        headers=headers
    )
    assert connect_res.status_code == 200

    # 4. Check connected accounts
    accounts_res = await client.get("/api/v1/gmail/accounts", headers=headers)
    assert accounts_res.status_code == 200
    assert len(accounts_res.json()) == 1
    assert accounts_res.json()[0]["email"] == "gtest@guardianmail.ai"

    # 5. Disconnect Gmail account
    disconnect_res = await client.delete("/api/v1/gmail/disconnect", headers=headers)
    assert disconnect_res.status_code == 200

    # 6. Check accounts is now empty
    accounts_after = await client.get("/api/v1/gmail/accounts", headers=headers)
    assert len(accounts_after.json()) == 0

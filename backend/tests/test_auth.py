import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_auth_workflow(client: AsyncClient):
    # 1. Register a test user
    email = "analyst@guardianmail.ai"
    password = "VerySecurePassword123!"
    
    register_response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": "SOC Analyst One",
            "role": "soc_analyst"
        }
    )
    assert register_response.status_code == 201
    assert register_response.json()["email"] == email
    assert register_response.json()["role"] == "soc_analyst"

    # 2. Login with correct credentials
    login_response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password
        }
    )
    assert login_response.status_code == 200
    token_data = login_response.json()
    assert "access_token" in token_data
    assert "refresh_token" in token_data
    assert token_data["role"] == "soc_analyst"

    # 3. Test access to protected endpoint
    token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    sessions_response = await client.get("/api/v1/devices/active-sessions", headers=headers)
    assert sessions_response.status_code == 200
    sessions = sessions_response.json()
    assert len(sessions) > 0
    assert sessions[0]["ip_address"] == "127.0.0.1"

    # 4. Login with bad credentials to test lockout counting
    bad_login_response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": "wrongpassword"
        }
    )
    assert bad_login_response.status_code == 400
    assert "attempts remaining" in bad_login_response.json()["detail"]

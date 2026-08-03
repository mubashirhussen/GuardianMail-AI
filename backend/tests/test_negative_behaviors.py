import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_unauthorized_endpoints_without_token(client: AsyncClient):
    """Verify that requesting protected routes without authentication fails with 401."""
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401
    assert "Not authenticated" in resp.json()["detail"]

@pytest.mark.asyncio
async def test_invalid_jwt_token_claims(client: AsyncClient):
    """Verify that passing an invalid or spoofed JWT token yields 401 unauthorized status."""
    headers = {"Authorization": "Bearer InvalidSpoofedTokenString123"}
    resp = await client.get("/api/v1/auth/me", headers=headers)
    print(f"DEBUG AUTH: {resp.status_code} - {resp.text}")
    assert resp.status_code == 401
    assert "Invalid authorization token" in resp.text or "Could not validate credentials" in resp.text

@pytest.mark.asyncio
async def test_request_payload_limit_middleware(client: AsyncClient):
    """Verify that ContentLengthLimitMiddleware blocks request payloads exceeding 10MB."""
    # Generate 11MB string
    large_payload = "A" * (11 * 1024 * 1024)
    
    headers = {
        "Authorization": "Bearer AnyTokenWillBeBlockedByMiddlewareBeforeVerification",
        "Content-Length": str(len(large_payload))
    }
    
    resp = await client.post(
        "/api/v1/auth/register",
        content=large_payload,
        headers=headers
    )
    print(f"DEBUG LIMIT: {resp.status_code} - {resp.text}")
    assert resp.status_code == 413
    assert "Payload Too Large" in resp.text

@pytest.mark.asyncio
async def test_invalid_email_format_registration(client: AsyncClient):
    """Verify Pydantic schema validation rejects registration with malformed emails."""
    resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "not-an-email",
            "password": "ValidSecurePassword2026!",
            "full_name": "QA Tester",
            "role": "user"
        }
    )
    assert resp.status_code == 422
    errors = resp.json()["detail"]
    assert any(err["loc"] == ["body", "email"] for err in errors)

@pytest.mark.asyncio
async def test_unsupported_file_extension(client: AsyncClient):
    """Verify that uploading a file with an unsupported extension yields a 400 Bad Request."""
    # Register and login to get auth token
    email = "qa_files@guardianmail.ai"
    password = "SecurePassword2026!"
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "full_name": "QA Files User", "role": "user"}
    )
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password}
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    files = {"file": ("malicious.exe", b"fake binary payload content", "application/octet-stream")}
    resp = await client.post(
        "/api/v1/attachments/analyze",
        files=files,
        headers=headers
    )
    assert resp.status_code == 400
    assert "Unsupported file type extension" in resp.json()["detail"]

@pytest.mark.asyncio
async def test_double_extension_rejection(client: AsyncClient):
    """Verify that uploading a file with a double extension (e.g. malicious.png.exe) yields a 400 Bad Request."""
    email = "qa_files@guardianmail.ai"
    password = "SecurePassword2026!"
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password}
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    files = {"file": ("exploit.png.exe", b"fake malicious double ext script", "application/x-msdownload")}
    resp = await client.post(
        "/api/v1/attachments/analyze",
        files=files,
        headers=headers
    )
    assert resp.status_code == 400
    assert "Double extension validation failed" in resp.json()["detail"]


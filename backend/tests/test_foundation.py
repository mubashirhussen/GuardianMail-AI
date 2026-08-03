import pytest
from httpx import AsyncClient
from app.config.settings import settings
from app.security.password import hash_password, verify_password
from app.security.jwt import create_access_token, create_refresh_token, decode_token
from app.exceptions.custom import TokenExpiredError, AuthError

def test_settings_validation():
    """Verify settings properties format validations."""
    assert settings.PROJECT_NAME == "GuardianMail AI"
    assert settings.API_V1_STR == "/api/v1"
    assert settings.ENVIRONMENT in ["development", "testing", "production"]

def test_password_security_helpers():
    """Test passlib-bcrypt password hashing and verify check utilities."""
    passwd = "SuperSecurePassword123!"
    hashed = hash_password(passwd)
    assert hashed != passwd
    assert verify_password(passwd, hashed)
    assert not verify_password("WrongPassword", hashed)

def test_jwt_tokens_generation_and_decoding():
    """Test Jose JWT encoder/decoder helpers for Access and Refresh tokens."""
    subject = "user_test_identifier_123"
    access_token = create_access_token(subject)
    refresh_token = create_refresh_token(subject)
    
    # Validate decoding access token
    access_payload = decode_token(access_token)
    assert access_payload["sub"] == subject
    assert access_payload["type"] == "access"
    
    # Validate decoding refresh token
    refresh_payload = decode_token(refresh_token)
    assert refresh_payload["sub"] == subject
    assert refresh_payload["type"] == "refresh"

@pytest.mark.asyncio
async def test_health_endpoints(client: AsyncClient):
    """Test health foundation API routes."""
    # 1. Main health check
    health_resp = await client.get("/api/v1/health")
    assert health_resp.status_code == 200
    json_data = health_resp.json()
    assert json_data["status"] == "healthy"
    assert "mongodb" in json_data["services"]
    assert "redis" in json_data["services"]
    
    # 2. Liveness check
    live_resp = await client.get("/api/v1/health/liveness")
    assert live_resp.status_code == 200
    assert live_resp.json()["status"] == "alive"
    
    # 3. Readiness check
    ready_resp = await client.get("/api/v1/health/readiness")
    assert ready_resp.status_code == 200
    assert ready_resp.json()["status"] == "ready"
    
    # 4. Version check
    ver_resp = await client.get("/api/v1/version")
    assert ver_resp.status_code == 200
    assert "version" in ver_resp.json()
    assert ver_resp.json()["api_version"] == "v1"

@pytest.mark.asyncio
async def test_security_headers_middleware(client: AsyncClient):
    """Check standard OWASP security headers injection checks on root endpoint."""
    resp = await client.get("/")
    assert resp.status_code == 200
    
    # Injected Security headers
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-XSS-Protection") == "1; mode=block"
    assert resp.headers.get("Referrer-Policy") == "no-referrer"
    assert "Content-Security-Policy" in resp.headers
    assert "X-Request-ID" in resp.headers

@pytest.mark.asyncio
async def test_global_exceptions_middleware(client: AsyncClient):
    """Test exception handlers middleware returns structured error response formatting."""
    # Access endpoint raising ValueError to trigger exception handler middleware
    resp = await client.get("/api/v1/health/error-trigger")
    assert resp.status_code == 500
    json_data = resp.json()
    assert json_data["success"] is False
    assert json_data["code"] == "INTERNAL_SERVER_ERROR"
    assert "request_id" in json_data

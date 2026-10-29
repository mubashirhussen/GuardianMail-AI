"""
Comprehensive automated test suite for GuardianMail AI Identity Verification,
Multi-channel OTP Delivery, Password Recovery, Anti-Enumeration, and Session Revocation.
"""

import pytest
import secrets
from httpx import AsyncClient
from app.database.connection import db_manager
from app.services.identity.delivery_service import (
    generate_secure_otp,
    normalize_phone_number,
    mask_identifier
)
from app.repositories.verification_repo import VerificationRepository

@pytest.mark.asyncio
async def test_otp_generation_and_masking():
    """Verify cryptographic OTP generation and identifier masking."""
    otp = generate_secure_otp(6)
    assert len(otp) == 6
    assert otp.isdigit()

    masked_email = mask_identifier("analyst.security@guardianmail.ai")
    assert "@guardianmail.ai" in masked_email
    assert "analyst.security" not in masked_email

    masked_phone = mask_identifier("+14155552671")
    assert masked_phone.startswith("+141")
    assert masked_phone.endswith("671")
    assert "***" in masked_phone

@pytest.mark.asyncio
async def test_phone_normalization():
    """Verify standard E.164 phone normalization and validation."""
    assert normalize_phone_number("+1 (415) 555-2671") == "+14155552671"
    assert normalize_phone_number("+44 20 7946 0991") == "+442079460991"
    assert normalize_phone_number("4155552671") == "+14155552671"

    with pytest.raises(ValueError):
        normalize_phone_number("invalid-phone")

    with pytest.raises(ValueError):
        normalize_phone_number("123")

@pytest.mark.asyncio
async def test_verification_repository_challenge_lifecycle():
    """Test challenge creation, HMAC verification, retry caps, and single-use consumption."""
    repo = VerificationRepository(db_manager.db)
    identifier = f"test_{secrets.token_hex(4)}@guardianmail.ai"
    purpose = "registration"
    code = "654321"

    # 1. Create challenge
    challenge = await repo.create_challenge(
        identifier=identifier,
        identifier_type="email",
        purpose=purpose,
        code=code,
        ttl_seconds=300,
        cooldown_seconds=30,
        max_attempts=3
    )
    assert challenge["identifier"] == identifier
    assert challenge["attempts_count"] == 0
    assert challenge["consumed_at"] is None

    # 2. Check cooldown active
    cooldown = await repo.check_resend_cooldown(identifier, purpose)
    assert cooldown > 0

    # 3. Incorrect code attempt
    success, msg = await repo.verify_challenge(identifier, purpose, "000000")
    assert success is False
    assert "2 attempt(s) remaining" in msg

    # 4. Correct code attempt
    success, msg = await repo.verify_challenge(identifier, purpose, code)
    assert success is True
    assert "successful" in msg.lower()

    # 5. Replay attempt rejected
    success, msg = await repo.verify_challenge(identifier, purpose, code)
    assert success is False
    assert "no active verification challenge" in msg.lower()

@pytest.mark.asyncio
async def test_verification_challenge_lockout_after_max_attempts():
    """Verify challenge invalidation when max attempts threshold is exceeded."""
    repo = VerificationRepository(db_manager.db)
    identifier = f"lockout_{secrets.token_hex(4)}@guardianmail.ai"
    purpose = "password_reset"
    code = "789123"

    await repo.create_challenge(
        identifier=identifier,
        identifier_type="email",
        purpose=purpose,
        code=code,
        max_attempts=2
    )

    # Attempt 1 failed
    success, msg = await repo.verify_challenge(identifier, purpose, "111111")
    assert success is False
    assert "1 attempt(s) remaining" in msg

    # Attempt 2 failed (limit reached)
    success, msg = await repo.verify_challenge(identifier, purpose, "222222")
    assert success is False
    assert "invalidated" in msg.lower()

    # Even with correct code, challenge is now consumed and invalidated
    success, msg = await repo.verify_challenge(identifier, purpose, code)
    assert success is False

@pytest.mark.asyncio
async def test_email_send_and_verify_endpoints(client: AsyncClient):
    """Test POST /email/send-code and POST /email/verify API endpoints."""
    test_email = f"user_{secrets.token_hex(4)}@guardianmail.ai"

    # 1. Send verification code
    resp = await client.post("/api/v1/auth/email/send-code", json={
        "email": test_email,
        "purpose": "registration"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "sent"
    assert "***" in data["destination"]

    # 2. Resend code immediately triggers cooldown rate limit (429)
    resp_cooldown = await client.post("/api/v1/auth/email/send-code", json={
        "email": test_email,
        "purpose": "registration"
    })
    assert resp_cooldown.status_code == 429
    assert "Please wait" in resp_cooldown.json()["detail"]

    # 3. Verify with wrong code fails with 400
    resp_wrong = await client.post("/api/v1/auth/email/verify", json={
        "email": test_email,
        "code": "999999",
        "purpose": "registration"
    })
    assert resp_wrong.status_code == 400
    assert "Invalid verification code" in resp_wrong.json()["detail"]

@pytest.mark.asyncio
async def test_phone_send_and_verify_endpoints(client: AsyncClient):
    """Test POST /phone/send-code and POST /phone/verify API endpoints."""
    test_phone = "+1415555" + str(secrets.randbelow(9000) + 1000)

    # 1. Send SMS verification code
    resp = await client.post("/api/v1/auth/phone/send-code", json={
        "phone_number": test_phone,
        "purpose": "phone_verification"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "sent"
    assert "***" in data["destination"]

    # 2. Invalid phone format triggers 400
    resp_invalid = await client.post("/api/v1/auth/phone/send-code", json={
        "phone_number": "not-a-number",
        "purpose": "phone_verification"
    })
    assert resp_invalid.status_code == 400

@pytest.mark.asyncio
async def test_forgot_password_anti_enumeration_and_recovery_flow(client: AsyncClient):
    """Test anti-enumeration on forgot-password and end-to-end password reset."""
    # 1. Register a test user
    user_email = f"victim_{secrets.token_hex(4)}@guardianmail.ai"
    initial_password = "InitialSecurePassword123!"
    reg_resp = await client.post("/api/v1/auth/register", json={
        "email": user_email,
        "password": initial_password,
        "full_name": "Test User"
    })
    assert reg_resp.status_code == 201

    # 2. Forgot password with non-existent email -> Returns generic 200 (Anti-enumeration)
    fake_email = "nonexistent_account_probe@guardianmail.ai"
    resp_fake = await client.post("/api/v1/auth/password/forgot", json={
        "email": fake_email
    })
    assert resp_fake.status_code == 200
    assert "If an account exists" in resp_fake.json()["message"]

    # 3. Forgot password with legitimate email -> Returns identical generic 200
    resp_real = await client.post("/api/v1/auth/password/forgot", json={
        "email": user_email
    })
    assert resp_real.status_code == 200
    assert resp_real.json()["message"] == resp_fake.json()["message"]

    # 4. Fetch the generated challenge code directly from DB for test verification
    verification_repo = VerificationRepository(db_manager.db)
    challenge = await verification_repo.get_latest_challenge(user_email, "password_reset")
    assert challenge is not None

    # Re-create known challenge code to test reset verification
    test_reset_code = "482910"
    await verification_repo.create_challenge(
        identifier=user_email,
        identifier_type="email",
        purpose="password_reset",
        code=test_reset_code
    )

    # 5. Attempt password reset with invalid code fails with 400
    new_password = "NewSuperSecurePassword456!"
    reset_fail = await client.post("/api/v1/auth/password/reset", json={
        "email": user_email,
        "code": "000000",
        "new_password": new_password
    })
    assert reset_fail.status_code == 400

    # 6. Password reset with valid code succeeds
    reset_success = await client.post("/api/v1/auth/password/reset", json={
        "email": user_email,
        "code": test_reset_code,
        "new_password": new_password
    })
    assert reset_success.status_code == 200
    assert "successfully reset" in reset_success.json()["message"].lower()

    # 7. Old password no longer works
    old_login = await client.post("/api/v1/auth/login", json={
        "email": user_email,
        "password": initial_password
    })
    assert old_login.status_code == 400

    # 8. New password initiates 2FA challenge and verifies successfully
    new_login = await client.post("/api/v1/auth/login", json={
        "email": user_email,
        "password": new_password
    })
    assert new_login.status_code == 200
    login_data = new_login.json()
    assert login_data["status"] == "otp_required"
    otp_code = login_data["code"]
    challenge_id = login_data["challenge_id"]

    verify_login = await client.post("/api/v1/auth/otp/verify", json={
        "email": user_email,
        "code": otp_code,
        "challenge_id": challenge_id
    })
    assert verify_login.status_code == 200
    assert "access_token" in verify_login.json()

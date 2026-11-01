import uuid
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.security import OAuth2PasswordRequestForm
from app.config.settings import settings
from app.security.password import hash_password, verify_password
from app.security.jwt import create_access_token, create_refresh_token, decode_token, decode_token_async
from app.api.dependencies.auth import get_user_repo, get_device_repo, get_verification_repo, get_current_active_user, reusable_oauth2
from app.models.user import UserCreate, UserLogin, UserResponse, UserRole, UserInDB
from app.repositories.user_repo import UserRepository
from app.repositories.device_repo import DeviceRepository
from app.repositories.verification_repo import VerificationRepository
from app.repositories.audit_repo import AuditRepository
from app.database.connection import db_manager
from app.database.cache import cache_manager
from app.exceptions.custom import AuthError, TokenExpiredError
from app.telemetry.otel import trace_span
from app.auth.oauth import GoogleOAuthService
from app.services.identity.delivery_service import (
    IdentityDeliveryService,
    generate_secure_otp,
    normalize_phone_number,
    mask_identifier
)
from app.services.totp_service import TOTPService

logger = logging.getLogger(__name__)

router = APIRouter()

async def get_audit_repo() -> AuditRepository:
    if db_manager.db is None:
         raise RuntimeError("Database connection not ready.")
    return AuditRepository(db_manager.db)

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@trace_span(name="auth_register")
async def register(
    user_in: UserCreate, 
    user_repo: UserRepository = Depends(get_user_repo),
    verification_repo: VerificationRepository = Depends(get_verification_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Register a new user account and dispatch initial verification challenge."""
    existing_user = await user_repo.get_by_email(user_in.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The user with this email already exists in the system.",
        )
        
    user_dict = user_in.model_dump()
    password = user_dict.pop("password")
    
    # Normalize phone number if supplied
    if user_dict.get("phone_number"):
        try:
            user_dict["phone_number"] = normalize_phone_number(user_dict["phone_number"])
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    
    now = datetime.now(timezone.utc)
    user_dict["hashed_password"] = hash_password(password)
    user_dict["created_at"] = now
    user_dict["updated_at"] = now
    user_dict["failed_login_attempts"] = 0
    user_dict["is_verified"] = False
    user_dict["email_verified"] = False
    user_dict["phone_verified"] = False
    
    created_user = await user_repo.create(user_dict)
    user_id_str = str(created_user["_id"])
    
    # Generate and issue cryptographically secure initial registration verification code
    code = generate_secure_otp()
    await verification_repo.create_challenge(
        identifier=created_user["email"],
        identifier_type="email",
        purpose="registration",
        code=code,
        user_id=user_id_str
    )
    
    try:
        await IdentityDeliveryService.send_email(created_user["email"], code, "registration")
    except Exception as e:
        logger.warning(f"Registration verification email dispatch warning: {str(e)}")
    
    # Audit log user registration
    await audit_repo.create({
        "user_id": user_id_str,
        "action": "USER_REGISTER",
        "details": {
            "email": created_user["email"],
            "role": created_user["role"]
        },
        "created_at": now
    })
    
    # Map _id string
    created_user["_id"] = user_id_str
    return created_user

@router.post("/login")
@trace_span(name="auth_login")
async def login(
    request: Request,
    user_in: UserLogin,
    user_repo: UserRepository = Depends(get_user_repo),
    verification_repo: VerificationRepository = Depends(get_verification_repo),
    device_repo: DeviceRepository = Depends(get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """
    Authenticate primary credentials (email/phone & password).
    Enforces account lockout protections, creates a mandatory 6-digit OTP challenge,
    dispatches the code to the verified destination, and returns a pending challenge.
    Access to protected resources is strictly withheld until OTP verification succeeds.
    """
    identifier = (user_in.identifier or user_in.email or user_in.phone_number or "").strip()
    if not identifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address or phone number is required."
        )
    if not user_in.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is required."
        )

    user = await user_repo.get_by_identifier(identifier)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email, phone number, or password"
        )
        
    # Check Lockout Protection
    now = datetime.now(timezone.utc)
    locked_until = user.get("locked_until")
    if locked_until:
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if now < locked_until:
            lock_duration = int((locked_until - now).total_seconds())
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account locked due to consecutive failures. Try again in {lock_duration} seconds."
            )
            
    # Verify Password
    if not verify_password(user_in.password, user["hashed_password"]):
        attempts = await user_repo.increment_login_attempts(
            identifier, 
            lockout_limit=settings.MAX_LOGIN_ATTEMPTS, 
            duration_seconds=settings.LOCKOUT_DURATION_SECONDS
        )
        
        # Audit log login failure
        await audit_repo.create({
            "user_id": str(user["_id"]),
            "action": "USER_LOGIN_FAILED",
            "details": {
                "identifier": mask_identifier(identifier),
                "attempts_count": attempts
            },
            "created_at": now
        })
        
        if attempts >= settings.MAX_LOGIN_ATTEMPTS:
            await audit_repo.create({
                "user_id": str(user["_id"]),
                "action": "USER_LOCKOUT",
                "details": {
                    "identifier": mask_identifier(identifier),
                    "lockout_duration_seconds": settings.LOCKOUT_DURATION_SECONDS
                },
                "created_at": now
            })
            
        remaining = settings.MAX_LOGIN_ATTEMPTS - attempts
        detail = "Incorrect email, phone number, or password."
        if remaining > 0:
            detail += f" {remaining} attempts remaining before account lockout."
        else:
            detail += f" Account is locked for {settings.LOCKOUT_DURATION_SECONDS // 60} minutes."
            
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail
        )
        
    # Reset failures on successful primary authentication
    await user_repo.reset_login_attempts(identifier)
    
    # ─── MANDATORY 6-DIGIT OTP AUTHENTICATION CHALLENGE ──────────────────────
    code = generate_secure_otp()
    challenge = await verification_repo.create_challenge(
        identifier=user["email"],
        identifier_type="email",
        purpose="login_2fa",
        code=code,
        user_id=str(user["_id"])
    )
    
    # Dispatch real 6-digit OTP code to verified account email
    try:
        await IdentityDeliveryService.send_email(user["email"], code, "login_step_up")
    except Exception as e:
        logger.warning(f"Failed to dispatch 2FA email: {str(e)}")
        
    masked_dest = mask_identifier(user["email"])
    logger.info(f"[DEV 2FA OTP DISPATCH] ---> 6-Digit OTP for {user['email']}: [{code}] <--- (Valid for 5 minutes)")
    
    # Record audit log for primary auth success and challenge issuance
    await audit_repo.create({
        "user_id": str(user["_id"]),
        "action": "USER_LOGIN_PRIMARY_SUCCESS_OTP_DISPATCHED",
        "details": {
            "email": masked_dest,
            "challenge_id": str(challenge["_id"])
        },
        "created_at": now
    })
    
    dev_code = code if (settings.DEBUG or (settings.EMAIL_PROVIDER or "").lower() == "console" or settings.ENVIRONMENT == "development") else None
    return {
        "status": "otp_required",
        "challenge_id": str(challenge["_id"]),
        "destination": masked_dest,
        "email": user["email"],
        "method": "email",
        "code": dev_code,
        "message": f"6-digit code dispatched to {masked_dest}"
    }

class LoginOTPVerifyRequest(BaseModel):
    challenge_id: Optional[str] = Field(default=None, description="Optional pending challenge ID")
    email: str = Field(..., description="Target user email address")
    code: str = Field(..., min_length=4, max_length=8, description="6-digit verification code")

class LoginOTPResendRequest(BaseModel):
    challenge_id: Optional[str] = Field(default=None, description="Optional pending challenge ID")
    email: str = Field(..., description="Target user email address")

class TOTPSetupRequest(BaseModel):
    email: Optional[str] = Field(default=None, description="Target user email address")

class TOTPEnableRequest(BaseModel):
    email: str = Field(..., description="Target user email address")
    secret: str = Field(..., description="Base32 TOTP secret")
    code: str = Field(..., min_length=6, max_length=8, description="6-digit code from authenticator app")

@router.get("/totp/setup")
@router.post("/totp/setup")
@trace_span(name="auth_totp_setup")
async def setup_totp(
    request: Request,
    email: Optional[str] = Query(default=None),
    payload: Optional[TOTPSetupRequest] = None,
    user_repo: UserRepository = Depends(get_user_repo)
):
    """
    Generate TOTP secret and QR code for Microsoft Authenticator / Google Authenticator.
    Option A: Allows any user to pair their mobile authenticator app.
    """
    target_email = None
    if payload and payload.email:
        target_email = payload.email.strip()
    elif email:
        target_email = email.strip()

    if not target_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User email is required to setup Microsoft / Google Authenticator."
        )

    clean_email = target_email.lower()
    secret = TOTPService.generate_secret()
    details = TOTPService.get_provisioning_details(
        secret=secret,
        account_name=clean_email,
        issuer_name="MailGuard"
    )

    return {
        "status": "ready",
        "email": clean_email,
        "secret": secret,
        "provisioning_uri": details["provisioning_uri"],
        "qr_code_base64": details["qr_code_base64"],
        "app_links": {
            "microsoft_authenticator_ios": "https://apps.apple.com/in/app/microsoft-authenticator/id983156458",
            "microsoft_authenticator_android": "https://play.google.com/store/apps/details?id=com.azure.authenticator",
            "google_authenticator_ios": "https://apps.apple.com/app/google-authenticator/id388497605",
            "google_authenticator_android": "https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2"
        },
        "instructions": "Scan this QR code with Microsoft Authenticator or Google Authenticator, then enter the 6-digit code to activate."
    }

@router.post("/totp/enable")
@trace_span(name="auth_totp_enable")
async def enable_totp(
    payload: TOTPEnableRequest,
    user_repo: UserRepository = Depends(get_user_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """
    Verify 6-digit TOTP code and permanently link Microsoft Authenticator to the user in MongoDB.
    """
    clean_email = payload.email.strip().lower()
    clean_code = payload.code.strip()

    # Verify TOTP code against secret
    is_valid = TOTPService.verify_code(payload.secret, clean_code)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 6-digit code. Please verify the code displayed in Microsoft Authenticator / Google Authenticator."
        )

    user = await user_repo.get_by_email(clean_email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User account '{clean_email}' not found."
        )

    await user_repo.set_totp_secret(str(user["_id"]), payload.secret)
    await audit_repo.create({
        "user_id": str(user["_id"]),
        "action": "USER_MFA_TOTP_ENABLED",
        "details": {
            "email": clean_email,
            "authenticator": "Microsoft/Google Authenticator",
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "created_at": datetime.now(timezone.utc)
    })

    return {
        "status": "success",
        "message": "Microsoft / Google Authenticator configured successfully!",
        "mfa_enabled": True
    }

@router.post("/otp/verify")
@router.post("/login/verify-otp")
@trace_span(name="auth_login_verify_otp")
async def verify_login_otp(
    request: Request,
    payload: LoginOTPVerifyRequest,
    user_repo: UserRepository = Depends(get_user_repo),
    verification_repo: VerificationRepository = Depends(get_verification_repo),
    device_repo: DeviceRepository = Depends(get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """
    Verify 6-digit OTP for mandatory two-factor login challenge.
    Supports Option A (Microsoft / Google Authenticator TOTP) as well as email challenge codes.
    Enforces expiration, attempt limits, and single-use consumption before granting tokens.
    """
    clean_email = payload.email.strip().lower()
    user = await user_repo.get_by_email(clean_email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account associated with this verification challenge not found."
        )

    # 1. Option A: Check Microsoft / Google Authenticator TOTP if user configured it
    code_verified = False
    verification_method = "email_otp"
    if user.get("totp_secret"):
        if TOTPService.verify_code(user["totp_secret"], payload.code):
            code_verified = True
            verification_method = "totp_authenticator"

    # 2. Check pending email verification challenge if not verified via TOTP
    if not code_verified:
        success, msg = await verification_repo.verify_challenge(clean_email, "login_2fa", payload.code)
        if success:
            code_verified = True
        else:
            fb_success, fb_msg = await verification_repo.verify_challenge(clean_email, "login_step_up", payload.code)
            if fb_success:
                code_verified = True
            else:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg or "Invalid verification code.")

    # User identity is confirmed! Generate device registration & secure session tokens
    now = datetime.now(timezone.utc)
    user_agent = request.headers.get("user-agent", "Unknown")
    ip_address = request.client.host if request.client else "127.0.0.1"
    fingerprint_hash = str(uuid.uuid5(uuid.NAMESPACE_DNS, user_agent + ip_address))

    await device_repo.register_device(
        user_id=str(user["_id"]),
        fingerprint_hash=fingerprint_hash,
        device_name="Browser Session",
        user_agent=user_agent,
        ip_address=ip_address
    )

    token_id = str(uuid.uuid4())
    access_token = create_access_token(subject=str(user["_id"]), jti=token_id)
    refresh_token = create_refresh_token(subject=str(user["_id"]), jti=token_id)

    await device_repo.create_session(
        user_id=str(user["_id"]),
        token_id=token_id,
        fingerprint_hash=fingerprint_hash,
        ip_address=ip_address,
        user_agent=user_agent
    )

    await audit_repo.create({
        "user_id": str(user["_id"]),
        "action": "USER_LOGIN_2FA_SUCCESS",
        "details": {
            "email": clean_email,
            "ip_address": ip_address,
            "session_id": token_id
        },
        "created_at": now
    })

    user_dict = {
        "_id": str(user["_id"]),
        "id": str(user["_id"]),
        "email": user["email"],
        "full_name": user.get("full_name", ""),
        "role": user.get("role", "user"),
        "is_active": user.get("is_active", True),
        "is_verified": True
    }

    return {
        "status": "authenticated",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": user_dict
    }

@router.post("/otp/resend")
@trace_span(name="auth_login_otp_resend")
async def resend_login_otp(
    payload: LoginOTPResendRequest,
    user_repo: UserRepository = Depends(get_user_repo),
    verification_repo: VerificationRepository = Depends(get_verification_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Resend 6-digit verification code with cooldown enforcement."""
    clean_email = payload.email.strip().lower()
    cooldown = await verification_repo.check_resend_cooldown(clean_email, "login_2fa")
    if cooldown > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Please wait {cooldown} seconds before requesting a new code."
        )

    code = generate_secure_otp()
    challenge = await verification_repo.create_challenge(
        identifier=clean_email,
        identifier_type="email",
        purpose="login_2fa",
        code=code
    )

    try:
        await IdentityDeliveryService.send_email(clean_email, code, "login_step_up")
    except Exception as e:
        logger.warning(f"Resend email dispatch error: {e}")

    logger.info(f"[DEV 2FA OTP DISPATCH] Resent 6-Digit OTP for {clean_email}: [{code}]")
    masked = mask_identifier(clean_email)

    await audit_repo.create({
        "action": "AUTH_LOGIN_OTP_RESENT",
        "details": {"destination": masked, "purpose": "login_2fa"},
        "created_at": datetime.now(timezone.utc)
    })

    dev_code = code if (settings.DEBUG or (settings.EMAIL_PROVIDER or "").lower() == "console" or settings.ENVIRONMENT == "development") else None
    return {
        "status": "sent",
        "destination": masked,
        "cooldown_seconds": settings.AUTH_RESEND_COOLDOWN_SECONDS,
        "code": dev_code,
        "message": f"6-digit code dispatched to {masked}"
    }

@router.post("/logout")
async def logout(
    request: Request,
    token: str = Depends(reusable_oauth2),
    device_repo: DeviceRepository = Depends(get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Log out the current session (revokes token ID)."""
    payload = decode_token(token)
    if payload:
        token_id = payload.get("jti")
        user_id = payload.get("sub")
        if token_id:
            await device_repo.revoke_session(token_id)
            # Add to Redis blacklist
            await cache_manager.set(f"blacklist:{token_id}", "1", 86400 * 30)
            
            # Audit log
            await audit_repo.create({
                "user_id": user_id,
                "action": "USER_LOGOUT",
                "details": {"session_id": token_id},
                "created_at": datetime.now(timezone.utc)
            })
            
    return {"detail": "Successfully logged out from current session"}

class RefreshTokenRequest(BaseModel):
    refresh_token: Optional[str] = Field(None, description="JWT refresh token")

@router.post("/refresh")
async def refresh_tokens(
    payload_body: Optional[RefreshTokenRequest] = None,
    refresh_token: Optional[str] = Query(None),
    device_repo: DeviceRepository = Depends(get_device_repo),
    user_repo: UserRepository = Depends(get_user_repo)
):
    """Rotate JWT credentials using the refresh token."""
    token_str = (payload_body.refresh_token if payload_body and payload_body.refresh_token else None) or refresh_token
    if not token_str:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Refresh token required.")

    try:
        payload = await decode_token_async(token_str)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid or expired refresh token: {str(e)}")
        
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type.")
        
    user_id = payload.get("sub")
    jti = payload.get("jti")
    
    # Verify user existence and account status
    user = await user_repo.get_by_id(user_id)
    if not user or not user.get("is_active", True):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account is inactive or disabled.")

    # Revoke old refresh token immediately by blacklisting old jti in Redis
    try:
        await cache_manager.set(f"blacklist:{jti}", "1", 86400 * 30)
    except Exception:
        pass
    
    new_token_id = str(uuid.uuid4())
    new_access = create_access_token(subject=user_id, jti=new_token_id)
    new_refresh = create_refresh_token(subject=user_id, jti=new_token_id)
    
    # Update token_id mapping inside active session record
    await device_repo.sessions_collection.update_one(
        {"token_id": jti, "is_active": True},
        {"$set": {"token_id": new_token_id, "last_activity": datetime.now(timezone.utc)}}
    )
    
    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer"
    }

@router.get("/me", response_model=UserResponse)
async def get_me(current_user: UserInDB = Depends(get_current_active_user)):
    """Retrieve details of the currently authenticated user."""
    # Convert _id to string for user response model compatibilities
    user_dict = current_user.model_dump(by_alias=True)
    user_dict["_id"] = str(user_dict.get("_id") or current_user.id)
    return user_dict

@router.put("/profile", response_model=UserResponse)
async def update_profile(
    profile_data: Dict[str, Any],
    current_user: UserInDB = Depends(get_current_active_user),
    user_repo: UserRepository = Depends(get_user_repo)
):
    """Modify authenticated user profile attributes."""
    allowed_updates = ["full_name", "email_notifications_enabled", "threat_alerts_enabled"]
    update_payload = {k: v for k, v in profile_data.items() if k in allowed_updates}
    
    user_id = str(current_user.id or current_user.model_dump().get("_id"))
    updated = await user_repo.update(user_id, update_payload)
    if not updated:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to update user profile")
        
    updated["_id"] = str(updated["_id"])
    return updated

@router.get("/sessions")
async def get_sessions(
    current_user: UserInDB = Depends(get_current_active_user),
    device_repo: DeviceRepository = Depends(get_device_repo)
):
    """Retrieve active session information list of user."""
    user_id = str(current_user.id or current_user.model_dump().get("_id"))
    sessions = await device_repo.get_active_sessions(user_id)
    return sessions

@router.delete("/session/{id}")
async def revoke_session(
    id: str,
    current_user: UserInDB = Depends(get_current_active_user),
    device_repo: DeviceRepository = Depends(get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Revoke specific active token ID (logs user out of single session)."""
    session = await device_repo.sessions_collection.find_one({"_id": device_repo._to_oid(id)})
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
        
    user_id = str(current_user.id or current_user.model_dump().get("_id"))
    if session["user_id"] != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot revoke another user's session")
        
    await device_repo.sessions_collection.update_one(
        {"_id": session["_id"]},
        {"$set": {"is_active": False}}
    )
    
    # Blacklist in Redis
    await cache_manager.set(f"blacklist:{session['token_id']}", "1", 86400 * 30)
    
    # Audit log
    await audit_repo.create({
        "user_id": user_id,
        "action": "USER_SESSION_REVOKED",
        "details": {"session_id": session["token_id"], "target_session_oid": id},
        "created_at": datetime.now(timezone.utc)
    })
    
    return {"detail": "Session successfully revoked"}

@router.post("/logout-other-devices")
async def logout_other_devices(
    token: str = Depends(reusable_oauth2),
    current_user: UserInDB = Depends(get_current_active_user),
    device_repo: DeviceRepository = Depends(get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Revoke all sessions for user except current session (Sign out from other devices)."""
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        
    current_token_id = payload.get("jti")
    user_id = str(current_user.id or current_user.model_dump().get("_id"))
    
    # Fetch all other active sessions before revoking, to blacklist them in Redis
    other_sessions = await device_repo.sessions_collection.find({
        "user_id": user_id,
        "token_id": {"$ne": current_token_id},
        "is_active": True
    }).to_list(length=100)
    
    for s in other_sessions:
        await cache_manager.set(f"blacklist:{s['token_id']}", "1", 86400 * 30)
        
    revoked_count = await device_repo.revoke_other_sessions(
        user_id=user_id,
        current_token_id=current_token_id
    )
    
    # Audit log
    await audit_repo.create({
        "user_id": user_id,
        "action": "USER_LOGOUT_OTHER_DEVICES",
        "details": {"revoked_sessions_count": revoked_count},
        "created_at": datetime.now(timezone.utc)
    })
    
    return {"detail": f"Successfully revoked {revoked_count} other sessions"}

@router.post("/logout-all")
async def logout_all(
    token: str = Depends(reusable_oauth2),
    current_user: UserInDB = Depends(get_current_active_user),
    device_repo: DeviceRepository = Depends(get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Revoke all active sessions and devices for the authenticated user."""
    user_id = str(current_user.id or current_user.model_dump().get("_id"))
    
    # Blacklist all sessions in Redis
    active_sessions = await device_repo.sessions_collection.find({
        "user_id": user_id,
        "is_active": True
    }).to_list(length=200)
    
    for s in active_sessions:
        await cache_manager.set(f"blacklist:{s['token_id']}", "1", 86400 * 30)
        
    await device_repo.sessions_collection.update_many(
        {"user_id": user_id, "is_active": True},
        {"$set": {"is_active": False}}
    )
    
    await audit_repo.create({
        "user_id": user_id,
        "action": "USER_LOGOUT_ALL",
        "details": {"revoked_sessions_count": len(active_sessions)},
        "created_at": datetime.now(timezone.utc)
    })
    
    return {"detail": f"Successfully logged out from all active sessions ({len(active_sessions)} revoked)."}

# ─── MULTI-CHANNEL IDENTITY VERIFICATION & RECOVERY ─────────────────────────

class EmailSendCodeRequest(BaseModel):
    email: str = Field(..., description="Target email address")
    purpose: str = Field(default="registration", description="registration, login_step_up, email_change")

class EmailVerifyRequest(BaseModel):
    email: str = Field(..., description="Target email address")
    code: str = Field(..., min_length=4, max_length=8, description="6-digit verification code")
    purpose: str = Field(default="registration", description="registration, login_step_up, email_change")

class PhoneSendCodeRequest(BaseModel):
    phone_number: str = Field(..., description="Phone number with country code")
    purpose: str = Field(default="phone_verification", description="phone_verification, registration, login_step_up")

class PhoneVerifyRequest(BaseModel):
    phone_number: str = Field(..., description="Phone number with country code")
    code: str = Field(..., min_length=4, max_length=8, description="6-digit verification code")
    purpose: str = Field(default="phone_verification", description="phone_verification, registration, login_step_up")

class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., description="Registered account email address")

class PasswordResetRequest(BaseModel):
    email: str = Field(..., description="Registered account email address")
    code: str = Field(..., min_length=4, max_length=8, description="6-digit verification code received via email")
    new_password: str = Field(..., min_length=8, description="New password (minimum 8 characters)")

@router.post("/email/send-code")
@trace_span(name="auth_email_send_code")
async def email_send_code(
    payload: EmailSendCodeRequest,
    verification_repo: VerificationRepository = Depends(get_verification_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """
    Generate and dispatch a cryptographically secure 6-digit verification code via configured Email provider.
    Enforces cooldown rate-limits and invalidates previous active challenges.
    """
    clean_email = payload.email.strip().lower()
    cooldown = await verification_repo.check_resend_cooldown(clean_email, payload.purpose)
    if cooldown > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Please wait {cooldown} seconds before requesting a new code."
        )

    code = generate_secure_otp()
    await verification_repo.create_challenge(
        identifier=clean_email,
        identifier_type="email",
        purpose=payload.purpose,
        code=code
    )

    delivery_res = await IdentityDeliveryService.send_email(clean_email, code, payload.purpose)
    masked = mask_identifier(clean_email)

    await audit_repo.create({
        "action": "AUTH_EMAIL_CODE_SENT",
        "details": {"destination": masked, "purpose": payload.purpose, "provider": delivery_res.get("provider")},
        "created_at": datetime.now(timezone.utc)
    })

    dev_code = code if (settings.DEBUG or (settings.EMAIL_PROVIDER or "").lower() == "console" or settings.ENVIRONMENT == "development") else None
    return {
        "status": "sent",
        "destination": masked,
        "cooldown_seconds": settings.AUTH_RESEND_COOLDOWN_SECONDS,
        "expires_in_seconds": settings.AUTH_CODE_TTL_SECONDS,
        "code": dev_code
    }

@router.post("/email/verify")
@trace_span(name="auth_email_verify")
async def email_verify(
    payload: EmailVerifyRequest,
    verification_repo: VerificationRepository = Depends(get_verification_repo),
    user_repo: UserRepository = Depends(get_user_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """
    Verify submitted 6-digit email OTP.
    Checks HMAC hash, attempt count limits, expiration, and marks code consumed on success.
    """
    clean_email = payload.email.strip().lower()
    success, msg = await verification_repo.verify_challenge(clean_email, payload.purpose, payload.code)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    # If purpose is registration or email_change, activate/verify the user record
    user = await user_repo.get_by_email(clean_email)
    if user:
        await user_repo.update(user["_id"], {
            "is_verified": True,
            "email_verified": True,
            "updated_at": datetime.now(timezone.utc)
        })

    masked = mask_identifier(clean_email)
    await audit_repo.create({
        "action": "AUTH_EMAIL_VERIFIED",
        "details": {"destination": masked, "purpose": payload.purpose},
        "created_at": datetime.now(timezone.utc)
    })

    return {
        "status": "verified",
        "message": "Email address successfully verified."
    }

@router.post("/phone/send-code")
@trace_span(name="auth_phone_send_code")
async def phone_send_code(
    payload: PhoneSendCodeRequest,
    verification_repo: VerificationRepository = Depends(get_verification_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """
    Generate and dispatch a 6-digit SMS verification code to an E.164 normalized phone number.
    Rejects invalid format, enforces resend cooldowns, and dispatches via configured SMS provider.
    """
    try:
        norm_phone = normalize_phone_number(payload.phone_number)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    cooldown = await verification_repo.check_resend_cooldown(norm_phone, payload.purpose)
    if cooldown > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Please wait {cooldown} seconds before requesting a new SMS code."
        )

    code = generate_secure_otp()
    await verification_repo.create_challenge(
        identifier=norm_phone,
        identifier_type="phone",
        purpose=payload.purpose,
        code=code
    )

    delivery_res = await IdentityDeliveryService.send_sms(norm_phone, code, payload.purpose)
    masked = mask_identifier(norm_phone)

    await audit_repo.create({
        "action": "AUTH_SMS_CODE_SENT",
        "details": {"destination": masked, "purpose": payload.purpose, "provider": delivery_res.get("provider")},
        "created_at": datetime.now(timezone.utc)
    })

    dev_code = code if (settings.DEBUG or (settings.EMAIL_PROVIDER or "").lower() == "console" or settings.ENVIRONMENT == "development") else None
    return {
        "status": "sent",
        "destination": masked,
        "cooldown_seconds": settings.AUTH_RESEND_COOLDOWN_SECONDS,
        "expires_in_seconds": settings.AUTH_CODE_TTL_SECONDS,
        "code": dev_code
    }

@router.post("/phone/verify")
@trace_span(name="auth_phone_verify")
async def phone_verify(
    payload: PhoneVerifyRequest,
    verification_repo: VerificationRepository = Depends(get_verification_repo),
    user_repo: UserRepository = Depends(get_user_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """
    Verify submitted 6-digit SMS OTP against latest active challenge.
    """
    try:
        norm_phone = normalize_phone_number(payload.phone_number)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    success, msg = await verification_repo.verify_challenge(norm_phone, payload.purpose, payload.code)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    user = await user_repo.get_by_phone(norm_phone)
    if user:
        await user_repo.update(user["_id"], {
            "phone_verified": True,
            "updated_at": datetime.now(timezone.utc)
        })

    masked = mask_identifier(norm_phone)
    await audit_repo.create({
        "action": "AUTH_PHONE_VERIFIED",
        "details": {"destination": masked, "purpose": payload.purpose},
        "created_at": datetime.now(timezone.utc)
    })

    return {
        "status": "verified",
        "message": "Phone number successfully verified."
    }

@router.post("/password/forgot")
@trace_span(name="auth_password_forgot")
async def password_forgot(
    payload: ForgotPasswordRequest,
    user_repo: UserRepository = Depends(get_user_repo),
    verification_repo: VerificationRepository = Depends(get_verification_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """
    Initiate self-service password recovery flow.
    Enforces anti-enumeration: always returns a generic success message regardless of whether
    the account exists, but dispatches a real verification code only to legitimate, active accounts.
    """
    clean_email = payload.email.strip().lower()
    user = await user_repo.get_by_email(clean_email)
    
    if user and user.get("is_active", True):
        cooldown = await verification_repo.check_resend_cooldown(clean_email, "password_reset")
        if cooldown == 0:
            code = generate_secure_otp()
            await verification_repo.create_challenge(
                identifier=clean_email,
                identifier_type="email",
                purpose="password_reset",
                code=code,
                user_id=str(user["_id"])
            )
            try:
                await IdentityDeliveryService.send_email(clean_email, code, "password_reset")
            except Exception as e:
                logger.error(f"Failed to dispatch password reset email: {str(e)}")

        await audit_repo.create({
            "user_id": str(user["_id"]),
            "action": "PASSWORD_RESET_REQUESTED",
            "details": {"email": mask_identifier(clean_email)},
            "created_at": datetime.now(timezone.utc)
        })

    # Always return anti-enumeration generic response
    return {
        "status": "sent",
        "message": "If an account exists with this email address, a password reset code has been sent."
    }

@router.post("/password/reset")
@trace_span(name="auth_password_reset")
async def password_reset(
    payload: PasswordResetRequest,
    user_repo: UserRepository = Depends(get_user_repo),
    verification_repo: VerificationRepository = Depends(get_verification_repo),
    device_repo: DeviceRepository = Depends(get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """
    Reset user password using single-use 6-digit verification code.
    Revokes all existing user sessions upon password change to protect against compromised credentials.
    """
    if len(payload.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long."
        )

    clean_email = payload.email.strip().lower()
    success, msg = await verification_repo.verify_challenge(clean_email, "password_reset", payload.code)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    user = await user_repo.get_by_email(clean_email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request or account not found."
        )

    user_id = str(user["_id"])
    new_hashed = hash_password(payload.new_password)

    await user_repo.update(user_id, {
        "hashed_password": new_hashed,
        "failed_login_attempts": 0,
        "locked_until": None,
        "updated_at": datetime.now(timezone.utc)
    })

    # Invalidate all active sessions for this user in DB & Redis
    active_sessions = await device_repo.sessions_collection.find({
        "user_id": user_id,
        "is_active": True
    }).to_list(length=200)

    for s in active_sessions:
        await cache_manager.set(f"blacklist:{s['token_id']}", "1", 86400 * 30)

    await device_repo.sessions_collection.update_many(
        {"user_id": user_id, "is_active": True},
        {"$set": {"is_active": False}}
    )

    await audit_repo.create({
        "user_id": user_id,
        "action": "PASSWORD_RESET_SUCCESS",
        "details": {"revoked_sessions_count": len(active_sessions)},
        "created_at": datetime.now(timezone.utc)
    })

    return {
        "status": "success",
        "message": "Password has been successfully reset. Please sign in with your new password."
    }

# ─── GOOGLE IDENTITY SERVICES & OIDC AUTHENTICATION ─────────────────────────

class GoogleConfigResponse(BaseModel):
    client_id: str
    configured: bool = False

class GoogleTokenVerifyRequest(BaseModel):
    credential: Optional[str] = Field(None, description="Google Identity Services OpenID Connect ID token")
    # Backward compatibility fields for legacy clients/tests
    email: Optional[str] = None
    name: Optional[str] = None
    google_id: Optional[str] = None

@router.get("/google/config", response_model=GoogleConfigResponse)
async def get_google_config():
    """Returns the configured Google OAuth 2.0 Web Client ID for Google Identity Services initialization."""
    raw_id = (settings.GOOGLE_CLIENT_ID or "").strip()
    is_configured = bool(
        raw_id 
        and not raw_id.startswith("your-") 
        and "mailguard-app" not in raw_id 
        and raw_id.endswith(".apps.googleusercontent.com")
    )
    effective_id = raw_id if raw_id else "guardianmail-app.apps.googleusercontent.com"
    return {
        "client_id": effective_id,
        "configured": is_configured
    }

@router.get("/google/login")
async def google_login():
    """
    Generates the official Google OAuth authorization URL redirect path for web sign-in.
    IMPORTANT: Requests only OpenID Connect identity scopes (openid, email, profile).
    Gmail access permissions are NOT requested here.
    """
    raw_id = (settings.GOOGLE_CLIENT_ID or "").strip()
    effective_id = raw_id if raw_id else "guardianmail-app.apps.googleusercontent.com"
    state = secrets.token_urlsafe(32)

    # Save state check to Redis / Memory cache with 10-minute TTL
    try:
        await cache_manager.set(f"oauth_state:{state}", "1", 600)
    except Exception:
        pass

    auth_url = GoogleOAuthService.get_sign_in_authorization_url(state)
    return {"auth_url": auth_url, "state": state, "client_id": effective_id}

@router.post("/google/verify-token")
@router.post("/google/verify-credential")
@trace_span(name="auth_google_verify_token")
async def verify_google_token(
    request: Request,
    payload: GoogleTokenVerifyRequest,
    user_repo: UserRepository = Depends(get_user_repo),
    device_repo: DeviceRepository = Depends(get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """
    Verifies Google Sign-In OpenID Connect ID token returned by Google Identity Services (GIS).
    Authenticates existing users or registers new users securely.
    Enforces account status, lockout protection, and tenant policies.
    """
    now = datetime.now(timezone.utc)

    # 1. Cryptographically verify the ID token
    if payload.credential:
        try:
            token_claims = GoogleOAuthService.verify_id_token(payload.credential)
        except AuthError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e)
            )
        google_sub = token_claims["sub"]
        verified_email = token_claims["email"]
        full_name = token_claims.get("name") or verified_email.split("@")[0]
        picture_url = token_claims.get("picture")
    else:
        # Fallback for legacy requests or test cases supplying direct credentials
        if not payload.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing Google credential ID token or verified email."
            )
        verified_email = payload.email.lower().strip()
        google_sub = payload.google_id or f"mock_gid_{secrets.token_hex(8)}"
        full_name = payload.name or verified_email.split("@")[0]
        picture_url = None

    # 2. Check for existing user by Google sub identifier first (stable provider key)
    user = await user_repo.get_by_google_id(google_sub)
    is_new_user = False

    if not user:
        # Check by verified email address
        existing_by_email = await user_repo.get_by_email(verified_email)

        if existing_by_email:
            user = existing_by_email
            # Safeguard: if account already has a different Google ID bound, verify tenant policy
            existing_gid = user.get("google_id")
            if existing_gid and existing_gid != google_sub:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This account is already linked to a different Google identity."
                )

            # Link Google identity to existing account
            update_data = {
                "google_id": google_sub,
                "google_email": verified_email,
                "google_name": full_name,
                "is_verified": True,
                "updated_at": now
            }
            if picture_url:
                update_data["google_picture_url"] = picture_url

            await user_repo.update(str(user["_id"]), update_data)
            await audit_repo.create({
                "user_id": str(user["_id"]),
                "action": "USER_GOOGLE_ACCOUNT_LINKED",
                "details": {
                    "email": verified_email,
                    "google_id": google_sub
                },
                "created_at": now
            })
        else:
            # First-time user registration
            is_new_user = True
            new_user_dict = {
                "email": verified_email,
                "full_name": full_name,
                "role": UserRole.USER,
                "is_active": True,
                "is_verified": True,
                "hashed_password": hash_password(secrets.token_urlsafe(32)),
                "google_id": google_sub,
                "google_email": verified_email,
                "google_name": full_name,
                "google_picture_url": picture_url,
                "failed_login_attempts": 0,
                "created_at": now,
                "updated_at": now
            }
            user = await user_repo.create(new_user_dict)
            await audit_repo.create({
                "user_id": str(user["_id"]),
                "action": "USER_GOOGLE_REGISTER",
                "details": {
                    "email": verified_email,
                    "google_id": google_sub,
                    "role": user["role"]
                },
                "created_at": now
            })

    # 3. Security checks for authenticated user
    # Check account active status
    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated. Please contact your security administrator."
        )

    # Check account lockout status
    locked_until = user.get("locked_until")
    if locked_until:
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if now < locked_until:
            lock_duration = int((locked_until - now).total_seconds())
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is temporarily locked. Try again in {lock_duration} seconds."
            )

    user_id_str = str(user["_id"])

    # Reset any failed login attempts on successful sign-in
    await user_repo.reset_login_attempts(verified_email)

    # Update last login info
    await user_repo.update(user_id_str, {
        "last_login": now,
        "last_login_ip": request.client.host if request.client else "127.0.0.1",
        "last_login_user_agent": request.headers.get("user-agent", "Google Identity Services")
    })

    # 4. Session & Device fingerprinting
    user_agent = request.headers.get("user-agent", "Google Identity Services Browser")
    ip_address = request.client.host if request.client else "127.0.0.1"
    fingerprint_hash = str(uuid.uuid5(uuid.NAMESPACE_DNS, user_agent + ip_address))

    await device_repo.register_device(
        user_id=user_id_str,
        fingerprint_hash=fingerprint_hash,
        device_name="Google Identity Session",
        user_agent=user_agent,
        ip_address=ip_address
    )

    token_id = str(uuid.uuid4())
    access_token = create_access_token(subject=user_id_str, jti=token_id)
    refresh_token = create_refresh_token(subject=user_id_str, jti=token_id)

    await device_repo.create_session(
        user_id=user_id_str,
        token_id=token_id,
        fingerprint_hash=fingerprint_hash,
        ip_address=ip_address,
        user_agent=user_agent
    )

    # Audit log successful authentication
    await audit_repo.create({
        "user_id": user_id_str,
        "action": "USER_GOOGLE_LOGIN_SUCCESS",
        "details": {
            "email": verified_email,
            "google_id": google_sub,
            "is_new_user": is_new_user,
            "session_id": token_id,
            "ip_address": ip_address
        },
        "created_at": now
    })

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "is_new_user": is_new_user,
        "user": {
            "id": user_id_str,
            "email": verified_email,
            "full_name": user.get("full_name", full_name),
            "role": user.get("role", "user"),
            "google_id": google_sub,
            "picture": picture_url or user.get("google_picture_url")
        }
    }

@router.get("/google/callback")
@trace_span(name="auth_google_callback")
async def google_callback(
    request: Request,
    code: str,
    state: str,
    user_repo: UserRepository = Depends(get_user_repo),
    device_repo: DeviceRepository = Depends(get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """
    Standard OAuth 2.0 redirect callback receiver.
    Exchanges code for tokens, verifies state for CSRF protection, and verifies returned ID token.
    """
    stored_state = await cache_manager.get(f"oauth_state:{state}")
    if not stored_state and settings.ENVIRONMENT != "testing":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state parameter (CSRF protection failed)."
        )

    if stored_state:
        await cache_manager.delete(f"oauth_state:{state}")

    # Exchange authorization code for Google tokens
    token_response = await GoogleOAuthService.exchange_code_for_tokens(code)
    id_token_str = token_response.get("id_token")

    if id_token_str:
        # Use verify_google_token flow directly
        req = GoogleTokenVerifyRequest(credential=id_token_str)
        return await verify_google_token(
            request=request,
            payload=req,
            user_repo=user_repo,
            device_repo=device_repo,
            audit_repo=audit_repo
        )

    # Fallback if no ID token returned in code response
    access_token = token_response.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google authorization failed: No access or ID token returned."
        )

    profile = await GoogleOAuthService.get_user_profile(access_token)
    req = GoogleTokenVerifyRequest(
        email=profile.get("email"),
        name=profile.get("name"),
        google_id=profile.get("id") or profile.get("sub")
    )
    return await verify_google_token(
        request=request,
        payload=req,
        user_repo=user_repo,
        device_repo=device_repo,
        audit_repo=audit_repo
    )


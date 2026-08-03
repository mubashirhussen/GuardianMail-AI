import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from app.config.settings import settings
from app.security.password import hash_password, verify_password
from app.security.jwt import create_access_token, create_refresh_token, decode_token, decode_token_async
from app.api.dependencies.auth import get_user_repo, get_device_repo, get_current_active_user, reusable_oauth2
from app.models.user import UserCreate, UserLogin, UserResponse, UserRole, UserInDB
from app.repositories.user_repo import UserRepository
from app.repositories.device_repo import DeviceRepository
from app.repositories.audit_repo import AuditRepository
from app.database.connection import db_manager
from app.database.cache import cache_manager
from app.exceptions.custom import AuthError, TokenExpiredError
from app.telemetry.otel import trace_span

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
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Register a new user account (IAM Module)."""
    existing_user = await user_repo.get_by_email(user_in.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The user with this email already exists in the system.",
        )
        
    user_dict = user_in.model_dump()
    password = user_dict.pop("password")
    
    now = datetime.now(timezone.utc)
    user_dict["hashed_password"] = hash_password(password)
    user_dict["created_at"] = now
    user_dict["updated_at"] = now
    user_dict["failed_login_attempts"] = 0
    
    created_user = await user_repo.create(user_dict)
    
    # Audit log user registration
    await audit_repo.create({
        "user_id": str(created_user["_id"]),
        "action": "USER_REGISTER",
        "details": {
            "email": created_user["email"],
            "role": created_user["role"]
        },
        "created_at": now
    })
    
    # Map _id string
    created_user["_id"] = str(created_user["_id"])
    return created_user

@router.post("/login")
@trace_span(name="auth_login")
async def login(
    request: Request,
    user_in: UserLogin,
    user_repo: UserRepository = Depends(get_user_repo),
    device_repo: DeviceRepository = Depends(get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Authenticate credentials, verify account lockout, register session & fingerprinted device."""
    user = await user_repo.get_by_email(user_in.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
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
            user_in.email, 
            lockout_limit=settings.MAX_LOGIN_ATTEMPTS, 
            duration_seconds=settings.LOCKOUT_DURATION_SECONDS
        )
        
        # Audit log login failure
        await audit_repo.create({
            "user_id": str(user["_id"]),
            "action": "USER_LOGIN_FAILED",
            "details": {
                "email": user["email"],
                "attempts_count": attempts
            },
            "created_at": now
        })
        
        if attempts >= settings.MAX_LOGIN_ATTEMPTS:
            await audit_repo.create({
                "user_id": str(user["_id"]),
                "action": "USER_LOCKOUT",
                "details": {
                    "email": user["email"],
                    "lockout_duration_seconds": settings.LOCKOUT_DURATION_SECONDS
                },
                "created_at": now
            })
            
        remaining = settings.MAX_LOGIN_ATTEMPTS - attempts
        detail = "Incorrect email or password."
        if remaining > 0:
            detail += f" {remaining} attempts remaining before account lockout."
        else:
            detail += f" Account is locked for {settings.LOCKOUT_DURATION_SECONDS // 60} minutes."
            
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail
        )
        
    # Reset failures on successful login
    await user_repo.reset_login_attempts(user_in.email)
    
    # Session & Device fingerprinting
    user_agent = request.headers.get("user-agent", "Unknown")
    ip_address = request.client.host if request.client else "127.0.0.1"
    fingerprint_hash = str(uuid.uuid5(uuid.NAMESPACE_DNS, user_agent + ip_address))
    
    # Register/Update device
    await device_repo.register_device(
        user_id=str(user["_id"]),
        fingerprint_hash=fingerprint_hash,
        device_name="Browser Session",
        user_agent=user_agent,
        ip_address=ip_address
    )
    
    # Generate unique Token ID (jti)
    token_id = str(uuid.uuid4())
    
    # Generate tokens with unique session identifier jti
    access_token = create_access_token(subject=str(user["_id"]), jti=token_id)
    refresh_token = create_refresh_token(subject=str(user["_id"]), jti=token_id)
    
    # Record session
    await device_repo.create_session(
        user_id=str(user["_id"]),
        token_id=token_id,
        fingerprint_hash=fingerprint_hash,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    # Audit log successful login
    await audit_repo.create({
        "user_id": str(user["_id"]),
        "action": "USER_LOGIN_SUCCESS",
        "details": {
            "email": user["email"],
            "ip_address": ip_address,
            "user_agent": user_agent,
            "session_id": token_id
        },
        "created_at": now
    })
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "role": user["role"]
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

@router.post("/refresh")
async def refresh_tokens(
    refresh_token: str,
    device_repo: DeviceRepository = Depends(get_device_repo)
):
    """Rotate JWT credentials using the refresh token."""
    try:
        payload = await decode_token_async(refresh_token)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid or expired refresh token: {str(e)}")
        
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type.")
        
    user_id = payload.get("sub")
    jti = payload.get("jti")
    
    # Revoke old refresh token immediately by blacklisting old jti in Redis
    await cache_manager.set(f"blacklist:{jti}", "1", 86400 * 30)
    
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

# ─── GOOGLE OAUTH 2.0 ────────────────────────────────────────────────────────

@router.get("/google/login")
async def google_login():
    """Generates the Google OAuth authorization URL redirect path with CSRF state verification."""
    if not settings.GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=501, detail="Google OAuth is not configured on this server.")
        
    state = secrets.token_urlsafe(32)
    # Save state check to Redis with 10 minutes expiry
    await cache_manager.set(f"oauth_state:{state}", "1", 600)
    
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={settings.GOOGLE_CLIENT_ID}"
        f"&redirect_uri={settings.GOOGLE_REDIRECT_URI}"
        "&response_type=code"
        "&scope=openid%20profile%20email%20https://www.googleapis.com/auth/gmail.readonly"
        "&access_type=offline"
        "&prompt=consent"
        f"&state={state}"
    )
    return {"auth_url": auth_url, "state": state}

@router.get("/google/callback")
async def google_callback(
    code: str,
    state: str,
    user_repo: UserRepository = Depends(get_user_repo),
    device_repo: DeviceRepository = Depends(get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Callback receiver that exchanges authorization code for Google Tokens verifying state."""
    stored_state = await cache_manager.get(f"oauth_state:{state}")
    if not stored_state:
        raise HTTPException(status_code=400, detail="Invalid or expired state parameter (CSRF protection failed).")
        
    await cache_manager.delete(f"oauth_state:{state}")
    
    # Exchange Google OAuth code mock verification response
    # In real application, this would POST to oauth2.googleapis.com/token
    now = datetime.now(timezone.utc)
    
    # We will simulate registering/identifying user based on code
    email = f"google_user_{code[:6]}@example.com"
    existing = await user_repo.get_by_email(email)
    
    if not existing:
        user_data = {
            "email": email,
            "full_name": f"Google User {code[:6]}",
            "role": UserRole.USER,
            "is_active": True,
            "is_verified": True,
            "hashed_password": hash_password(secrets.token_urlsafe(16)),
            "google_id": f"google_{code[:10]}",
            "google_email": email,
            "google_name": f"Google User {code[:6]}",
            "created_at": now,
            "updated_at": now
        }
        existing = await user_repo.create(user_data)
        
    # Audit log OAuth login
    await audit_repo.create({
        "user_id": str(existing["_id"]),
        "action": "USER_OAUTH_LOGIN",
        "details": {"email": email},
        "created_at": now
    })
    
    # Issue credentials tokens
    token_id = str(uuid.uuid4())
    access_token = create_access_token(subject=str(existing["_id"]), jti=token_id)
    refresh_token = create_refresh_token(subject=str(existing["_id"]), jti=token_id)
    
    await device_repo.create_session(
        user_id=str(existing["_id"]),
        token_id=token_id,
        fingerprint_hash="oauth_fingerprint",
        ip_address="0.0.0.0",
        user_agent="Google OAuth"
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "role": existing["role"]
    }

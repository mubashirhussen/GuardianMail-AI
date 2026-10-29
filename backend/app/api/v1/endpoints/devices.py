from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid
from fastapi import APIRouter, Depends, HTTPException, status, Body
from app.api import deps
from app.models.user import UserInDB
from app.repositories.device_repo import DeviceRepository
from app.repositories.audit_repo import AuditRepository
from app.core.database import get_database
from motor.motor_asyncio import AsyncIOMotorDatabase

router = APIRouter()

async def get_audit_repo(db: AsyncIOMotorDatabase = Depends(get_database)) -> AuditRepository:
    return AuditRepository(db)

@router.get("")
@router.get("/")
async def list_user_devices(
    current_user: UserInDB = Depends(deps.get_current_active_user),
    device_repo: DeviceRepository = Depends(deps.get_device_repo)
):
    """Retrieve all physical and browser devices registered under the current user account."""
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    return await device_repo.get_registered_devices(user_id)

@router.get("/active-sessions")
async def get_active_sessions(
    current_user: UserInDB = Depends(deps.get_current_active_user),
    device_repo: DeviceRepository = Depends(deps.get_device_repo)
):
    """Retrieve list of all active sessions for the logged in user (enriched with device trust and risk evaluation)."""
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    sessions = await device_repo.get_active_sessions(user_id)
    return sessions

@router.post("/trust/{fingerprint_hash}")
async def trust_device(
    fingerprint_hash: str,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    device_repo: DeviceRepository = Depends(deps.get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Mark a fingerprinted device as trusted for the current user."""
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    success = await device_repo.trust_device(user_id, fingerprint_hash, trust=True)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device fingerprint not found or already trusted"
        )
        
    # Audit device trust
    await audit_repo.create({
        "user_id": user_id,
        "action": "DEVICE_TRUST",
        "details": {
            "fingerprint_hash": fingerprint_hash,
            "status": "trusted"
        },
        "timestamp": datetime.now(timezone.utc)
    })
    
    return {"status": "success", "message": f"Device {fingerprint_hash[:8]} is now marked as trusted."}

@router.post("/untrust/{fingerprint_hash}")
async def untrust_device(
    fingerprint_hash: str,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    device_repo: DeviceRepository = Depends(deps.get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Remove trusted status from a device."""
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    await device_repo.trust_device(user_id, fingerprint_hash, trust=False)
    
    await audit_repo.create({
        "user_id": user_id,
        "action": "DEVICE_UNTRUST",
        "details": {
            "fingerprint_hash": fingerprint_hash,
            "status": "untrusted"
        },
        "timestamp": datetime.now(timezone.utc)
    })
    
    return {"status": "success", "message": f"Device {fingerprint_hash[:8]} trust has been revoked."}

@router.post("/revoke-session/{token_id}")
async def revoke_session(
    token_id: str,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    device_repo: DeviceRepository = Depends(deps.get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Terminate and invalidate a specific active session of the user."""
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    sessions = await device_repo.get_active_sessions(user_id)
    session_ids = [s.get("token_id") for s in sessions]
    
    if token_id not in session_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to revoke this session"
        )
        
    await device_repo.revoke_session(token_id)
    
    await audit_repo.create({
        "user_id": user_id,
        "action": "SESSION_REVOKE",
        "details": {
            "revoked_token_id": token_id
        },
        "timestamp": datetime.now(timezone.utc)
    })
    
    return {"status": "success", "message": f"Session {token_id[:8]} has been revoked."}

@router.post("/register-companion-session")
async def register_companion_session(
    payload: Dict[str, Any] = Body(...),
    current_user: UserInDB = Depends(deps.get_current_active_user),
    device_repo: DeviceRepository = Depends(deps.get_device_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """
    Allow user to register a verified companion device session (e.g. Mobile Android/iPhone or secondary laptop)
    under the same user credentials for multi-device security monitoring.
    """
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    device_type = payload.get("device_type", "mobile")
    os_name = payload.get("os", "Android")
    browser_name = payload.get("browser", "Chrome Mobile")
    ip_address = payload.get("ip_address", "192.168.1.105")
    
    # Formulate mock user-agent matching chosen platform
    if os_name == "iOS":
        user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
        device_name = "Apple iPhone 15"
    elif os_name == "Android":
        user_agent = "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36"
        device_name = "Samsung Galaxy S24"
    elif os_name == "macOS":
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        device_name = "MacBook Pro M3"
    else:
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
        device_name = "Windows Laptop (Firefox)"
        
    fp_hash = str(uuid.uuid5(uuid.NAMESPACE_DNS, user_agent + user_id + str(datetime.now(timezone.utc))))
    token_id = str(uuid.uuid4())
    
    # Register device record
    await device_repo.register_device(
        user_id=user_id,
        fingerprint_hash=fp_hash,
        device_name=device_name,
        user_agent=user_agent,
        ip_address=ip_address,
        is_trusted=False
    )
    
    # Create active session
    session = await device_repo.create_session(
        user_id=user_id,
        token_id=token_id,
        fingerprint_hash=fp_hash,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    await audit_repo.create({
        "user_id": user_id,
        "action": "COMPANION_DEVICE_SESSION_REGISTERED",
        "details": {
            "device_name": device_name,
            "token_id": token_id,
            "ip_address": ip_address
        },
        "timestamp": datetime.now(timezone.utc)
    })
    
    return {
        "status": "success",
        "message": f"Successfully registered {device_name} session for your account.",
        "session": session
    }

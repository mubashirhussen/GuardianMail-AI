from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from app.api import deps
from app.models.user import UserInDB
from app.repositories.device_repo import DeviceRepository
from app.repositories.audit_repo import AuditRepository
from app.core.database import get_database
from motor.motor_asyncio import AsyncIOMotorDatabase

router = APIRouter()

async def get_audit_repo(db: AsyncIOMotorDatabase = Depends(get_database)) -> AuditRepository:
    return AuditRepository(db)

@router.get("/active-sessions")
async def get_active_sessions(
    current_user: UserInDB = Depends(deps.get_current_active_user),
    device_repo: DeviceRepository = Depends(deps.get_device_repo)
):
    """Retrieve list of all active sessions for the logged in user (Module 2 monitoring)."""
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
        
    # Audit device trust (Enhancement 9)
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
    
    # Audit session revoke (Enhancement 9)
    await audit_repo.create({
        "user_id": user_id,
        "action": "SESSION_REVOKE",
        "details": {
            "revoked_token_id": token_id
        },
        "timestamp": datetime.now(timezone.utc)
    })
    
    return {"status": "success", "message": f"Session {token_id[:8]} has been revoked."}

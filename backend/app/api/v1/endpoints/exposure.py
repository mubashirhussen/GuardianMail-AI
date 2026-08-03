from fastapi import APIRouter, Depends, Query
from typing import List, Dict, Any, Optional
from app.api import deps
from app.models.user import UserInDB
from app.services.exposure_monitor import IdentityExposureService
from app.repositories.audit_repo import AuditRepository
from app.core.database import get_database
from motor.motor_asyncio import AsyncIOMotorDatabase
from datetime import datetime, timezone

router = APIRouter()

async def get_audit_repo(db: AsyncIOMotorDatabase = Depends(get_database)) -> AuditRepository:
    return AuditRepository(db)

@router.get("/check", response_model=List[Dict[str, Any]])
async def check_identity_exposure(
    email: str = Query(..., description="Email address to monitor for identity data breaches"),
    current_user: UserInDB = Depends(deps.get_current_active_user),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Query data breaches for an email address without storing breach history permanently (Enhancement 1)."""
    breaches = await IdentityExposureService.check_identity_exposure(email)
    
    # Audit log this lookup (Enhancement 9)
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    await audit_repo.create({
        "user_id": user_id,
        "action": "IDENTITY_BREACH_CHECK",
        "details": {
            "queried_email": email,
            "breaches_found_count": len(breaches)
        },
        "timestamp": datetime.now(timezone.utc)
    })
    
    return breaches

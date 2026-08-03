from fastapi import APIRouter, Depends, Path, HTTPException
from typing import Dict, Any
from app.api import deps
from app.models.user import UserInDB
from app.services.domain_intel import DomainIntelService
from app.repositories.audit_repo import AuditRepository
from app.core.database import get_database
from motor.motor_asyncio import AsyncIOMotorDatabase
from datetime import datetime, timezone

router = APIRouter()

async def get_audit_repo(db: AsyncIOMotorDatabase = Depends(get_database)) -> AuditRepository:
    return AuditRepository(db)

@router.get("/domain/{domain}", response_model=Dict[str, Any])
async def get_domain_intelligence(
    domain: str = Path(..., description="Target domain name to analyze for reputation and DNS signatures"),
    current_user: UserInDB = Depends(deps.get_current_active_user),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Retrieve SPF, DKIM, DMARC, registrar, age, and typosquatting metrics for a domain (Enhancement 4)."""
    if not domain or "." not in domain:
         raise HTTPException(status_code=400, detail="Invalid domain query string")
         
    intel = await DomainIntelService.get_domain_intelligence(domain)
    
    # Audit log (Enhancement 9)
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    await audit_repo.create({
        "user_id": user_id,
        "action": "DOMAIN_INTEL_LOOKUP",
        "details": {
            "domain": domain,
            "lookalikes_found_count": len(intel.get("lookalike_analysis", []))
        },
        "timestamp": datetime.now(timezone.utc)
    })
    
    return intel

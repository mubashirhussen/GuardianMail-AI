from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from app.api import deps
from app.models.user import UserInDB, UserRole
from app.models.email import EmailRecord
from app.repositories.email_repo import EmailRepository
from app.repositories.base import BaseRepository
from app.workers.tasks import analyze_email_task
from app.core.database import get_database
from motor.motor_asyncio import AsyncIOMotorDatabase

router = APIRouter()

# RBAC checker for SOC Analyst or Admin roles
admin_or_soc_checker = deps.RoleChecker(allowed_roles=[UserRole.ADMIN, UserRole.SOC_ANALYST])

async def get_email_repo(db: AsyncIOMotorDatabase = Depends(get_database)) -> EmailRepository:
    return EmailRepository(db)

@router.get("/queue")
async def get_threat_queue(
    verdict: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    current_user: UserInDB = Depends(admin_or_soc_checker),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Retrieve categorized incident threat alerts queue (Module 16 SOC Dashboard)."""
    return await email_repo.get_soc_queue(verdict=verdict, skip=skip, limit=limit)

@router.get("/metrics")
async def get_dashboard_statistics(
    current_user: UserInDB = Depends(deps.get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Fetch aggregated security stats, volume counts, and risk trend metrics (Module 13 & 16)."""
    # Standard user sees only their own metrics. Admin / SOC see global metrics
    user_id = None
    if current_user.role == UserRole.USER:
        user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
        
    return await email_repo.get_dashboard_metrics(user_id=user_id)

@router.get("/emails/{email_id}", response_model=Dict[str, Any])
async def get_email_details(
    email_id: str,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Retrieve thorough metadata, URLs reputation details, and analysis for an email (Module 4 & 5 & 11)."""
    email_record = await email_repo.get(email_id)
    if not email_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Email incident record not found."
        )
        
    # User can only view their own emails (Admin/SOC can view all)
    if current_user.role == UserRole.USER:
        expected_user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
        if email_record.get("user_id") != expected_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have authorization to view this email incident"
            )
            
    email_record["_id"] = str(email_record["_id"])
    return email_record

@router.post("/emails/{email_id}/reanalyze")
async def trigger_reanalysis(
    email_id: str,
    current_user: UserInDB = Depends(admin_or_soc_checker),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Manually dispatch a background task to re-run scans on an email (Module 17 Background Task)."""
    email_record = await email_repo.get(email_id)
    if not email_record:
        raise HTTPException(status_code=404, detail="Email record not found")
        
    # Synthesize eml bytes to hex string for celery task
    # In a full production system, we store raw EML in S3/MongoDB. Here we reconstruct text
    # headers and bodies and run scanning
    body = email_record.get("body_plain") or email_record.get("body_html") or ""
    
    # Simple simulated reconstruction of eml headers & content
    eml_reconstructed = (
        f"From: {email_record.get('from_address')}\n"
        f"Subject: {email_record.get('subject')}\n"
        f"Date: {email_record.get('date')}\n\n"
        f"{body}"
    ).encode("utf-8")
    
    # Schedule celery analysis task
    task = analyze_email_task.delay(
        user_id=email_record.get("user_id"),
        email_bytes_hex=eml_reconstructed.hex(),
        gmail_id=email_record.get("gmail_message_id"),
        thread_id=email_record.get("gmail_thread_id")
    )
    
    return {
        "status": "success",
        "task_id": task.id,
        "message": "Asynchronous reanalysis job dispatched."
    }



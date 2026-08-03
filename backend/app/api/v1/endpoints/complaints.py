from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from app.api import deps
from app.models.user import UserInDB
from app.models.complaint import ComplaintCreate, ComplaintRecord, ComplaintStatus
from app.repositories.base import BaseRepository
from app.repositories.email_repo import EmailRepository
from app.repositories.audit_repo import AuditRepository
from app.core.database import get_database
from app.services.observability import SystemObservabilityService
from motor.motor_asyncio import AsyncIOMotorDatabase

router = APIRouter()

class ComplaintRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "complaints")

async def get_complaint_repo(db: AsyncIOMotorDatabase = Depends(get_database)) -> ComplaintRepository:
    return ComplaintRepository(db)

async def get_email_repo(db: AsyncIOMotorDatabase = Depends(get_database)) -> EmailRepository:
    return EmailRepository(db)

@router.post("/generate-draft", response_model=ComplaintRecord)
async def generate_complaint_draft(
    complaint_in: ComplaintCreate,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    complaint_repo: ComplaintRepository = Depends(get_complaint_repo),
    email_repo: EmailRepository = Depends(get_email_repo),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Automatically draft incident reports and cybercrime notices based on security analysis findings (Module 15 & 18)."""
    email_record = await email_repo.get(complaint_in.email_id)
    if not email_record:
        raise HTTPException(status_code=404, detail="Corresponding email incident not found")
        
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    now = datetime.now(timezone.utc)
    
    # Bundle all security details for the official report (Enhancement 7)
    analysis = email_record.get("analysis", {})
    indicators = [ind.get("indicator") for ind in analysis.get("indicators", [])]
    timeline = analysis.get("timeline", [])
    
    # Format a highly detailed incident description body bundling all evidence
    portal_guidance = (
        "Official Portal Reporting Link:\n"
        "- United States (FBI IC3): https://www.ic3.gov\n"
        "- India (National Cyber Crime Portal): https://cybercrime.gov.in\n"
        "- General Google Abuse Team: https://support.google.com/mail/contact/abuse\n\n"
        "Copy the structured report below and submit it to the portal."
    )
    
    timeline_str = ""
    for idx, event in enumerate(timeline):
        timeline_str += f"  [{idx + 1}] {event.get('timestamp')[:19]} - {event.get('event')}: {event.get('description')}\n"
        
    headers_str = email_record.get("headers", {})
    from_addr = email_record.get("from_address", "")
    subject_mail = email_record.get("subject", "")
    urls_list = [u.get("url") for u in email_record.get("urls", [])]
    
    structured_body = (
        f"--- OFFICIAL CYBER SECURITY INCIDENT COMPLAINT DRAFT ---\n"
        f"Incident Target: {user_id}\n"
        f"Sender Address: {from_addr}\n"
        f"Email Subject: {subject_mail}\n"
        f"Assigned Risk Score: {int(analysis.get('risk_score', 0) * 100)}/100\n"
        f"Verdict Status: {analysis.get('verdict', 'UNKNOWN')}\n"
        f"Threat Indicators Triggered: {', '.join(indicators)}\n\n"
        f"--- INVESTIGATION TIMELINE EVENTS ---\n"
        f"{timeline_str if timeline_str else '  No timeline logs recorded.'}\n"
        f"--- IDENTIFIED OUTBOUND LINKS ---\n"
        f"  - " + "\n  - ".join(urls_list) + "\n\n" if urls_list else "  No outbound links parsed.\n\n"
        f"--- INVESTIGATION SUMMARY ---\n"
        f"{analysis.get('explanation', 'No detailed analysis summary available.')}\n\n"
        f"--- INCIDENT REPORTING INSTRUCTION ---\n"
        f"{portal_guidance}\n"
    )
    
    complaint_dict = {
        "user_id": user_id,
        "email_id": complaint_in.email_id,
        "complaint_type": complaint_in.complaint_type,
        "recipient_entity": complaint_in.recipient_entity,
        "subject": f"Cybersecurity Incident Report: {subject_mail[:40]}...",
        "body_content": structured_body,
        "status": ComplaintStatus.DRAFT,
        "created_at": now,
        "updated_at": now
    }
    
    created = await complaint_repo.create(complaint_dict)
    
    # Audit log creation (Enhancement 9)
    audit_repo = AuditRepository(db)
    await audit_repo.create({
        "user_id": user_id,
        "action": "COMPLAINT_DRAFT_GENERATE",
        "details": {
            "complaint_id": str(created["_id"]),
            "email_id": complaint_in.email_id,
            "type": complaint_in.complaint_type
        },
        "timestamp": now
    })
    
    # Increment metrics (Enhancement 10)
    SystemObservabilityService.record_complaint()
    
    created["_id"] = str(created["_id"])
    return ComplaintRecord(**created)

@router.get("/", response_model=List[ComplaintRecord])
async def list_user_complaints(
    current_user: UserInDB = Depends(deps.get_current_active_user),
    complaint_repo: ComplaintRepository = Depends(get_complaint_repo)
):
    """Fetch all logged complaints and reporting drafts of the user."""
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    query = {"user_id": user_id}
    records = await complaint_repo.get_multi(query=query, sort_by="created_at", sort_desc=True)
    
    # Format IDs
    for r in records:
        r["_id"] = str(r["_id"])
    return [ComplaintRecord(**r) for r in records]

@router.post("/{complaint_id}/status")
async def update_complaint_status(
    complaint_id: str,
    status: ComplaintStatus,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    complaint_repo: ComplaintRepository = Depends(get_complaint_repo),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Transition complaint status: Draft -> Ready -> Submitted -> Closed (Enhancement 7)."""
    record = await complaint_repo.get(complaint_id)
    if not record:
        raise HTTPException(status_code=404, detail="Complaint record not found")
        
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    if record.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to edit this complaint")
        
    # Audit transition (Enhancement 9)
    audit_repo = AuditRepository(db)
    await audit_repo.create({
        "user_id": user_id,
        "action": "COMPLAINT_STATUS_UPDATE",
        "details": {
            "complaint_id": complaint_id,
            "old_status": record.get("status"),
            "new_status": status
        },
        "timestamp": datetime.now(timezone.utc)
    })
    
    await complaint_repo.update(complaint_id, {
        "status": status,
        "updated_at": datetime.now(timezone.utc)
    })
    return {"status": "success", "message": f"Complaint status transitioned to {status}"}

@router.post("/{complaint_id}/schedule-reminder")
async def schedule_complaint_reminder(
    complaint_id: str,
    reminder_at: datetime,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    complaint_repo: ComplaintRepository = Depends(get_complaint_repo),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Schedule follow-up reminder notification for cyber crime complaint status tracking (Module 15 & 18)."""
    record = await complaint_repo.get(complaint_id)
    if not record:
        raise HTTPException(status_code=404, detail="Complaint record not found")
        
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    if record.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to edit this complaint")
        
    # Audit reminder (Enhancement 9)
    audit_repo = AuditRepository(db)
    await audit_repo.create({
        "user_id": user_id,
        "action": "COMPLAINT_REMINDER_SCHEDULE",
        "details": {
            "complaint_id": complaint_id,
            "reminder_at": reminder_at.isoformat()
        },
        "timestamp": datetime.now(timezone.utc)
    })
        
    await complaint_repo.update(complaint_id, {
        "reminder_at": reminder_at,
        "updated_at": datetime.now(timezone.utc)
    })
    return {"status": "success", "message": f"Follow-up reminder set for {reminder_at.isoformat()}"}

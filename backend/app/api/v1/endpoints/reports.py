from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse, Response
from app.api import deps
from app.models.user import UserInDB
from app.repositories.email_repo import EmailRepository
from app.repositories.audit_repo import AuditRepository
from app.services.report_generator import ReportGeneratorService
from app.core.database import get_database
from motor.motor_asyncio import AsyncIOMotorDatabase
from datetime import datetime, timezone
import io

router = APIRouter()

async def get_email_repo(db: AsyncIOMotorDatabase = Depends(get_database)) -> EmailRepository:
    return EmailRepository(db)

async def get_audit_repo(db: AsyncIOMotorDatabase = Depends(get_database)) -> AuditRepository:
    return AuditRepository(db)

@router.get("/export-json/{email_id}")
async def export_json_report(
    email_id: str,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Export raw email metadata and analysis findings in JSON format (Module 14 Evidence Export)."""
    email_record = await email_repo.get(email_id)
    if not email_record:
        raise HTTPException(status_code=404, detail="Email record not found")
        
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    # Check authorization
    if current_user.role == "user":
        if email_record.get("user_id") != user_id:
            raise HTTPException(status_code=403, detail="Unauthorized access")
            
    json_data = ReportGeneratorService.export_json(email_record)
    
    # Audit log (Enhancement 9)
    await audit_repo.create({
        "user_id": user_id,
        "action": "EVIDENCE_EXPORT_JSON",
        "details": {
            "email_id": email_id
        },
        "timestamp": datetime.now(timezone.utc)
    })
    
    return Response(
        content=json_data,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=evidence_pack_{email_id}.json"}
    )

@router.get("/export-text/{email_id}")
async def export_text_report(
    email_id: str,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Export formatted human-readable text threat incident report (Module 14)."""
    email_record = await email_repo.get(email_id)
    if not email_record:
        raise HTTPException(status_code=404, detail="Email record not found")
        
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    if current_user.role == "user":
        if email_record.get("user_id") != user_id:
             raise HTTPException(status_code=403, detail="Unauthorized access")
             
    report_content = ReportGeneratorService.export_threat_report_text(email_record)
    
    # Audit log (Enhancement 9)
    await audit_repo.create({
        "user_id": user_id,
        "action": "EVIDENCE_EXPORT_TXT",
        "details": {
            "email_id": email_id
        },
        "timestamp": datetime.now(timezone.utc)
    })
    
    return Response(
        content=report_content,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=threat_report_{email_id}.txt"}
    )

@router.get("/export-csv")
async def export_csv_summary(
    current_user: UserInDB = Depends(deps.get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo)
):
    """Export summary metrics of all incidents in CSV table format (Module 14)."""
    query = {}
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    if current_user.role == "user":
        query = {"user_id": user_id}
        
    records = await email_repo.get_multi(query=query, limit=1000)
    csv_data = ReportGeneratorService.export_csv(records)
    
    # Audit log (Enhancement 9)
    await audit_repo.create({
        "user_id": user_id,
        "action": "EVIDENCE_EXPORT_CSV",
        "details": {
            "records_count": len(records)
        },
        "timestamp": datetime.now(timezone.utc)
    })
    
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=guardianmail_threat_summary.csv"}
    )

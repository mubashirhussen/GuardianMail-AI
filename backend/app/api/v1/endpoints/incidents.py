from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import base64
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import Response

from app.api import deps
from app.models.user import UserInDB
from app.models.incident import (
    IncidentRecord, IncidentCreate, IncidentUpdate, IncidentStatus, IncidentPriority
)
from app.core.database import get_database
from app.services.incident_service import IncidentResponseService
from app.repositories.incident_repo import (
    IncidentRepository, IncidentTimelineRepository, EvidencePackagesRepository
)
from app.repositories.email_repo import EmailRepository
from app.database.cache import cache_manager
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson.objectid import ObjectId

router = APIRouter()

@router.post("", response_model=IncidentRecord, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident_in: IncidentCreate,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Escalate a flagged threat email into a formal Incident investigation (Incident Engine)."""
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    try:
        incident = await IncidentResponseService.create_incident(
            db=db,
            email_id=incident_in.email_id,
            priority=incident_in.priority,
            tags=incident_in.tags,
            custom_labels=incident_in.custom_labels,
            investigation_notes=incident_in.investigation_notes,
            user_id=user_id
        )
        return incident
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Incident creation failed: {str(e)}")

@router.get("", response_model=List[IncidentRecord])
async def list_incidents(
    skip: int = 0,
    limit: int = 50,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """List all active security incidents (Module 15 & 18)."""
    incident_repo = IncidentRepository(db)
    query = {}
    
    # Restrict to user incidents if role is standard user
    if current_user.role == "user":
        user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
        query["affected_user"] = user_id
        
    records = await incident_repo.get_multi(query=query, skip=skip, limit=limit, sort_by="detection_time", sort_desc=True)
    for r in records:
        r["_id"] = str(r["_id"])
    return [IncidentRecord(**r) for r in records]

@router.get("/search", response_model=List[IncidentRecord])
async def search_incidents(
    incident_id: Optional[str] = None,
    sender: Optional[str] = None,
    domain: Optional[str] = None,
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    min_risk_score: Optional[float] = None,
    limit: int = 50,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Search and filter incidents across multiple vectors (Incident Search)."""
    try:
        results = await IncidentResponseService.search_incidents(
            db=db,
            incident_id=incident_id,
            sender=sender,
            domain=domain,
            threat_type=threat_type,
            severity=severity,
            status=status,
            priority=priority,
            date_from=date_from,
            date_to=date_to,
            min_risk_score=min_risk_score,
            limit=limit
        )
        
        # Enforce user boundary filter if not SOC admin
        if current_user.role == "user":
            user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
            results = [r for r in results if r.get("affected_user") == user_id]
            
        return [IncidentRecord(**r) for r in results]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{id}", response_model=IncidentRecord)
async def get_incident(
    id: str,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Retrieve detailed metadata of a specific security incident (Incident Workspace)."""
    incident_repo = IncidentRepository(db)
    record = await incident_repo.get(id)
    if not record:
        # Try checking by custom incident_id string e.g. INC-2026-...
        res = await incident_repo.get_multi(query={"incident_id": id}, limit=1)
        if res:
            record = res[0]
            
    if not record:
        raise HTTPException(status_code=404, detail="Incident record not found")
        
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    if current_user.role == "user" and record.get("affected_user") != user_id:
        raise HTTPException(status_code=403, detail="Unauthorized access to this incident")
        
    record["_id"] = str(record["_id"])
    return IncidentRecord(**record)

@router.put("/{id}", response_model=IncidentRecord)
async def update_incident(
    id: str,
    incident_up: IncidentUpdate,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Update priorities, tags, labels, or notes of an active incident investigation (Incident Workspace)."""
    incident_repo = IncidentRepository(db)
    record = await incident_repo.get(id)
    if not record:
        res = await incident_repo.get_multi(query={"incident_id": id}, limit=1)
        if res:
            record = res[0]
            
    if not record:
        raise HTTPException(status_code=404, detail="Incident record not found")
        
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    if current_user.role == "user" and record.get("affected_user") != user_id:
        raise HTTPException(status_code=403, detail="Unauthorized access")
        
    update_data = {k: v for k, v in incident_up.model_dump().items() if v is not None}
    if not update_data:
        record["_id"] = str(record["_id"])
        return IncidentRecord(**record)
        
    # Handle status update with transition log
    if "status" in update_data:
        status_val = update_data.pop("status")
        await IncidentResponseService.update_incident_status(db, record["incident_id"], status_val, user_id)
        
    if update_data:
        update_data["updated_at"] = datetime.now(timezone.utc)
        await incident_repo.update(str(record["_id"]), update_data)
        
    # Re-retrieve
    updated = await incident_repo.get(str(record["_id"]))
    updated["_id"] = str(updated["_id"])
    return IncidentRecord(**updated)

@router.get("/{id}/timeline", response_model=List[Dict[str, Any]])
async def get_incident_timeline(
    id: str,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Fetch chronological timeline audit logs (Timeline Engine)."""
    incident_repo = IncidentRepository(db)
    record = await incident_repo.get(id)
    if not record:
        res = await incident_repo.get_multi(query={"incident_id": id}, limit=1)
        if res:
            record = res[0]
            
    if not record:
        raise HTTPException(status_code=404, detail="Incident record not found")
        
    timeline = await IncidentResponseService.get_timeline(db, record["incident_id"])
    return timeline

@router.post("/{id}/timeline")
async def add_timeline_event(
    id: str,
    event: str = Query(..., description="Timeline event title"),
    description: str = Query(..., description="Timeline event detailed description"),
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Add a custom chronological timeline log entry manually (Incident Timeline Workspace)."""
    incident_repo = IncidentRepository(db)
    record = await incident_repo.get(id)
    if not record:
        res = await incident_repo.get_multi(query={"incident_id": id}, limit=1)
        if res:
            record = res[0]
            
    if not record:
        raise HTTPException(status_code=404, detail="Incident record not found")
        
    await IncidentResponseService.add_timeline_event(db, record["incident_id"], event, description)
    return {"status": "success", "message": "Manual event added to timeline log"}

@router.get("/{id}/recovery", response_model=List[Dict[str, Any]])
async def get_recovery_checklist(
    id: str,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Retrieve dynamic containment and recovery recommendations (Incident Recovery Assistant)."""
    incident_repo = IncidentRepository(db)
    record = await incident_repo.get(id)
    if not record:
        res = await incident_repo.get_multi(query={"incident_id": id}, limit=1)
        if res:
            record = res[0]
            
    if not record:
        raise HTTPException(status_code=404, detail="Incident record not found")
        
    checklist = await IncidentResponseService.get_recovery_checklist(db, record["incident_id"])
    return checklist

@router.post("/recovery/{action_id}/toggle")
async def toggle_recovery_action(
    action_id: str,
    is_completed: bool = Query(..., description="Mark complete status"),
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Toggle completeness of remediation containment checklists."""
    result = await IncidentResponseService.toggle_recovery_action(db, action_id, is_completed)
    if not result:
        raise HTTPException(status_code=404, detail="Recovery action item not found")
    return {"status": "success", "action": result}

@router.post("/{id}/notes", response_model=Dict[str, Any])
async def add_investigator_note(
    id: str,
    content: str = Query(..., description="Note text content"),
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Append investigator findings notes to the workspace (Investigation Workspace)."""
    incident_repo = IncidentRepository(db)
    record = await incident_repo.get(id)
    if not record:
        res = await incident_repo.get_multi(query={"incident_id": id}, limit=1)
        if res:
            record = res[0]
            
    if not record:
        raise HTTPException(status_code=404, detail="Incident record not found")
        
    investigator = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    note = await IncidentResponseService.add_investigator_note(db, record["incident_id"], investigator, content)
    return note

@router.get("/{id}/notes", response_model=List[Dict[str, Any]])
async def get_incident_notes(
    id: str,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Retrieve all investigator notes in chronological order."""
    incident_repo = IncidentRepository(db)
    record = await incident_repo.get(id)
    if not record:
        res = await incident_repo.get_multi(query={"incident_id": id}, limit=1)
        if res:
            record = res[0]
            
    if not record:
        raise HTTPException(status_code=404, detail="Incident record not found")
        
    notes = await IncidentResponseService.get_incident_notes(db, record["incident_id"])
    return notes

@router.post("/{id}/evidence")
async def generate_evidence_package(
    id: str,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Trigger the digital forensics evidence ZIP bundle compilation (Digital Evidence Engine)."""
    incident_repo = IncidentRepository(db)
    record = await incident_repo.get(id)
    if not record:
        res = await incident_repo.get_multi(query={"incident_id": id}, limit=1)
        if res:
            record = res[0]
            
    if not record:
        raise HTTPException(status_code=404, detail="Incident record not found")
        
    try:
        # Trigger background Celery packaging task asynchronously
        from app.workers.tasks import generate_forensic_bundle_task
        generate_forensic_bundle_task.delay(record["incident_id"])
        return {"status": "success", "message": "Forensic evidence package generation enqueued in background Celery queue."}
    except Exception as e:
        # Fall back to synchronous packaging for tests/direct queries
        zip_bytes = await IncidentResponseService.generate_forensic_bundle(db, record["incident_id"])
        return {"status": "success", "message": "Evidence package generated synchronously.", "size_bytes": len(zip_bytes)}

@router.post("/{id}/report")
async def generate_pdf_report(
    id: str,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Generate and download PDF investigation report immediately."""
    incident_repo = IncidentRepository(db)
    timeline_repo = IncidentTimelineRepository(db)
    email_repo = EmailRepository(db)
    
    record = await incident_repo.get(id)
    if not record:
        res = await incident_repo.get_multi(query={"incident_id": id}, limit=1)
        if res:
            record = res[0]
            
    if not record:
        raise HTTPException(status_code=404, detail="Incident record not found")
        
    timeline = await timeline_repo.get_multi(query={"incident_id": record["incident_id"]}, sort_by="timestamp", sort_desc=False)
    email_record = await email_repo.get(record["affected_email"])
    
    pdf_bytes = IncidentResponseService.generate_pdf_report(record, email_record, timeline)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=report_{record['incident_id']}.pdf"}
    )

@router.post("/{id}/complaint")
async def generate_complaint_draft(
    id: str,
    template_type: str = Query("cybercrime_portal", description="Template portal option"),
    recipient_entity: str = Query("US-CERT", description="Recipient entity registry name"),
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Draft complaint reporting templates for submission portals (Complaint Preparation)."""
    incident_repo = IncidentRepository(db)
    record = await incident_repo.get(id)
    if not record:
        res = await incident_repo.get_multi(query={"incident_id": id}, limit=1)
        if res:
            record = res[0]
            
    if not record:
        raise HTTPException(status_code=404, detail="Incident record not found")
        
    try:
        draft = await IncidentResponseService.generate_complaint_draft(
            db=db,
            incident_id=record["incident_id"],
            template_type=template_type,
            recipient_entity=recipient_entity
        )
        return {"status": "success", "complaint_draft": draft}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{id}/download")
async def download_evidence_package(
    id: str,
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Retrieve and download the generated packaged ZIP forensics bundle (Evidence Package)."""
    incident_repo = IncidentRepository(db)
    record = await incident_repo.get(id)
    if not record:
        res = await incident_repo.get_multi(query={"incident_id": id}, limit=1)
        if res:
            record = res[0]
            
    if not record:
        raise HTTPException(status_code=404, detail="Incident record not found")
        
    # Check cache first
    cache_key = f"evidence:zip:{record['incident_id']}"
    cached_base64 = await cache_manager.get(cache_key)
    if cached_base64:
        zip_bytes = base64.b64decode(cached_base64)
        return Response(
            content=zip_bytes,
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename=evidence_{record['incident_id']}.zip"}
        )
        
    # Fetch from database
    evidence_repo = EvidencePackagesRepository(db)
    evidence = await evidence_repo.get_multi(query={"email_id": record["affected_email"]}, limit=1)
    if not evidence:
        # Generate synchronously if missing
        zip_bytes = await IncidentResponseService.generate_forensic_bundle(db, record["incident_id"])
    else:
        zip_bytes = base64.b64decode(evidence[0]["content_payload"])
        
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=evidence_{record['incident_id']}.zip"}
    )

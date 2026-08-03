from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from app.api.dependencies.auth import get_current_active_user
from app.models.user import UserInDB
from app.repositories.email_repo import EmailRepository
from app.database.connection import db_manager
from app.services.threat_detector import ThreatDetectorService

router = APIRouter()

async def get_email_repo() -> EmailRepository:
    if db_manager.db is None:
         raise RuntimeError("Database connection not ready.")
    return EmailRepository(db_manager.db)

@router.post("/analyze")
async def analyze_email_threats(
    payload: Dict[str, str],
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Run multi-engine threat detection pipeline on an ingested email, returning risk score & evidence."""
    email_id = payload.get("email_id")
    if not email_id:
         raise HTTPException(status_code=400, detail="Missing email_id parameter.")
         
    email_rec = await email_repo.get(email_id)
    if not email_rec:
         raise HTTPException(status_code=404, detail="Email record not found.")
         
    if email_rec.get("user_id") != str(current_user.id):
         raise HTTPException(status_code=403, detail="Forbidden: cannot access another user's email.")
         
    # Perform threat analysis using the 12-detector service
    analysis = await ThreatDetectorService.analyze_email(email_rec, db_manager.db)
    
    # Save the analysis result back to the email record
    updates = {
        "analysis": analysis.model_dump(),
        "processing_status": "completed"
    }
    await email_repo.update(email_id, updates)
    return analysis

@router.get("/history")
async def get_threat_history(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Retrieve historical emails flagged as suspicious, spam, or phishing."""
    user_id = str(current_user.id)
    # Match any non-SAFE verdict
    query = {
        "user_id": user_id,
        "analysis.verdict": {"$in": ["PHISHING", "SUSPICIOUS", "SPAM", "MALWARE", "BEC", "CREDENTIAL_HARVESTING"]}
    }
    results = await email_repo.get_multi(query=query, skip=skip, limit=limit, sort_by="date", sort_desc=True)
    for r in results:
         r["_id"] = str(r["_id"])
    return results

@router.get("/evidence/{id}")
async def get_threat_evidence(
    id: str,
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Retrieve structured positive & negative evidence lists for explainable auditing."""
    email_rec = await email_repo.get(id)
    if not email_rec:
         raise HTTPException(status_code=404, detail="Email record not found.")
         
    if email_rec.get("user_id") != str(current_user.id):
         raise HTTPException(status_code=403, detail="Forbidden.")
         
    analysis = email_rec.get("analysis")
    if not analysis:
         raise HTTPException(status_code=404, detail="Threat analysis data is not available for this email.")
         
    return {
        "email_id": id,
        "verdict": analysis.get("verdict"),
        "risk_score": analysis.get("risk_score"),
        "positive_evidence": analysis.get("positive_evidence", []),
        "negative_evidence": analysis.get("negative_evidence", []),
        "detectors_run": analysis.get("detector_sources", [])
    }

@router.get("/{id}")
async def get_threat_by_id(
    id: str,
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Retrieve threat analysis details of a specific email."""
    email_rec = await email_repo.get(id)
    if not email_rec:
         raise HTTPException(status_code=404, detail="Email record not found.")
         
    if email_rec.get("user_id") != str(current_user.id):
         raise HTTPException(status_code=403, detail="Forbidden.")
         
    analysis = email_rec.get("analysis")
    if not analysis:
         raise HTTPException(status_code=404, detail="Threat analysis data is not available for this email.")
         
    return analysis

@router.post("/reanalyze")
async def reanalyze_threats(
    payload: Dict[str, str],
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Clear threat analysis status and re-run the 12-detector pipeline."""
    email_id = payload.get("email_id")
    if not email_id:
         raise HTTPException(status_code=400, detail="Missing email_id parameter.")
         
    email_rec = await email_repo.get(email_id)
    if not email_rec:
         raise HTTPException(status_code=404, detail="Email record not found.")
         
    if email_rec.get("user_id") != str(current_user.id):
         raise HTTPException(status_code=403, detail="Forbidden.")
         
    # Clear threat details and run analyze
    analysis = await ThreatDetectorService.analyze_email(email_rec, db_manager.db)
    updates = {
        "analysis": analysis.model_dump(),
        "processing_status": "completed"
    }
    await email_repo.update(email_id, updates)
    return {"status": "success", "message": "Email re-analyzed successfully.", "verdict": analysis.verdict}

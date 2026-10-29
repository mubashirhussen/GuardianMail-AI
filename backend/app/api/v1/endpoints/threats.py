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

# =========================================================================
# URL THREAT INTELLIGENCE & INCIDENT INVESTIGATION MODULE (MASTER PROMPT)
# =========================================================================
from app.services.url_threat_intelligence_service import URLThreatIntelligenceService

@router.post("/scan-url")
@router.post("/url-investigations")
async def scan_or_investigate_url(
    payload: Dict[str, Any],
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Investigate a submitted URL using real RDAP, DNS, TLS, multi-provider threat intelligence,
    SSRF protections, community reports, and relationship graph generation.
    """
    raw_url = payload.get("url", "").strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="Missing required 'url' parameter.")

    # Guard against unusually long inputs
    if len(raw_url) > 2048:
        raise HTTPException(status_code=400, detail="URL exceeds maximum allowed length of 2048 characters.")

    result = await URLThreatIntelligenceService.investigate_url(raw_url, str(current_user.id))
    return result

@router.get("/url-history")
async def get_url_scan_history(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Retrieve historical URL investigations for the current user."""
    if db_manager.db is None:
        return []
    
    cursor = db_manager.db["url_investigations"].find(
        {"user_id": str(current_user.id)}
    ).sort("created_at", -1).skip(skip).limit(limit)
    
    records = await cursor.to_list(length=limit)
    for r in records:
        r.pop("_id", None)
    return records

@router.get("/url-investigations/{investigation_id}")
async def get_url_investigation_by_id(
    investigation_id: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Retrieve a specific URL investigation by its ID."""
    if db_manager.db is None:
        raise HTTPException(status_code=500, detail="Database not connected.")
        
    doc = await db_manager.db["url_investigations"].find_one({"investigation_id": investigation_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Investigation record not found.")
        
    doc.pop("_id", None)
    return doc

@router.get("/url-investigations/{investigation_id}/evidence")
async def get_url_investigation_evidence(
    investigation_id: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Retrieve structured evidence and provenance for an investigation."""
    if db_manager.db is None:
        raise HTTPException(status_code=500, detail="Database not connected.")
        
    doc = await db_manager.db["url_investigations"].find_one({"investigation_id": investigation_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Investigation record not found.")
        
    return {
        "investigation_id": investigation_id,
        "indicators": doc.get("indicators", []),
        "positive_evidence": doc.get("positive_evidence", []),
        "contradictory_evidence": doc.get("contradictory_evidence", []),
        "security_providers": doc.get("security_providers", []),
        "connection_security": doc.get("connection_security", {})
    }

@router.get("/url-investigations/{investigation_id}/reports")
async def get_investigation_reports(
    investigation_id: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Retrieve community and internal reports related to an investigation."""
    if db_manager.db is None:
        return {"reports": []}
        
    inv = await db_manager.db["url_investigations"].find_one({"investigation_id": investigation_id})
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
        
    url = inv.get("url")
    reports = await db_manager.db["url_reports"].find({"url": url}).to_list(length=50)
    for r in reports:
        r.pop("_id", None)
    return {"reports": reports, "summary": inv.get("community_reports", {})}

@router.post("/url-investigations/{investigation_id}/reports")
async def submit_investigation_report(
    investigation_id: str,
    payload: Dict[str, Any],
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Submit a user community report about a suspicious URL."""
    if db_manager.db is None:
        raise HTTPException(status_code=500, detail="Database not ready.")
        
    inv = await db_manager.db["url_investigations"].find_one({"investigation_id": investigation_id})
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
        
    category = payload.get("category", "Phishing")
    explanation = payload.get("explanation", "").strip()
    
    report_doc = {
        "report_id": f"REP-{uuid.uuid4().hex[:8].upper()}",
        "investigation_id": investigation_id,
        "url": inv.get("url"),
        "domain": inv.get("domain"),
        "user_id": str(current_user.id),
        "user_email": current_user.email,
        "category": category,
        "explanation": explanation,
        "status": "pending",
        "submitted_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db_manager.db["url_reports"].insert_one(report_doc)
    report_doc.pop("_id", None)
    return {"status": "success", "message": "Report submitted for moderation.", "report": report_doc}

@router.get("/url-investigations/{investigation_id}/relationships")
async def get_investigation_relationships(
    investigation_id: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Retrieve relationship graph nodes and edges for an investigation."""
    if db_manager.db is None:
        raise HTTPException(status_code=500, detail="Database not connected.")
        
    doc = await db_manager.db["url_investigations"].find_one({"investigation_id": investigation_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Investigation not found.")
        
    return doc.get("relationships", {"nodes": [], "edges": []})

@router.get("/url-investigations/{investigation_id}/export")
async def export_investigation_json(
    investigation_id: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Export complete investigation dossier as JSON format."""
    if db_manager.db is None:
        raise HTTPException(status_code=500, detail="Database not connected.")
        
    doc = await db_manager.db["url_investigations"].find_one({"investigation_id": investigation_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Investigation not found.")
        
    doc.pop("_id", None)
    return doc


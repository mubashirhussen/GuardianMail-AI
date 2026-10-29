from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from app.api.dependencies.auth import get_current_active_user
from app.models.user import UserInDB
from app.models.email import EmailRecord
from app.repositories.email_repo import EmailRepository
from app.database.connection import db_manager

router = APIRouter()

async def get_email_repo() -> EmailRepository:
    if db_manager.db is None:
         raise RuntimeError("Database connection not ready.")
    return EmailRepository(db_manager.db)

@router.get("/")
async def get_emails(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    sender: Optional[str] = None,
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Retrieve a paginated list of normalized emails matching filters, incorporating uploaded email attachments."""
    user_id = str(current_user.id)
    query = {"user_id": user_id}
    if sender:
         query["from_address"] = {"$regex": sender, "$options": "i"}
         
    emails = await email_repo.get_multi(query=query, skip=skip, limit=limit, sort_by="date", sort_desc=True)
    existing_subjects = {str(e.get("subject", "")).lower() for e in emails}

    # Also pull scanned email files (.eml, .msg) from attachments collection
    if db_manager.db is not None:
        try:
            att_cursor = db_manager.db["attachments"].find({"user_id": user_id}).sort("created_at", -1).limit(limit)
            attachments = await att_cursor.to_list(length=limit)
            for att in attachments:
                fn = att.get("filename", "")
                meta = att.get("analysis", {}).get("embedded_metadata", {})
                subj = meta.get("subject") or fn
                if subj.lower() in existing_subjects:
                    continue
                
                # Synthesize email record for inbox display
                analysis = att.get("analysis", {})
                verdict = att.get("verdict", "SAFE")
                risk = att.get("risk_score", 10)
                extracted_text = analysis.get("extracted_text", "")
                created_dt = att.get("created_at")
                
                synth_email = {
                    "_id": str(att["_id"]),
                    "user_id": user_id,
                    "from_address": meta.get("from") or "sender@domain.com",
                    "to_address": meta.get("to") or current_user.email,
                    "subject": subj,
                    "body_text": extracted_text or f"Scanned file: {fn}",
                    "body_html": f"<pre>{extracted_text or fn}</pre>",
                    "date": created_dt.isoformat() if hasattr(created_dt, "isoformat") else str(created_dt),
                    "processing_status": "completed",
                    "analysis": {
                        "verdict": verdict,
                        "risk_score": risk,
                        "confidence": 0.95,
                        "threat_types": [verdict.lower()] if verdict != "SAFE" else [],
                        "indicators": analysis.get("risk_indicators", []),
                        "timestamp": att.get("analysis", {}).get("scan_timestamp")
                    },
                    "is_attachment_scan": True,
                    "filename": fn
                }
                emails.insert(0, synth_email)
                existing_subjects.add(subj.lower())
        except Exception:
            pass

    # Map _id string
    for e in emails:
         e["_id"] = str(e["_id"])
    return emails[:limit]

@router.get("/search")
async def search_emails(
    q: str = Query(..., min_length=1),
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Search email headers or bodies using MongoDB text indexing search."""
    user_id = str(current_user.id)
    query = {
        "user_id": user_id,
        "$text": {"$search": q}
    }
    results = await email_repo.get_multi(query=query, limit=50)
    for r in results:
         r["_id"] = str(r["_id"])
    return results

@router.get("/{id}")
async def get_email_by_id(
    id: str,
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Retrieve details of a specific normalized email by its ID."""
    email_doc = await email_repo.get(id)
    if not email_doc:
         raise HTTPException(status_code=404, detail="Email record not found.")
         
    user_id = str(current_user.id)
    if email_doc["user_id"] != user_id:
         raise HTTPException(status_code=403, detail="Forbidden: cannot access another user's email.")
         
    email_doc["_id"] = str(email_doc["_id"])
    return email_doc

@router.get("/thread/{thread_id}")
async def get_emails_thread(
    thread_id: str,
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Retrieve all normalized emails belonging to the same thread ID."""
    user_id = str(current_user.id)
    query = {
        "user_id": user_id,
        "thread_id": thread_id
    }
    emails = await email_repo.get_multi(query=query, sort_by="date", sort_desc=False)
    for e in emails:
         e["_id"] = str(e["_id"])
    return emails

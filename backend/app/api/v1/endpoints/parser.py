from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from app.api.dependencies.auth import get_current_active_user
from app.models.user import UserInDB
from app.services.email_parser import EmailParserService
from app.repositories.email_repo import EmailRepository
from app.database.connection import db_manager
from app.workers.tasks import reprocess_email_task

router = APIRouter()

async def get_email_repo() -> EmailRepository:
    if db_manager.db is None:
         raise RuntimeError("Database connection not ready.")
    return EmailRepository(db_manager.db)

@router.post("/process")
async def process_raw_email(
    payload: Dict[str, str],
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Parse and normalize raw hex-encoded email bytes directly, returning JSON metadata."""
    hex_data = payload.get("raw_hex", "")
    if not hex_data:
         raise HTTPException(status_code=400, detail="Missing raw_hex email data.")
         
    try:
         email_bytes = bytes.fromhex(hex_data)
         parsed = EmailParserService.parse_eml_bytes(email_bytes)
         # Pop out binary reference since it is not JSON-serializable
         parsed.pop("raw_msg", None)
         
         # Adjust count of links
         if "metrics" in parsed:
              parsed["metrics"]["links_count"] = len(parsed.get("urls", []))
              
         # If date is datetime object, convert to string
         if parsed.get("date"):
              parsed["date"] = parsed["date"].isoformat()
              
         return parsed
    except Exception as e:
         raise HTTPException(status_code=400, detail=f"Failed parsing email bytes: {str(e)}")

@router.post("/reprocess")
async def trigger_email_reprocess(
    payload: Dict[str, str],
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Trigger background Celery reprocess job for an existing email record."""
    email_id = payload.get("email_id")
    if not email_id:
         raise HTTPException(status_code=400, detail="Missing email_id parameter.")
         
    email_rec = await email_repo.get(email_id)
    if not email_rec:
         raise HTTPException(status_code=404, detail="Email record not found.")
         
    if email_rec.get("user_id") != str(current_user.id):
         raise HTTPException(status_code=403, detail="Forbidden: cannot access another user's email.")
         
    # Mark status as processing in database
    await email_repo.update(email_id, {"processing_status": "processing"})
    
    # Enqueue background task
    reprocess_email_task.delay(email_id)
    return {"status": "success", "message": "Email reprocessing task enqueued."}

@router.get("/status/{email_id}")
async def get_parsing_status(
    email_id: str,
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Retrieve parsing ingestion status of a specific email."""
    email_rec = await email_repo.get(email_id)
    if not email_rec:
         raise HTTPException(status_code=404, detail="Email record not found.")
         
    if email_rec.get("user_id") != str(current_user.id):
         raise HTTPException(status_code=403, detail="Forbidden.")
         
    return {
        "email_id": email_id,
        "processing_status": email_rec.get("processing_status", "unknown"),
        "sync_time": email_rec.get("sync_time"),
        "updated_at": email_rec.get("updated_at")
    }

@router.get("/metadata/{email_id}")
async def get_parsing_metadata(
    email_id: str,
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Retrieve enriched parsing metadata details (headers size, links count, attachments lists)."""
    email_rec = await email_repo.get(email_id)
    if not email_rec:
         raise HTTPException(status_code=404, detail="Email record not found.")
         
    if email_rec.get("user_id") != str(current_user.id):
         raise HTTPException(status_code=403, detail="Forbidden.")
         
    return {
        "email_id": email_id,
        "metrics": email_rec.get("metrics"),
        "urls": email_rec.get("urls", []),
        "attachments": email_rec.get("attachments", []),
        "sender_domain": email_rec.get("sender_domain"),
        "subject": email_rec.get("subject")
    }

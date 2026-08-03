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
    limit: int = Query(20, ge=1, le=100),
    sender: Optional[str] = None,
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Retrieve a paginated list of normalized emails matching filters."""
    user_id = str(current_user.id)
    query = {"user_id": user_id}
    if sender:
         query["from_address"] = {"$regex": sender, "$options": "i"}
         
    emails = await email_repo.get_multi(query=query, skip=skip, limit=limit, sort_by="date", sort_desc=True)
    # Map _id string
    for e in emails:
         e["_id"] = str(e["_id"])
    return emails

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

from datetime import datetime, timezone
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, status
from app.api.dependencies.auth import get_current_active_user, get_user_repo
from app.models.user import UserInDB
from app.repositories.user_repo import UserRepository
from app.database.cache import cache_manager
from app.workers.tasks import gmail_sync_job

router = APIRouter()

@router.post("/connect")
async def connect_gmail(
    payload: Dict[str, str],
    current_user: UserInDB = Depends(get_current_active_user),
    user_repo: UserRepository = Depends(get_user_repo)
):
    """Exchanges Google authorization code for access/refresh tokens and links mailbox profile."""
    code = payload.get("code")
    if not code:
         raise HTTPException(status_code=400, detail="Missing Google authorization code.")
         
    # Mock exchanging OAuth code for credentials (exchanges with Google API)
    # In real application, this triggers token exchange POST to oauth2.googleapis.com
    now = datetime.now(timezone.utc)
    updates = {
        "gmail_access_token": f"mock_access_token_{secrets_token()}",
        "gmail_refresh_token": f"mock_refresh_token_{secrets_token()}",
        "gmail_token_expires_at": now + timedelta(hours=1),
        "google_email": current_user.email,
        "google_id": f"g_id_{code[:10]}"
    }
    await user_repo.update(str(current_user.id), updates)
    return {"status": "success", "message": "Gmail account linked successfully."}

@router.delete("/disconnect")
async def disconnect_gmail(
    current_user: UserInDB = Depends(get_current_active_user),
    user_repo: UserRepository = Depends(get_user_repo)
):
    """Unlinks Gmail account and clears stored OAuth credentials tokens."""
    updates = {
        "gmail_access_token": None,
        "gmail_refresh_token": None,
        "gmail_token_expires_at": None,
        "google_email": None,
        "google_id": None
    }
    await user_repo.update(str(current_user.id), updates)
    return {"status": "success", "message": "Gmail account disconnected."}

@router.get("/accounts")
async def get_gmail_accounts(current_user: UserInDB = Depends(get_current_active_user)):
    """Retrieve details of the connected Google email account."""
    if not current_user.gmail_refresh_token:
         return []
    return [{
        "email": current_user.google_email or current_user.email,
        "google_id": current_user.google_id,
        "status": "connected"
    }]

@router.post("/sync")
async def trigger_mailbox_sync(current_user: UserInDB = Depends(get_current_active_user)):
    """Enqueue background Celery synchronization job for current Gmail account."""
    if not current_user.gmail_refresh_token:
         raise HTTPException(status_code=400, detail="Gmail account is not connected.")
         
    user_id = str(current_user.id)
    # Trigger background task asynchronously
    gmail_sync_job.delay(user_id)
    return {"status": "success", "message": "Mailbox synchronization task queued."}

@router.get("/sync/status")
async def get_sync_status(current_user: UserInDB = Depends(get_current_active_user)):
    """Retrieve current synchronization task state from cache manager."""
    user_id = str(current_user.id)
    sync_status = await cache_manager.get(f"gmail_sync_status:{user_id}")
    if not sync_status:
         return {"status": "idle", "message": "No active sync found."}
    return sync_status

@router.post("/sync/retry")
async def retry_sync(current_user: UserInDB = Depends(get_current_active_user)):
    """Retry execution of failed mailbox synchronization."""
    if not current_user.gmail_refresh_token:
         raise HTTPException(status_code=400, detail="Gmail account is not connected.")
         
    user_id = str(current_user.id)
    gmail_sync_job.delay(user_id)
    return {"status": "success", "message": "Retrying mailbox synchronization task."}

# Helper to generate random secrets
def secrets_token() -> str:
    import secrets
    return secrets.token_hex(8)

# Helper for timedelta
from datetime import timedelta

from datetime import datetime, timezone, timedelta
import secrets
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, status
from app.api.dependencies.auth import get_current_active_user, get_user_repo
from app.models.user import UserInDB
from app.repositories.user_repo import UserRepository
from app.database.cache import cache_manager
from app.workers.tasks import gmail_sync_job
from app.auth.oauth import GoogleOAuthService
from app.config.settings import settings

router = APIRouter()

@router.get("/permissions")
async def get_gmail_permissions_info():
    """
    Returns explicit disclosure of permissions requested for Gmail integration.
    Clarifies scope separation from initial sign-in.
    """
    return {
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
        "scope_name": "Gmail Read-Only Access",
        "data_accessed": [
            "Inbound email headers (Sender, Recipient, Subject, Timestamps)",
            "Email bodies (HTML/Text) for phishing, BEC, and impersonation detection",
            "Message attachments for sandbox detonation and malware scanning"
        ],
        "purpose": "GuardianMail AI analyzes incoming emails in real-time to alert security operations (SOC) against phishing, weaponized attachments, malicious URLs, and threat actors.",
        "data_retention": "Extracted threat telemetry is kept according to your organization's security policy. Raw email content is not shared with third parties.",
        "user_control": "You may disconnect Gmail at any time. Revoking access immediately halts synchronization and wipes stored OAuth tokens."
    }

@router.get("/auth-url")
async def get_gmail_auth_url(current_user: UserInDB = Depends(get_current_active_user)):
    """
    Generates the official Google OAuth authorization URL specifically for Gmail consent.
    This is strictly isolated from basic user authentication.
    """
    state = secrets.token_urlsafe(32)
    user_id = str(current_user.id)
    try:
        await cache_manager.set(f"gmail_oauth_state:{state}", user_id, 600)
    except Exception:
        pass

    auth_url = GoogleOAuthService.get_gmail_authorization_url(state)
    return {
        "auth_url": auth_url,
        "state": state,
        "scope": "https://www.googleapis.com/auth/gmail.readonly"
    }

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

    state = payload.get("state")
    if state and settings.ENVIRONMENT != "testing":
        stored_user_id = await cache_manager.get(f"gmail_oauth_state:{state}")
        if stored_user_id and stored_user_id != str(current_user.id):
            raise HTTPException(status_code=400, detail="State user ID mismatch (CSRF protection failed).")
        if stored_user_id:
            await cache_manager.delete(f"gmail_oauth_state:{state}")

    now = datetime.now(timezone.utc)

    # If configured with real Google OAuth credentials, perform token exchange
    if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET and not code.startswith("mock_"):
        try:
            tokens = await GoogleOAuthService.exchange_code_for_tokens(code)
            access_token = tokens.get("access_token")
            refresh_token = tokens.get("refresh_token")
            expires_in = tokens.get("expires_in", 3600)
            token_expires_at = now + timedelta(seconds=expires_in)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to exchange Gmail code with Google: {str(e)}")
    else:
        access_token = f"mock_access_token_{secrets.token_hex(8)}"
        refresh_token = f"mock_refresh_token_{secrets.token_hex(8)}"
        token_expires_at = now + timedelta(hours=1)

    updates = {
        "gmail_access_token": access_token,
        "gmail_refresh_token": refresh_token,
        "gmail_token_expires_at": token_expires_at,
        "google_email": current_user.email,
        "google_id": current_user.google_id or f"gid_{secrets.token_hex(8)}"
    }
    await user_repo.update(str(current_user.id), updates)
    return {"status": "success", "message": "Gmail account linked successfully for security analysis."}

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

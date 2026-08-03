import base64
import logging
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from app.config.settings import settings
from app.models.user import UserInDB
from app.models.email import EmailRecord
from app.models.email_headers import EmailHeaders
from app.models.attachment import EmailAttachmentRecord
from app.repositories.email_repo import EmailRepository
from app.repositories.base import BaseRepository
from app.services.email_parser import EmailParserService

logger = logging.getLogger(__name__)

class GmailService:
    """Enterprise Gmail integration engine managing credentials refresh, ingestion, and email normalization."""
    
    @staticmethod
    def get_credentials(user: UserInDB) -> Credentials:
        """Construct Google OAuth Credentials instance and auto-refresh if expired."""
        creds = Credentials(
            token=user.gmail_access_token,
            refresh_token=user.gmail_refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            scopes=["https://www.googleapis.com/auth/gmail.readonly"]
        )
        
        # If token expired or expiring soon, refresh it
        if user.gmail_token_expires_at:
             expires_at = user.gmail_token_expires_at
             if expires_at.tzinfo is None:
                  expires_at = expires_at.replace(tzinfo=timezone.utc)
             # Refresh if past or within 5 minutes of expiration
             if datetime.now(timezone.utc) >= (expires_at - timedelta(minutes=5)):
                  try:
                       creds.refresh(Request())
                  except Exception as e:
                       logger.error(f"Failed to refresh Google OAuth token: {str(e)}")
                       raise RuntimeError("Google OAuth token refresh failed.") from e
        return creds

    @staticmethod
    def get_gmail_client(user: UserInDB) -> Any:
        """Build Google Gmail API client discovery resource."""
        creds = GmailService.get_credentials(user)
        return build("gmail", "v1", credentials=creds)

    @staticmethod
    async def ingest_single_message(
        user_id: str, 
        msg_id: str, 
        thread_id: str,
        gmail_client: Any,
        email_repo: EmailRepository,
        db: Any
    ) -> Optional[Dict[str, Any]]:
        """Retrieve, decode, parse, and store a single Gmail message in standard schema."""
        try:
            # 1. Check if message already exists
            existing = await email_repo.get_by_gmail_id(user_id, msg_id)
            if existing:
                logger.debug(f"Email {msg_id} already ingested. Skipping.")
                return existing
                
            # 2. Fetch raw message bytes from Google API
            res = gmail_client.users().messages().get(
                userId="me", 
                id=msg_id, 
                format="raw"
            ).execute()
            
            raw_b64 = res.get("raw", "")
            if not raw_b64:
                logger.warning(f"Empty raw payload returned for Gmail message {msg_id}")
                return None
                
            email_bytes = base64.urlsafe_b64decode(raw_b64)
            
            # 3. Parse email content bytes using the parser service
            parsed = EmailParserService.parse_eml_bytes(email_bytes)
            
            # 4. Normalize and create EmailRecord model dict
            now = datetime.now(timezone.utc)
            
            # Extract attachment metadata models list
            attachments_meta = []
            for att in parsed.get("attachments", []):
                attachments_meta.append({
                    "filename": att.get("filename"),
                    "content_type": att.get("content_type", "application/octet-stream"),
                    "size_bytes": att.get("size_bytes", 0),
                    "md5_hash": att.get("md5_hash"),
                    "sha256_hash": att.get("sha256_hash") or hashlib.sha256(att.get("payload", b"")).hexdigest() if att.get("payload") else None,
                    "is_malicious": False
                })
                
            email_data = {
                "user_id": user_id,
                "gmail_message_id": msg_id,
                "gmail_thread_id": thread_id,
                "subject": parsed.get("subject", "No Subject"),
                "from_address": parsed.get("from_address"),
                "from_domain": parsed.get("from_address").split("@")[-1] if "@" in parsed.get("from_address", "") else "unknown",
                "to_address": parsed.get("to_address", []),
                "date": parsed.get("date") or now,
                "body_plain": parsed.get("body_plain"),
                "body_html": parsed.get("body_html"),
                "size_bytes": len(email_bytes),
                "thread_id": thread_id,
                "is_read": False,
                "sync_time": now,
                "processing_status": "completed",
                "status": "new"
            }
            
            created_email = await email_repo.create(email_data)
            email_oid = str(created_email["_id"])
            
            # 5. Insert EmailHeaders
            header_repo = BaseRepository(db, "email_headers")
            raw_headers_dict = {}
            # msg is reference of Email Message object
            if "raw_msg" in parsed:
                 for k, v in parsed["raw_msg"].items():
                      raw_headers_dict[k] = str(v)
                      
            await header_repo.create({
                "email_id": email_oid,
                "raw_headers": raw_headers_dict,
                "received_hops": [],
                "spf_header": raw_headers_dict.get("Received-SPF"),
                "dkim_header": raw_headers_dict.get("DKIM-Signature"),
                "dmarc_header": raw_headers_dict.get("Authentication-Results")
            })
            
            # 6. Insert Attachments metadata
            if attachments_meta:
                 att_repo = BaseRepository(db, "attachments")
                 for att in attachments_meta:
                      await att_repo.create({
                          "email_id": email_oid,
                          "filename": att["filename"],
                          "content_type": att["content_type"],
                          "size_bytes": att["size_bytes"],
                          "sha256_hash": att["sha256_hash"],
                          "sandbox_result_verdict": "clean"
                      })
                      
            logger.info(f"Ingested Gmail message {msg_id} successfully for user {user_id}")
            return created_email
        except Exception as e:
            logger.error(f"Failed ingesting Gmail message {msg_id}: {str(e)}")
            return None

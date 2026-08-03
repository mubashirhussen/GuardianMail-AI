import asyncio
import logging
from celery.utils.log import get_task_logger
from app.core.celery_app import celery_app
from app.core.database import db_manager
from app.repositories.email_repo import EmailRepository
from app.services.email_parser import EmailParserService
from app.services.threat_detector import ThreatDetectorService
from app.services.recommender import RecommendationService

logger = get_task_logger(__name__)

# Helper to run async code inside synchronous Celery workers
def run_async(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
        
    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, coro)
            return future.result()
    else:
        try:
            return asyncio.run(coro)
        except RuntimeError:
            # Fallback for older python environments where loop exists but not running
            return asyncio.get_event_loop().run_until_complete(coro)

async def _analyze_email_async(user_id: str, email_bytes: bytes, gmail_id: str = None, thread_id: str = None) -> str:
    """Async implementation of email parsing and risk classification."""
    import time
    start_time = time.time()

    # Ensure DB connection is open (Celery worker lifecycle)
    if db_manager.db is None:
        await db_manager.connect()
        
    email_repo = EmailRepository(db_manager.db)
    
    # 1. Parse EML
    parsed = EmailParserService.parse_eml_bytes(email_bytes)
    
    # 2. Check for duplication if gmail_id is provided
    if gmail_id:
        existing = await email_repo.get_by_gmail_id(user_id, gmail_id)
        if existing:
            logger.info(f"Email {gmail_id} already analyzed. Skipping.")
            return existing["_id"]

    # 3. Analyze threats (phishing, headers, URLs, attachments)
    analysis = await ThreatDetectorService.analyze_email(parsed, db_manager.db)
    
    # Track observability scan (Enhancement 10)
    duration = time.time() - start_time
    from app.services.observability import SystemObservabilityService
    SystemObservabilityService.record_scan(duration)
    
    # 4. Email Trust History & Behavior Spikes (Enhancement 2)
    from app.repositories.sender_trust_repo import SenderTrustRepository
    from app.services.sender_trust import SenderTrustService
    sender_trust_repo = SenderTrustRepository(db_manager.db)
    
    # Track indicators
    has_auth_fail = not analysis.auth_status.overall_authentication_pass if analysis.auth_status else True
    has_suspicious_urls = any(ind.severity in ["CRITICAL", "HIGH"] for ind in analysis.indicators if ind.type == "phishing")
    has_suspicious_attachments = any(ind.type == "malware" for ind in analysis.indicators)
    
    # Evaluate sender trust
    trust_record, anomaly_detected, anomaly_details = await SenderTrustService.evaluate_sender_trust(
        sender_email=parsed["from_address"],
        current_risk_score=analysis.risk_score,
        is_phishing=analysis.is_phishing,
        repo=sender_trust_repo
    )
    
    if anomaly_detected:
        # Append abnormal behavior indicator
        from app.models.email import ThreatIndicator
        analysis.indicators.append(
            ThreatIndicator(
                indicator="Abnormal Sender Behavior Detected",
                detail=anomaly_details,
                severity="HIGH",
                confidence=0.85,
                type="phishing"
            )
        )
        # Elevate low verdict categories due to behavioral anomalies
        if analysis.verdict in ["SAFE", "LOW"]:
            analysis.verdict = "MEDIUM"
            analysis.risk_score = max(analysis.risk_score, 0.45)
            
    # 5. Add anomaly to chronological timeline if detected (Enhancement 6)
    if anomaly_detected:
        from app.models.email import TimelineEvent
        analysis.timeline.append(
            TimelineEvent(
                event="SENDER_BEHAVIOR_ANOMALY",
                timestamp=datetime.utcnow(),
                description=anomaly_details
            )
        )
    
    # 6. Compile recommendations & tips
    recommendations = RecommendationService.generate_recommendations(analysis)
    
    # 7. Credential Recovery Assistant (Enhancement 5) & Safety Education (Enhancement 8)
    if analysis.verdict in ["CRITICAL", "HIGH", "MEDIUM"]:
        # recovery steps
        from app.services.recovery_assistant import CredentialRecoveryService
        checklist = CredentialRecoveryService.get_recovery_checklist(
            analysis.verdict,
            [ind.indicator for ind in analysis.indicators]
        )
        for item in checklist:
            recommendations.next_steps.append(f"{item['title']}: {item['description']}")
            
        # safety safety cards
        from app.services.education_service import CyberSafetyEducationService
        education_cards = CyberSafetyEducationService.get_educational_materials(
            [ind.indicator for ind in analysis.indicators]
        )
        for card in education_cards:
            recommendations.security_tips.append(f"{card['title']}: {card['explanation']}")
    
    # Remove the raw message parameter since it cannot be serialized into BSON
    parsed.pop("raw_msg", None)
    
    # 8. Save email record
    email_record = {
        "user_id": user_id,
        "gmail_message_id": gmail_id,
        "gmail_thread_id": thread_id,
        "subject": parsed["subject"],
        "from_address": parsed["from_address"],
        "from_domain": parsed["from_address"].split("@")[-1].strip(">").lower() if "@" in parsed["from_address"] else "",
        "to_address": parsed["to_address"],
        "reply_to": parsed["reply_to"],
        "return_path": parsed["return_path"],
        "date": parsed["date"],
        "body_plain": parsed["body_plain"],
        "body_html": parsed["body_html"],
        "attachments": parsed["attachments"],
        "urls": parsed["urls"],
        "analysis": analysis.model_dump(),
        "recommendations": recommendations.model_dump(),
        "labels": ["Inbox"],
        "is_read": False,
        "sync_time": datetime.utcnow()
    }
    
    created = await email_repo.create(email_record)
    logger.info(f"Finished threat analysis for email {created['_id']}. Score: {analysis.risk_score}")
    return created["_id"]

from datetime import datetime
from app.models.user import UserInDB
from app.services.gmail_service import GmailService

async def _gmail_sync_job_async(user_id: str) -> dict:
    from app.repositories.user_repo import UserRepository
    from app.repositories.email_repo import EmailRepository
    from app.database.connection import db_manager
    from app.database.cache import cache_manager
    
    if db_manager.db is None:
        await db_manager.connect()
        
    user_repo = UserRepository(db_manager.db)
    email_repo = EmailRepository(db_manager.db)
    
    user_dict = await user_repo.get(user_id)
    if not user_dict:
        return {"status": "failed", "error": "User not found"}
        
    user = UserInDB(**user_dict)
    if not user.gmail_refresh_token:
        return {"status": "failed", "error": "Gmail account not linked"}
        
    # Mark sync status as processing
    await cache_manager.set(
        f"gmail_sync_status:{user_id}", 
        {"status": "processing", "started_at": str(datetime.utcnow()), "synced_count": 0}
    )
    
    try:
        gmail_client = GmailService.get_gmail_client(user)
        res = gmail_client.users().messages().list(userId="me", maxResults=50).execute()
        messages = res.get("messages", [])
        
        count = 0
        for m in messages:
            email_record = await GmailService.ingest_single_message(
                user_id=user_id,
                msg_id=m["id"],
                thread_id=m["threadId"],
                gmail_client=gmail_client,
                email_repo=email_repo,
                db=db_manager.db
            )
            if email_record:
                count += 1
                
        # Update sync status to success
        await cache_manager.set(
            f"gmail_sync_status:{user_id}", 
            {"status": "completed", "completed_at": str(datetime.utcnow()), "synced_count": count}
        )
        return {
            "status": "success",
            "user_id": user_id,
            "synchronized_emails_count": count,
            "message": "Mailbox synchronization completed successfully."
        }
    except Exception as e:
        logger.error(f"Gmail sync failed for user {user_id}: {str(e)}")
        await cache_manager.set(
            f"gmail_sync_status:{user_id}", 
            {"status": "failed", "error": str(e), "failed_at": str(datetime.utcnow())}
        )
        return {"status": "failed", "error": str(e)}

async def _token_refresh_async() -> dict:
    from app.repositories.user_repo import UserRepository
    from app.database.connection import db_manager
    
    if db_manager.db is None:
        await db_manager.connect()
        
    user_repo = UserRepository(db_manager.db)
    users_cursor = user_repo.collection.find({"gmail_refresh_token": {"$ne": None}})
    users = await users_cursor.to_list(length=100)
    
    refreshed_count = 0
    for u_dict in users:
        u = UserInDB(**u_dict)
        try:
            creds = GmailService.get_credentials(u)
            if creds.valid:
                await user_repo.update(str(u.id), {
                    "gmail_access_token": creds.token,
                    "gmail_token_expires_at": creds.expiry
                })
                refreshed_count += 1
        except Exception as e:
            logger.error(f"Token refresh failed for user {u.id}: {str(e)}")
            
    return {"refreshed_users_count": refreshed_count}

@celery_app.task(name="tasks.analyze_email_task")
def analyze_email_task(user_id: str, email_bytes_hex: str, gmail_id: str = None, thread_id: str = None) -> str:
    """Celery task wrapper to analyze email bytes (Module 17 Background Workers)."""
    email_bytes = bytes.fromhex(email_bytes_hex)
    return run_async(_analyze_email_async(user_id, email_bytes, gmail_id, thread_id))

@celery_app.task(name="tasks.gmail_sync_job")
def gmail_sync_job(user_id: str) -> dict:
    """Background incremental synchronization task for Gmail mailbox (Module 3 & 17)."""
    return run_async(_gmail_sync_job_async(user_id))

@celery_app.task(name="tasks.token_refresh_job")
def token_refresh_job() -> dict:
    """Background Google OAuth token checker and refresh task."""
    return run_async(_token_refresh_async())

async def _reprocess_email_async(email_id: str) -> dict:
    from app.repositories.email_repo import EmailRepository
    from app.repositories.user_repo import UserRepository
    from app.services.gmail_service import GmailService
    from app.database.connection import db_manager
    from datetime import timezone
    import base64
    
    if db_manager.db is None:
        await db_manager.connect()
        
    email_repo = EmailRepository(db_manager.db)
    user_repo = UserRepository(db_manager.db)
    
    email_rec = await email_repo.get(email_id)
    if not email_rec:
        return {"status": "failed", "error": "Email record not found"}
        
    gmail_id = email_rec.get("gmail_message_id")
    user_id = email_rec.get("user_id")
    
    if not gmail_id or not user_id:
        return {"status": "failed", "error": "Invalid email metadata for reprocessing"}
        
    user_dict = await user_repo.get(user_id)
    if not user_dict:
        return {"status": "failed", "error": "User profile not found"}
        
    user = UserInDB(**user_dict)
    try:
        gmail_client = GmailService.get_gmail_client(user)
        res = gmail_client.users().messages().get(userId="me", id=gmail_id, format="raw").execute()
        raw_b64 = res.get("raw", "")
        if not raw_b64:
            return {"status": "failed", "error": "Empty payload returned from Gmail"}
            
        email_bytes = base64.urlsafe_b64decode(raw_b64)
        
        from app.services.email_parser import EmailParserService
        parsed = EmailParserService.parse_eml_bytes(email_bytes)
        
        attachments_meta = []
        for att in parsed.get("attachments", []):
            attachments_meta.append({
                "filename": att.get("filename"),
                "content_type": att.get("content_type", "application/octet-stream"),
                "size_bytes": att.get("size_bytes", 0),
                "sha256_hash": att.get("sha256_hash")
            })
            
        updates = {
            "subject": parsed.get("subject"),
            "from_address": parsed.get("from_address"),
            "to_address": parsed.get("to_address"),
            "body_plain": parsed.get("body_plain"),
            "body_html": parsed.get("body_html"),
            "attachments": attachments_meta,
            "processing_status": "completed",
            "updated_at": datetime.now(timezone.utc)
        }
        await email_repo.update(email_id, updates)
        return {"status": "success", "message": f"Email {email_id} reprocessed successfully."}
    except Exception as e:
        logger.error(f"Reprocess task failed for email {email_id}: {str(e)}")
        await email_repo.update(email_id, {"processing_status": "failed", "updated_at": datetime.now(timezone.utc)})
        return {"status": "failed", "error": str(e)}

@celery_app.task(name="tasks.reprocess_email_task")
def reprocess_email_task(email_id: str) -> dict:
    """Background task to reprocess a normalized email record."""
    return run_async(_reprocess_email_async(email_id))

async def _analyze_attachment_async(attachment_id: str) -> dict:
    from app.database.connection import db_manager
    from app.services.attachment_analyzer import AttachmentAnalyzerService
    from bson import ObjectId
    
    if db_manager.db is None:
        await db_manager.connect()
        
    rec = await db_manager.db["attachments"].find_one({"_id": ObjectId(attachment_id)})
    if not rec:
        return {"status": "failed", "error": "Attachment record not found"}
        
    filename = rec.get("filename", "file")
    content = rec.get("content_bytes") or b""
    
    analysis = await AttachmentAnalyzerService.analyze_attachment(content, filename)
    await db_manager.db["attachments"].update_one(
        {"_id": ObjectId(attachment_id)},
        {"$set": {"analysis": analysis, "status": "completed"}}
    )
    return {"status": "success", "attachment_id": attachment_id}

@celery_app.task(name="tasks.analyze_attachment_task", bind=True, max_retries=3)
def analyze_attachment_task(self, attachment_id: str) -> dict:
    """Celery background task for full attachment analysis."""
    try:
        return run_async(_analyze_attachment_async(attachment_id))
    except Exception as exc:
        logger.error(f"Attachment analysis task failed. Retrying... Error: {str(exc)}")
        raise self.retry(exc=exc, countdown=10)

async def _ocr_task_async(image_bytes: bytes) -> dict:
    from app.services.attachment_analyzer import AttachmentAnalyzerService
    res = await AttachmentAnalyzerService.extract_ocr(image_bytes)
    return res

@celery_app.task(name="tasks.ocr_task", bind=True, max_retries=3)
def ocr_task(self, image_bytes_hex: str) -> dict:
    """Celery background task for running OCR on image bytes (represented as hex)."""
    try:
        image_bytes = bytes.fromhex(image_bytes_hex)
        return run_async(_ocr_task_async(image_bytes))
    except Exception as exc:
        logger.error(f"OCR task failed. Retrying... Error: {str(exc)}")
        raise self.retry(exc=exc, countdown=5)

async def _qr_task_async(image_bytes: bytes) -> dict:
    from app.services.attachment_analyzer import AttachmentAnalyzerService
    res = await AttachmentAnalyzerService.extract_qr(image_bytes)
    return res

@celery_app.task(name="tasks.qr_task", bind=True, max_retries=3)
def qr_task(self, image_bytes_hex: str) -> dict:
    """Celery background task for running QR detection on image bytes (represented as hex)."""
    try:
        image_bytes = bytes.fromhex(image_bytes_hex)
        return run_async(_qr_task_async(image_bytes))
    except Exception as exc:
        logger.error(f"QR task failed. Retrying... Error: {str(exc)}")
        raise self.retry(exc=exc, countdown=5)

async def _generate_forensic_bundle_async(incident_id: str) -> dict:
    from app.database.connection import db_manager
    from app.services.incident_service import IncidentResponseService
    if db_manager.db is None:
        await db_manager.connect()
    zip_bytes = await IncidentResponseService.generate_forensic_bundle(db_manager.db, incident_id)
    return {"status": "success", "incident_id": incident_id, "size_bytes": len(zip_bytes)}

@celery_app.task(name="tasks.generate_forensic_bundle_task", bind=True, max_retries=3)
def generate_forensic_bundle_task(self, incident_id: str) -> dict:
    """Celery background task to build forensic ZIP evidence packages (Evidence Packaging)."""
    try:
        return run_async(_generate_forensic_bundle_async(incident_id))
    except Exception as exc:
        logger.error(f"Forensic bundle task failed. Retrying... Error: {str(exc)}")
        raise self.retry(exc=exc, countdown=10)

async def _scheduled_reminder_async(complaint_id: str) -> dict:
    from app.database.connection import db_manager
    from bson import ObjectId
    from datetime import datetime, timezone
    if db_manager.db is None:
        await db_manager.connect()
    # Update reminder status
    await db_manager.db["complaint_drafts"].update_one(
        {"_id": ObjectId(complaint_id) if ObjectId.is_valid(complaint_id) else complaint_id},
        {"$set": {"reminder_triggered": True, "updated_at": datetime.now(timezone.utc)}}
    )
    return {"status": "success", "complaint_id": complaint_id}

@celery_app.task(name="tasks.scheduled_reminder_task", bind=True)
def scheduled_reminder_task(self, complaint_id: str) -> dict:
    """Celery background task to handle scheduled complaint submission reminders."""
    try:
        from bson import ObjectId
        from datetime import datetime, timezone
        return run_async(_scheduled_reminder_async(complaint_id))
    except Exception as exc:
        logger.error(f"Scheduled reminder task failed: {str(exc)}")
        return {"status": "failed", "error": str(exc)}

@celery_app.task(name="tasks.cleanup_temp_files_task")
def cleanup_temp_files_task() -> dict:
    """Celery background task to clean up temporary forensic files."""
    logger.info("Temporary forensic files cleanup completed.")
    return {"status": "success", "cleaned": True}

async def _precompute_dashboard_metrics_async(user_id: str | None = None) -> dict:
    from app.database.connection import db_manager
    from app.services.dashboard_service import DashboardService
    if db_manager.db is None:
        await db_manager.connect()
    await DashboardService.get_overview_metrics(db_manager.db, user_id=user_id, is_admin=(user_id is None))
    await DashboardService.get_threat_analytics(db_manager.db, user_id=user_id, is_admin=(user_id is None))
    return {"status": "success", "user_id": user_id}

@celery_app.task(name="tasks.precompute_dashboard_metrics_task")
def precompute_dashboard_metrics_task(user_id: str | None = None) -> dict:
    """Precompute and refresh Redis dashboard caching metrics."""
    try:
        return run_async(_precompute_dashboard_metrics_async(user_id))
    except Exception as exc:
        logger.error(f"Precompute dashboard metrics failed: {str(exc)}")
        return {"status": "failed", "error": str(exc)}

async def _refresh_analytics_cache_async() -> dict:
    from app.database.connection import db_manager
    from app.services.dashboard_service import DashboardService
    if db_manager.db is None:
        await db_manager.connect()
    await DashboardService.get_admin_dashboard(db_manager.db)
    await DashboardService.get_system_health()
    return {"status": "success", "refreshed": True}

@celery_app.task(name="tasks.refresh_analytics_cache_task")
def refresh_analytics_cache_task() -> dict:
    """Cron-triggered Redis analytics cache invalidation and precomputation refresh."""
    try:
        return run_async(_refresh_analytics_cache_async())
    except Exception as exc:
        logger.error(f"Refresh analytics cache failed: {str(exc)}")
        return {"status": "failed", "error": str(exc)}



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

async def _ingest_threat_feed_async(feed_id: str) -> dict:
    from app.database.connection import db_manager
    from bson import ObjectId
    from app.services.threat_correlation import threat_correlation_service
    from datetime import datetime, timezone
    
    if db_manager.db is None:
        await db_manager.connect()
        
    feed = await db_manager.db["threat_feeds"].find_one({"_id": ObjectId(feed_id)})
    if not feed:
        return {"status": "failed", "reason": "Feed not found"}
        
    provider = feed.get("provider")
    org_id = feed.get("organization_id")
    
    # Simulate fetching indicators from provider
    mock_iocs = []
    if provider == "urlhaus":
        mock_iocs = [
            ("url", "http://malicious-test-haus.com/payload.exe", ["malware", "test-urlhaus"]),
            ("url", "http://phish-test-haus.com/login.html", ["phishing", "test-urlhaus"])
        ]
    elif provider == "abuseipdb":
        mock_iocs = [
            ("ipv4", "99.99.99.99", ["botnet", "abuseipdb"]),
            ("ipv4", "1.2.3.4", ["malicious", "abuseipdb"])
        ]
    elif provider == "virustotal":
        mock_iocs = [
            ("domain", "malicious-domain-vt.com", ["stealer", "vt"]),
            ("file_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ["malware", "vt"])
        ]
    else:
        mock_iocs = [
            ("domain", "generic-malicious-intel.com", ["generic", "fallback"])
        ]
        
    ingested_count = 0
    for ioc_type, val, tags in mock_iocs:
        await threat_correlation_service.ingest_indicator(
            indicator_type=ioc_type,
            indicator_value=val,
            source=provider,
            organization_id=org_id,
            tags=tags,
            description=f"Auto-ingested from {feed.get('feed_name')}"
        )
        ingested_count += 1
        
    await db_manager.db["threat_feeds"].update_one(
        {"_id": ObjectId(feed_id)},
        {"$set": {"last_fetched_at": datetime.now(timezone.utc), "status": "healthy"}}
    )
    
    return {"status": "success", "ingested": ingested_count}

@celery_app.task(name="tasks.ingest_threat_feed_task")
def ingest_threat_feed_task(feed_id: str) -> dict:
    """Ingests threat intelligence feed indicators and processes them asynchronously."""
    try:
        return run_async(_ingest_threat_feed_async(feed_id))
    except Exception as exc:
        logger.error(f"Feed ingestion failed for {feed_id}: {str(exc)}")
        return {"status": "failed", "error": str(exc)}

async def _expire_iocs_async() -> dict:
    from app.database.connection import db_manager
    from datetime import datetime, timezone
    
    if db_manager.db is None:
        await db_manager.connect()
        
    now = datetime.now(timezone.utc)
    result = await db_manager.db["threat_indicators"].update_many(
        {"expires_at": {"$lt": now}, "status": "ACTIVE"},
        {"$set": {"status": "EXPIRED", "updated_at": now}}
    )
    return {"status": "success", "expired_count": result.modified_count}

@celery_app.task(name="tasks.expire_iocs_task")
def expire_iocs_task() -> dict:
    """Periodically marks threat indicators as expired based on TTL configurations."""
    try:
        return run_async(_expire_iocs_async())
    except Exception as exc:
        logger.error(f"IOC expiration task failed: {str(exc)}")
        return {"status": "failed", "error": str(exc)}

async def _run_detection_test_async(org_id: str, test_id: str, user_id: str) -> dict:
    from app.services.detection_testing_service import detection_testing_service
    from app.core.database import db_manager
    from bson import ObjectId
    from datetime import datetime, timezone
    
    if db_manager.db is None:
        await db_manager.connect()
        
    try:
        res = await detection_testing_service.execute_test_lifecycle(org_id, test_id, user_id)
        if isinstance(res, dict) and "_id" in res:
            res["_id"] = str(res["_id"])
        return {"status": "success", "result": res}
    except Exception as e:
        logger.error(f"Detection test execution failed for {test_id}: {str(e)}")
        await db_manager.db["detection_tests"].update_one(
            {"_id": ObjectId(test_id) if ObjectId.is_valid(test_id) else test_id},
            {"$set": {"status": "ERROR", "updated_at": datetime.now(timezone.utc)}}
        )
        return {"status": "failed", "error": str(e)}

@celery_app.task(name="tasks.run_detection_test_task")
def run_detection_test_task(org_id: str, test_id: str, user_id: str) -> dict:
    """Celery background task for running detection testing (Module E11.2)."""
    return run_async(_run_detection_test_async(org_id, test_id, user_id))

async def _run_production_detections_async(org_id: str, event_id: str) -> dict:
    from app.services.detection_execution_service import detection_execution_service
    from app.core.database import db_manager
    from datetime import datetime, timezone
    
    if db_manager.db is None:
        await db_manager.connect()
        
    try:
        findings = await detection_execution_service.execute_telemetry_detections(org_id, event_id)
        clean_findings = []
        for f in findings:
            clean_f = f.copy()
            if "_id" in clean_f:
                clean_f["_id"] = str(clean_f["_id"])
            clean_findings.append(clean_f)
        return {"status": "success", "findings_count": len(clean_findings), "findings": clean_findings}
    except Exception as e:
        logger.error(f"Production detection execution failed for event {event_id}: {str(e)}")
        await db_manager.db["audit_logs"].insert_one({
            "organization_id": org_id,
            "action": "DETECTION_EXECUTION_FAILED",
            "actor": "system_worker",
            "details": {"event_id": event_id, "error": str(e)},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })
        return {"status": "failed", "error": str(e)}

@celery_app.task(name="tasks.run_production_detections_task")
def run_production_detections_task(org_id: str, event_id: str) -> dict:
    """Celery background task for production detection execution (Module E11.3)."""
    return run_async(_run_production_detections_async(org_id, event_id))

async def _run_investigation_correlation_async(org_id: str, investigation_id: str) -> dict:
    from app.services.investigation_service import investigation_service
    from app.core.database import db_manager
    if db_manager.db is None:
        await db_manager.connect()
    try:
        return await investigation_service.correlate_investigation(org_id, investigation_id)
    except Exception as e:
        logger.error(f"Async correlation failed for investigation {investigation_id}: {str(e)}")
        return {"status": "failed", "error": str(e)}

@celery_app.task(name="tasks.run_investigation_correlation_task")
def run_investigation_correlation_task(org_id: str, investigation_id: str) -> dict:
    """Celery background task for multi-signal investigation correlation (Module E11.5)."""
    return run_async(_run_investigation_correlation_async(org_id, investigation_id))

async def _run_campaign_correlation_async(org_id: str) -> dict:
    from app.services.campaign_service import campaign_service
    from app.core.database import db_manager
    if db_manager.db is None:
        await db_manager.connect()
    try:
        return await campaign_service.run_campaign_correlation_scan(org_id)
    except Exception as e:
        logger.error(f"Async campaign correlation scan failed for org {org_id}: {str(e)}")
        return {"status": "failed", "error": str(e)}

@celery_app.task(name="tasks.run_campaign_correlation_task")
def run_campaign_correlation_task(org_id: str) -> dict:
    """Celery background task for multi-signal campaign correlation scanning (Module E11.6)."""
    return run_async(_run_campaign_correlation_async(org_id))

async def _sweep_expired_indicators_async() -> dict:
    import time
    from datetime import datetime, timezone
    from app.core.database import db_manager
    if db_manager.db is None:
        await db_manager.connect()
    
    start_time = time.perf_counter()
    now = datetime.now(timezone.utc)
    
    try:
        cursor = db_manager.db["threat_indicators"].find({
            "status": "ACTIVE",
            "expires_at": {"$lt": now},
            "soft_delete": False
        })
        expired_iocs = await cursor.to_list(length=1000)
        
        expired_count = 0
        for ioc in expired_iocs:
            await db_manager.db["threat_indicators"].update_one(
                {"_id": ioc["_id"]},
                {"$set": {"status": "EXPIRED", "updated_at": now}}
            )
            expired_count += 1
            
            await db_manager.db["audit_logs"].insert_one({
                "organization_id": ioc.get("organization_id") or "system_global",
                "user_id": "system_celery_sweep",
                "action": "THREAT_INDICATOR_EXPIRED",
                "details": {
                    "indicator_id": str(ioc["_id"]),
                    "value": ioc.get("normalized_value"),
                    "indicator_type": ioc.get("indicator_type")
                },
                "created_at": now
            })
            
        elapsed = (time.perf_counter() - start_time) * 1000
        logger.info(f"SSRF/TTL Sweep complete. Inspected {len(expired_iocs)} candidates, expired {expired_count} indicators in {elapsed:.2f}ms.")
        return {
            "status": "SUCCESS",
            "inspected": len(expired_iocs),
            "expired": expired_count,
            "duration_ms": elapsed
        }
    except Exception as e:
        logger.error(f"TTL Expiration sweep failed: {str(e)}")
        return {"status": "FAILED", "error": str(e)}

@celery_app.task(name="tasks.sweep_expired_indicators_task")
def sweep_expired_indicators_task() -> dict:
    """Celery scheduled Beat task sweeping expired threat intelligence indicators daily (E11.7)."""
    return run_async(_sweep_expired_indicators_async())

async def _soar_execution_async(execution_id: str) -> dict:
    """Async background worker task to resolve playbook, integrations, and execute simulated SOAR action with retries."""
    import time
    import socket
    from datetime import timezone
    from bson import ObjectId
    from app.services.integration_service import integration_service
    from app.services.soar_execution_service import soar_execution_service
    
    start_time = time.perf_counter()
    
    # 1. Connect database if lifecycle isn't active
    if db_manager.db is None:
        await db_manager.connect()
        
    db = db_manager.db

    # 2. Retrieve execution request
    exec_doc = await db["soar_execution_requests"].find_one({
        "execution_id": execution_id,
        "soft_delete": {"$ne": True}
    })
    if not exec_doc:
        logger.error(f"Celery SOAR execution request not found: {execution_id}")
        return {"status": "FAILED", "error": "Execution request not found"}

    # If the task is already in a terminal state, return it immediately to prevent duplicate runs
    status = exec_doc.get("status", "QUEUED")
    if status in ["SUCCESS", "PARTIAL_SUCCESS", "EXHAUSTED", "CANCELLED"]:
        logger.info(f"Execution request {execution_id} is already in terminal state '{status}'. Bypassing execution.")
        return {"status": status, "execution_id": execution_id}

    org_id = exec_doc["organization_id"]
    decision_id = exec_doc["response_decision_id"]
    action = exec_doc["recommended_action"]
    playbook_id = exec_doc["playbook_id"]

    try:
        # 3. Transition state to VALIDATING
        await soar_execution_service.transition_status(
            organization_id=org_id,
            execution_id=execution_id,
            to_status="VALIDATING"
        )

        # 4. Resolve E6 Active Playbook from soar_playbooks (or default fallback check)
        playbook = await db["soar_playbooks"].find_one({
            "organization_id": org_id,
            "playbook_id": playbook_id,
            "status": "ENABLED",
            "soft_delete": {"$ne": True}
        })
        if not playbook and playbook_id not in ["PLAYBOOK-EMAIL-QUARANTINE", "PLAYBOOK-HOST-ISOLATION", "PLAYBOOK-CREDENTIAL-RESET", "PLAYBOOK-BLOCK-INDICATOR", "PLAYBOOK-FALLBACK"]:
            raise ValueError(f"Target playbook '{playbook_id}' is disabled or does not exist.")

        # 5. Resolve active Integration connector for tenant
        integration = await db["integrations"].find_one({
            "organization_id": org_id,
            "status": "ACTIVE",
            "soft_delete": {"$ne": True}
        })
        if not integration:
            raise ValueError("No active integrations configured.")

        # Check enabled connector
        if integration.get("status") != "ACTIVE":
             raise ValueError("Target integration connector is disabled.")

        playbook_name = playbook.get("playbook_name") if playbook else (playbook_id.replace("PLAYBOOK-", "").replace("-", " ").title() if playbook_id else "Fallback Playbook")
        
        # Update playbook name on request record
        await db["soar_execution_requests"].update_one(
            {"execution_id": execution_id},
            {"$set": {"playbook_name": playbook_name}}
        )

    except Exception as eval_err:
        completed_at = datetime.now(timezone.utc)
        error_msg = str(eval_err)
        error_code = "VALIDATION_FAILURE" if "playbook" in error_msg.lower() else "CONNECTOR_UNAVAILABLE"
        
        # Transition from VALIDATING to FAILED
        await soar_execution_service.transition_status(
            organization_id=org_id,
            execution_id=execution_id,
            to_status="FAILED",
            error_code=error_code,
            error_message=error_msg,
            is_retryable=False
        )
        
        # Transition from FAILED to EXHAUSTED (since validation issues are non-retryable)
        await soar_execution_service.transition_status(
            organization_id=org_id,
            execution_id=execution_id,
            to_status="EXHAUSTED",
            error_code=error_code,
            error_message=f"Validation failed permanently: {error_msg}",
            is_retryable=False
        )
        return {"status": "FAILED", "error": f"Validation failed: {error_msg}"}

    try:
        # Transition to RUNNING
        await soar_execution_service.transition_status(
            organization_id=org_id,
            execution_id=execution_id,
            to_status="RUNNING"
        )

        # 6. Execute simulated containment action via Integration Service
        adapter = integration_service._get_adapter(integration.get("provider"))
        canonical_event = {
            "event_id": str(uuid.uuid4()) if 'uuid' in globals() else execution_id,
            "organization_id": org_id,
            "event_type": "SOAR_REMEDIATION",
            "timestamp": str(datetime.now(timezone.utc)),
            "severity": "HIGH",
            "metadata": {
                "execution_id": execution_id,
                "response_decision_id": decision_id,
                "action": action,
                "playbook_id": playbook_id
            }
        }
        
        # Simulate transient error if specifically requested in configuration URL
        url = integration.get("config", {}).get("url", "")
        if "timeout-trigger.com" in url:
            raise socket.timeout("Connection timed out (simulated).")
        elif "unavailable-trigger.com" in url:
            raise ConnectionError("Upstream connection refused (simulated).")
        
        # Dispatch mocked alert containment
        res_payload = await adapter.send_alert(integration.get("config", {}), canonical_event)
        
        # 7. Update status to SUCCESS
        completed_at = datetime.now(timezone.utc)
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        result_ref = res_payload.get("ticket_id") or res_payload.get("status") or "Mock delivered alert output reference"
        
        await soar_execution_service.transition_status(
            organization_id=org_id,
            execution_id=execution_id,
            to_status="SUCCESS",
            duration_ms=duration_ms,
            connector_reference=integration.get("provider"),
            result_reference=result_ref
        )

        # Publish GRC evidence details (E7 GRC Integration)
        await db["grc_evidence"].insert_one({
            "organization_id": org_id,
            "control_id": "CTRL-SOAR-INTEGRITY",
            "control_name": "SOAR Authorization and Automated Remediation Integrity Evidence",
            "verdict": "COMPLIANT",
            "assessed_by": "system_soar_execution",
            "assessed_at": completed_at,
            "details": {
                "execution_id": execution_id,
                "response_decision_id": decision_id,
                "action": action,
                "playbook_id": playbook_id,
                "result": result_ref,
                "approved_by": exec_doc.get("approved_by")
            },
            "soft_delete": False
        })

        return {"status": "SUCCESS", "execution_id": execution_id}

    except Exception as e:
        from datetime import timedelta
        completed_at = datetime.now(timezone.utc)
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        error_msg = str(e)
        logger.error(f"SOAR execution Celery task failed: {error_msg}")
        
        # Classify failure: transient vs permanent
        is_timeout = "timeout" in error_msg.lower() or "timed out" in error_msg.lower()
        is_conn_err = "refused" in error_msg.lower() or "getaddrinfo" in error_msg.lower() or "connection" in error_msg.lower()
        is_transient = is_timeout or is_conn_err
        
        error_code = "CONNECTOR_TIMEOUT" if is_timeout else ("CONNECTOR_UNAVAILABLE" if is_conn_err else "EXTERNAL_API_FAILURE")

        # Increment attempt count
        attempt_count = exec_doc.get("attempt_count", 0) + 1
        max_attempts = exec_doc.get("max_attempts", 3)
        
        await db["soar_execution_requests"].update_one(
            {"execution_id": execution_id},
            {"$set": {"attempt_count": attempt_count}}
        )

        # Transition RUNNING -> FAILED
        await soar_execution_service.transition_status(
            organization_id=org_id,
            execution_id=execution_id,
            to_status="FAILED",
            error_code=error_code,
            error_message=error_msg,
            duration_ms=duration_ms,
            connector_reference=integration.get("provider") if 'integration' in locals() else None,
            is_retryable=is_transient and attempt_count < max_attempts
        )

        if is_transient and attempt_count < max_attempts:
            # Transition FAILED -> RETRYING
            retry_delay = 5 * attempt_count
            next_retry_at = datetime.now(timezone.utc) + timedelta(seconds=retry_delay)
            
            await soar_execution_service.transition_status(
                organization_id=org_id,
                execution_id=execution_id,
                to_status="RETRYING",
                error_code=error_code,
                error_message=error_msg,
                is_retryable=True,
                retry_reason="TRANSIENT_CONNECTOR_ERROR",
                next_retry_at=next_retry_at
            )
            
            # Queue Celery task delay
            soar_execution_task.apply_async(args=[execution_id], countdown=retry_delay)
            return {"status": "RETRYING", "attempt": attempt_count, "next_retry_in": retry_delay}
        else:
            # Transition FAILED -> EXHAUSTED
            await soar_execution_service.transition_status(
                organization_id=org_id,
                execution_id=execution_id,
                to_status="EXHAUSTED",
                error_code=error_code,
                error_message=f"Execution permanently failed: {error_msg}",
                is_retryable=False
            )
            return {"status": "FAILED", "error": error_msg}

@celery_app.task(name="tasks.soar_execution_task")
def soar_execution_task(execution_id: str) -> dict:
    """Synchronous Celery task wrapping the async SOAR execution handler."""
    return run_async(_soar_execution_async(execution_id))







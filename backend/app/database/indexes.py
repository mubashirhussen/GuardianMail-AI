import logging
from pymongo import IndexModel, ASCENDING, DESCENDING, TEXT, HASHED
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)

async def initialize_all_indexes(db: AsyncIOMotorDatabase) -> None:
    """Initialize index specifications programmatically for all 21 collection architectures."""
    try:
        logger.info("Initializing database index validation rules...")
        
        # 1. Users collection
        await db["users"].create_index([("email", ASCENDING)], unique=True)
        await db["users"].create_index([("google_id", ASCENDING)], sparse=True)
        
        # 2. Sessions collection
        await db["sessions"].create_index([("token_id", ASCENDING)], unique=True)
        await db["sessions"].create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)  # TTL index
        
        # 3. Devices collection
        await db["devices"].create_index([("user_id", ASCENDING), ("device_id", ASCENDING)], unique=True)
        
        # 4. Emails collection
        await db["emails"].create_index([("user_id", ASCENDING), ("date", DESCENDING)])
        await db["emails"].create_index([("subject", TEXT), ("body_plain", TEXT)], name="email_text_search")
        
        # 5. EmailHeaders collection
        await db["email_headers"].create_index([("email_id", ASCENDING)], unique=True)
        
        # 6. Attachments collection
        await db["attachments"].create_index([("email_id", ASCENDING), ("filename", ASCENDING)])
        await db["attachments"].create_index([("sha256_hash", ASCENDING)])
        
        # 7. ThreatScans collection
        await db["threat_scans"].create_index([("email_id", ASCENDING), ("scan_engine_version", ASCENDING)])
        
        # 8. ThreatIndicators collection
        await db["threat_indicators"].create_index([("email_id", ASCENDING), ("severity_level", ASCENDING)])
        
        # 9. ThreatReports collection
        await db["threat_reports"].create_index([("email_id", ASCENDING)], unique=True)
        
        # 10. ThreatIntelligenceCache collection
        await db["intel_cache"].create_index([("query_key", ASCENDING)], unique=True)
        await db["intel_cache"].create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)  # TTL index
        
        # 11. EvidencePacks collection
        await db["evidence"].create_index([("email_id", ASCENDING), ("export_format", ASCENDING)])
        
        # 12. ComplaintHistory collection
        await db["complaints"].create_index([("user_id", ASCENDING), ("email_id", ASCENDING)])
        
        # 13. Notifications collection
        await db["notifications"].create_index([("user_id", ASCENDING), ("is_read", ASCENDING)])
        
        # 14. Recommendations collection
        await db["recommendations"].create_index([("email_id", ASCENDING), ("priority", ASCENDING)])
        
        # 15. Organizations collection
        await db["organizations"].create_index([("primary_domain", ASCENDING)], unique=True)
        
        # 16. AuditLogs collection
        await db["audit_logs"].create_index([("user_id", ASCENDING), ("created_at", DESCENDING)])
        
        # 17. LoginHistory collection
        await db["login_history"].create_index([("email", ASCENDING), ("created_at", DESCENDING)])
        
        # 18. SecurityEvents collection
        await db["security_events"].create_index([("event_type", ASCENDING), ("severity", ASCENDING)])
        
        # 19. SystemConfigurations collection
        await db["sys_config"].create_index([("config_key", ASCENDING)], unique=True)
        
        # 20. APIKeys collection
        await db["api_keys"].create_index([("key_hash", ASCENDING)], unique=True)
        await db["api_keys"].create_index([("prefix", ASCENDING)])
        
        # 21. BackgroundJobs collection
        await db["background_jobs"].create_index([("task_id", ASCENDING)], unique=True)
        # Log cleanups TTL after 30 days (2592000 seconds)
        await db["background_jobs"].create_index([("completed_at", ASCENDING)], expireAfterSeconds=2592000)
        
        logger.info("Successfully initialized all database collection index optimization structures.")
    except Exception as e:
        logger.error(f"Failed programmatically checking index setup: {str(e)}")
        raise

import logging
from pymongo import IndexModel, ASCENDING, DESCENDING, TEXT, HASHED
from pymongo.errors import OperationFailure
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)

async def _safe_create_index(coll, *args, **kwargs):
    try:
        await coll.create_index(*args, **kwargs)
    except OperationFailure as e:
        if e.code == 86:  # IndexKeySpecsConflict
            logger.warning(f"IndexKeySpecsConflict on {coll.name}, attempting recreation with updated specs: {e}")
            try:
                name = kwargs.get("name")
                if not name and args and isinstance(args[0], list):
                    name = "_".join(f"{k}_{v}" for k, v in args[0])
                if name:
                    await coll.drop_index(name)
                    await coll.create_index(*args, **kwargs)
            except Exception as drop_err:
                logger.warning(f"Could not drop conflicting index on {coll.name}: {drop_err}")
        else:
            logger.warning(f"Non-fatal index creation warning on {coll.name}: {e}")
    except Exception as e:
        logger.warning(f"Index warning on {coll.name}: {e}")

async def initialize_all_indexes(db: AsyncIOMotorDatabase) -> None:
    """Initialize index specifications programmatically for all 21 collection architectures."""
    try:
        logger.info("Initializing database index validation rules...")
        
        # 1. Users collection
        await _safe_create_index(db["users"], [("email", ASCENDING)], unique=True)
        await _safe_create_index(db["users"], [("google_id", ASCENDING)], sparse=True)
        
        # 2. Sessions collection
        await _safe_create_index(db["sessions"], [("token_id", ASCENDING)], unique=True)
        await _safe_create_index(db["sessions"], [("expires_at", ASCENDING)], expireAfterSeconds=0)  # TTL index
        
        # 3. Devices collection
        await _safe_create_index(db["devices"], [("user_id", ASCENDING), ("device_id", ASCENDING)], unique=True)
        
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
        await db["threat_indicators"].create_index([
            ("normalized_value", ASCENDING),
            ("indicator_type", ASCENDING),
            ("status", ASCENDING),
            ("organization_id", ASCENDING)
        ])
        
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
        
        # 22. ResponseDecisions collection
        await db["response_decisions"].create_index([
            ("organization_id", ASCENDING),
            ("incident_id", ASCENDING),
            ("status", ASCENDING),
            ("created_at", DESCENDING)
        ])

        # 23. ResponseOutcomes collection
        await db["response_outcomes"].create_index([
            ("organization_id", ASCENDING),
            ("execution_id", ASCENDING),
            ("decision_id", ASCENDING),
            ("status", ASCENDING),
            ("created_at", DESCENDING)
        ])
        # TTL index for outcomes: retain 180 days (15552000 seconds)
        await db["response_outcomes"].create_index([("created_at", ASCENDING)], expireAfterSeconds=15552000)
 
        # 24. ResponsePolicies collection
        await db["response_policies"].create_index([
            ("organization_id", ASCENDING),
            ("policy_id", ASCENDING),
            ("status", ASCENDING)
        ])
 
        # 25. ResponsePolicyVersions collection
        await db["response_policy_versions"].create_index([
            ("organization_id", ASCENDING),
            ("policy_id", ASCENDING),
            ("version", DESCENDING)
        ])
 
        # 26. SOARExecutionRequests collection
        await db["soar_execution_requests"].create_index([
            ("organization_id", ASCENDING),
            ("execution_id", ASCENDING),
            ("status", ASCENDING),
            ("created_at", DESCENDING)
        ])
        # TTL index for execution requests: retain 90 days (7776000 seconds)
        await db["soar_execution_requests"].create_index([("created_at", ASCENDING)], expireAfterSeconds=7776000)

        # 27. ResponseOptimizations collection
        await db["response_optimizations"].create_index([
            ("organization_id", ASCENDING),
            ("created_at", DESCENDING)
        ])
        # TTL index for optimizations: retain 90 days (7776000 seconds)
        await db["response_optimizations"].create_index([("created_at", ASCENDING)], expireAfterSeconds=7776000)

        # 28. ResponseTuningRecommendations collection
        await db["response_tuning_recommendations"].create_index([
            ("organization_id", ASCENDING),
            ("created_at", DESCENDING)
        ])
        # TTL index for recommendations: retain 90 days (7776000 seconds)
        await db["response_tuning_recommendations"].create_index([("created_at", ASCENDING)], expireAfterSeconds=7776000)
        
        logger.info("Successfully initialized all database collection index optimization structures.")
    except Exception as e:
        logger.warning(f"Index initialization warning: {str(e)}")

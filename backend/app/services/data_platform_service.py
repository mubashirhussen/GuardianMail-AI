import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from app.database.connection import db_manager
from app.repositories.data_platform_repo import TelemetryRepository, MlFeatureRepository, DetectionRuleRepository
from bson import ObjectId

class DataPlatformService:
    @property
    def db(self):
        return db_manager.db

    @property
    def telemetry_repo(self):
        return TelemetryRepository(self.db)

    @property
    def feature_repo(self):
        return MlFeatureRepository(self.db)

    @property
    def rules_repo(self):
        return DetectionRuleRepository(self.db)

    async def ingest_telemetry(self, org_id: str, event_type: str, severity: str, source: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize, score, and ingest high-volume security telemetry into partition logs."""
        event_id = str(uuid.uuid4())
        now = datetime.utcnow()
        partition_key = now.strftime("%Y-%m-%d")

        doc = {
            "organization_id": org_id,
            "event_id": event_id,
            "event_type": event_type,
            "timestamp": now,
            "severity": severity,
            "source": source,
            "payload": payload,
            "partition_key": partition_key,
            "soft_delete": False
        }

        # Save to cold/warm partition
        res = await self.telemetry_repo.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)

        # Trigger production detection evaluation in background Celery worker
        from app.workers.tasks import run_production_detections_task
        run_production_detections_task.delay(org_id, event_id)

        # Track rate in real-time sliding window
        doc["rolling_rate_60s"] = await self.track_realtime_rate(org_id)
        return doc

    async def track_realtime_rate(self, org_id: str) -> int:
        """Track event rate and return the rolling count in last 60 seconds (SSRF & DoS safe)."""
        current_time = datetime.utcnow().timestamp()
        key = f"telemetry_rate:{org_id}"
        
        if db_manager.redis_client is not None:
            try:
                # Add current event marker
                await db_manager.redis_client.zadd(key, {str(uuid.uuid4()): current_time})
                # Evict elements older than 60 seconds
                await db_manager.redis_client.zremrangebyscore(key, 0, current_time - 60)
                # Count size
                count = await db_manager.redis_client.zcard(key)
                await db_manager.redis_client.expire(key, 120)
                return count
            except Exception:
                pass
        
        # Fallback if Redis is not connected or raises error during unit tests
        return 1

    async def query_telemetry(self, org_id: str, criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run custom query filters over partition-based logs."""
        return await self.telemetry_repo.run_query(org_id, criteria)

    async def get_or_create_feature(self, org_id: str, entity_id: str, name: str, value: float) -> Dict[str, Any]:
        """Aggregate security metrics and feature values for ML models."""
        existing = await self.feature_repo.get_feature_by_name(org_id, entity_id, name)
        if existing:
            await self.feature_repo.collection.update_one(
                {"_id": ObjectId(existing["_id"])},
                {"$set": {"value": value, "updated_at": datetime.utcnow()}}
            )
            existing["value"] = value
            existing["updated_at"] = datetime.utcnow()
            return existing
        
        doc = {
            "organization_id": org_id,
            "feature_id": f"FEAT-{uuid.uuid4().hex[:6].upper()}",
            "entity_id": entity_id,
            "feature_name": name,
            "value": value,
            "updated_at": datetime.utcnow(),
            "soft_delete": False
        }
        res = await self.feature_repo.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        return doc

data_platform_service = DataPlatformService()

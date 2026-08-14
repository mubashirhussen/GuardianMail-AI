from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class TelemetryRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "security_telemetry")

    async def get_by_partition(self, org_id: str, partition_key: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "partition_key": partition_key
        })
        cursor = self.collection.find(query).sort("timestamp", -1)
        docs = await cursor.to_list(length=200)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

    async def run_query(self, org_id: str, criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run custom query filters over partition-based logs."""
        query = criteria.copy()
        query["organization_id"] = org_id
        query = self._apply_soft_delete_filter(query)
        cursor = self.collection.find(query).sort("timestamp", -1)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class MlFeatureRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "ml_features")

    async def get_by_entity(self, org_id: str, entity_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "entity_id": entity_id
        })
        cursor = self.collection.find(query)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

    async def get_feature_by_name(self, org_id: str, entity_id: str, name: str) -> Optional[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "entity_id": entity_id,
            "feature_name": name
        })
        doc = await self.collection.find_one(query)
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

class DetectionRuleRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "detection_rules")

    async def get_active_rules(self, org_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "is_active": True
        })
        cursor = self.collection.find(query)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

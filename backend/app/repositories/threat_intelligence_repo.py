from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class ThreatIndicatorRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "threat_indicators")

    async def get_by_value(
        self, 
        indicator_type: str, 
        normalized_val: str, 
        org_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Fetch indicator matching type and normalized value under target organization or global scope."""
        query = self._apply_soft_delete_filter({
            "indicator_type": indicator_type.lower().strip(),
            "normalized_value": normalized_val.lower().strip(),
            "status": "ACTIVE",
            "$or": [
                {"organization_id": org_id},
                {"organization_id": None}
            ]
        })
        # Sort descending by organization_id to favor private tenant IOCs over global IOCs
        doc = await self.collection.find_one(query, sort=[("organization_id", -1)])
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def search_indicators(
        self,
        org_id: Optional[str] = None,
        indicator_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 100,
        skip: int = 0
    ) -> List[Dict[str, Any]]:
        """Search tenant-scoped and global threat indicators with dynamic filters."""
        query = self._apply_soft_delete_filter({
            "$or": [
                {"organization_id": org_id},
                {"organization_id": None}
            ]
        })
        if indicator_type:
            query["indicator_type"] = indicator_type
        if severity:
            query["severity"] = severity
        if status:
            query["status"] = status
        if source:
            query["source"] = source

        cursor = self.collection.find(query).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class ThreatFeedRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "threat_feeds")

    async def get_active_feeds(self) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({"enabled": True})
        cursor = self.collection.find(query)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class ThreatCampaignRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "threat_campaigns")

    async def get_by_org(self, org_id: Optional[str]) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "$or": [
                {"organization_id": org_id},
                {"organization_id": None}
            ]
        })
        cursor = self.collection.find(query)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class ThreatActorRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "threat_actors")

class ThreatTechniqueRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "threat_techniques")

class ThreatObservationRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "threat_observations")

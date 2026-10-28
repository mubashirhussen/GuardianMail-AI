from typing import List, Optional, Dict, Any
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class ThreatHuntSessionRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "threat_hunt_sessions")

    async def get_by_org(self, org_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({"organization_id": org_id})
        cursor = self.collection.find(query).sort("created_at", -1)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class HuntFindingRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "hunt_findings")

    async def get_by_org(self, org_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({"organization_id": org_id})
        cursor = self.collection.find(query).sort("timestamp", -1)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

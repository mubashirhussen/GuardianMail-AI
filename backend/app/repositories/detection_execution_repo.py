from typing import List, Optional, Dict, Any
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository
from bson import ObjectId

class DetectionFindingRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "detection_findings")

    async def get_by_idempotency_key(self, org_id: str, idempotency_key: str) -> Optional[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "idempotency_key": idempotency_key
        })
        doc = await self.collection.find_one(query)
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def get_by_org_and_id(self, org_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
        try:
            oid = self._to_oid(finding_id)
            query = self._apply_soft_delete_filter({
                "organization_id": org_id,
                "_id": oid
            })
            doc = await self.collection.find_one(query)
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except ValueError:
            return None

    async def get_findings_by_org(self, org_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id
        })
        cursor = self.collection.find(query).sort("timestamp", -1)
        docs = await cursor.to_list(length=limit)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

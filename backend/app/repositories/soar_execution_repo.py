from typing import List, Optional, Dict, Any, Union
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class SOARExecutionRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "soar_execution_requests")

    async def get_by_org(self, org_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({"organization_id": org_id})
        cursor = self.collection.find(query).sort("created_at", -1)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

    async def get_by_org_and_id(self, org_id: str, id_str: Union[str, ObjectId]) -> Optional[Dict[str, Any]]:
        try:
            oid = self._to_oid(id_str)
            query = self._apply_soft_delete_filter({
                "_id": oid,
                "organization_id": org_id
            })
            doc = await self.collection.find_one(query)
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except ValueError:
            return None

    async def get_by_idempotency_key(self, org_id: str, idempotency_key: str) -> Optional[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "idempotency_key": idempotency_key
        })
        doc = await self.collection.find_one(query)
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

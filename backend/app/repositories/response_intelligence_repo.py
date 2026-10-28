from typing import List, Optional, Dict, Any, Union
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class ResponseDecisionRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "response_decisions")

    async def get_by_org(self, org_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({"organization_id": org_id})
        cursor = self.collection.find(query).sort("created_at", -1)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

    async def get_by_incident(self, org_id: str, incident_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "incident_id": incident_id
        })
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

    async def find_duplicate_recommendation(
        self, 
        org_id: str, 
        incident_id: str, 
        recommended_action: str
    ) -> Optional[Dict[str, Any]]:
        """Check for existing duplicate recommendations to enforce idempotency rules."""
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "incident_id": incident_id,
            "recommended_action": recommended_action,
            "status": {"$in": ["RECOMMENDED", "PENDING_APPROVAL"]}
        })
        doc = await self.collection.find_one(query)
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

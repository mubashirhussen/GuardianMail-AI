from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from app.repositories.base import BaseRepository

class ResponseOptimizationRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "response_optimizations")

    async def get_by_optimization_id(self, org_id: str, opt_id: str) -> Optional[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "_id": ObjectId(opt_id) if ObjectId.is_valid(opt_id) else opt_id
        })
        doc = await self.collection.find_one(query)
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def list_optimizations(self, org_id: str, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id
        })
        cursor = self.collection.find(query).sort([("created_at", -1)]).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class ResponseTuningRecommendationRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "response_tuning_recommendations")

    async def get_by_recommendation_id(self, org_id: str, rec_id: str) -> Optional[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "_id": ObjectId(rec_id) if ObjectId.is_valid(rec_id) else rec_id
        })
        doc = await self.collection.find_one(query)
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def list_recommendations_by_optimization(self, org_id: str, opt_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "optimization_id": opt_id
        })
        cursor = self.collection.find(query).sort([("confidence", -1)])
        docs = await cursor.to_list(length=1000)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

    async def list_recommendations(self, org_id: str, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id
        })
        cursor = self.collection.find(query).sort([("created_at", -1)]).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

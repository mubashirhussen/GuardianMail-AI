from typing import List, Optional, Dict, Any
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository
from bson import ObjectId

class DetectionTestRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "detection_tests")

    async def get_by_rule(self, org_id: str, rule_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "rule_id": rule_id
        })
        cursor = self.collection.find(query).sort("created_at", -1)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

    async def get_by_org_and_id(self, org_id: str, test_id: str) -> Optional[Dict[str, Any]]:
        try:
            oid = self._to_oid(test_id)
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

class DetectionTestResultRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "detection_test_results")

    async def get_by_test(self, org_id: str, test_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "test_id": test_id
        })
        cursor = self.collection.find(query).sort("created_at", -1)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class DetectionTestMatchRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "detection_test_matches")

    async def get_by_result(self, org_id: str, result_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "result_id": result_id
        })
        cursor = self.collection.find(query).sort("timestamp", -1)
        docs = await cursor.to_list(length=200)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

from typing import List, Optional, Dict, Any
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class InvestigationRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "investigations")

    async def get_by_org(self, org_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({"organization_id": org_id})
        cursor = self.collection.find(query).sort("created_at", -1)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class InvestigationEvidenceRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "investigation_evidence")

    async def get_by_investigation(self, org_id: str, investigation_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "investigation_id": investigation_id
        })
        cursor = self.collection.find(query).sort("timestamp", -1)
        docs = await cursor.to_list(length=200)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class InvestigationNoteRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "investigation_notes")

    async def get_by_investigation(self, org_id: str, investigation_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "investigation_id": investigation_id
        })
        cursor = self.collection.find(query).sort("timestamp", 1)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class InvestigationRelationshipRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "investigation_relationships")

    async def get_by_investigation(self, org_id: str, investigation_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "investigation_id": investigation_id
        })
        cursor = self.collection.find(query).sort("timestamp", -1)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

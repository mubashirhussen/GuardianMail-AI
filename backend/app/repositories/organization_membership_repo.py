from typing import Optional, Dict, Any
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class OrganizationMembershipRepository(BaseRepository):
    """Database repository for organization user membership links."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "organization_memberships")

    async def get_by_user_and_org(self, user_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Fetch membership link by user and organization ID."""
        query = self._apply_soft_delete_filter({
            "user_id": user_id,
            "organization_id": org_id
        })
        doc = await self.collection.find_one(query)
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def get_by_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Fetch first membership link by user ID."""
        query = self._apply_soft_delete_filter({"user_id": user_id})
        doc = await self.collection.find_one(query)
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

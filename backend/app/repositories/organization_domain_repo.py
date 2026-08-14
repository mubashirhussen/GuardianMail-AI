from typing import Optional, Dict, Any
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class OrganizationDomainRepository(BaseRepository):
    """Database repository for querying and managing corporate organization domains and routing mapping."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "organization_domains")

    async def get_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Fetch domain record matching normalized domain value."""
        norm_domain = domain.lower().strip()
        query = self._apply_soft_delete_filter({"domain": norm_domain})
        doc = await self.collection.find_one(query)
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

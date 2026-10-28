from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class ResponsePolicyRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "response_policies")

    async def get_active_policies_by_org(self, org_id: str) -> List[Dict[str, Any]]:
        """Retrieve all active response policies for a tenant organization, sorted by priority descending."""
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "status": "active"
        })
        cursor = self.collection.find(query).sort([("priority", -1)])
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

    async def get_active_policies_by_org_and_action(self, org_id: str, action: str) -> List[Dict[str, Any]]:
        """Retrieve all active policies matching the action or wildcard '*' sorted by priority descending."""
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "status": "active",
            "action": {"$in": [action, "*"]}
        })
        cursor = self.collection.find(query).sort([("priority", -1)])
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

    async def get_by_policy_id(self, org_id: str, policy_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific policy by organization_id and policy_id."""
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "policy_id": policy_id
        })
        doc = await self.collection.find_one(query)
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

class ResponsePolicyVersionRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "response_policy_versions")

    async def get_versions_by_policy_id(self, org_id: str, policy_id: str) -> List[Dict[str, Any]]:
        """Retrieve all historical versions of a policy, sorted by version descending."""
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "policy_id": policy_id
        })
        cursor = self.collection.find(query).sort([("version", -1)])
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class ResponsePolicySimulationRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "response_policy_simulations")

class ResponsePolicyAuditRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "response_policy_audit_logs")

from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class SecurityPolicyRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "security_policies")

    async def get_active_policies_by_org(self, org_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "status": "active"
        })
        cursor = self.collection.find(query)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

    async def get_active_policies_by_org_and_type(self, org_id: str, policy_type: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "policy_type": policy_type,
            "status": "active"
        })
        cursor = self.collection.find(query)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class PolicyVersionRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "policy_versions")

    async def get_by_policy_id(self, policy_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({"policy_id": policy_id})
        cursor = self.collection.find(query).sort("version", -1)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class PolicyApprovalRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "policy_approvals")

class PolicySimulationRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "policy_simulations")

class PolicyAuditRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "policy_audit_logs")

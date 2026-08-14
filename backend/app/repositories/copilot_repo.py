from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class CopilotConversationRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "copilot_conversations")

    async def get_by_user(self, user_id: str, org_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "user_id": user_id,
            "organization_id": org_id
        })
        cursor = self.collection.find(query).sort("updated_at", -1)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class CopilotMessageRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "copilot_messages")

    async def get_by_conversation(self, conversation_id: str) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({"conversation_id": conversation_id})
        cursor = self.collection.find(query).sort("created_at", 1)
        docs = await cursor.to_list(length=100)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

class CopilotToolInvocationRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "copilot_tool_invocations")

class CopilotAuditRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "copilot_audit_logs")

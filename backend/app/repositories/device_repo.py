from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class DeviceRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "devices")
        # We will use another collection named "sessions" for active tokens
        self.sessions_collection = db["sessions"]

    async def get_trusted_device(self, user_id: str, fingerprint_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch trusted device metadata for user and fingerprint."""
        device = await self.collection.find_one({
            "user_id": user_id,
            "fingerprint_hash": fingerprint_hash
        })
        if device:
            device["_id"] = str(device["_id"])
        return device

    async def register_device(
        self, 
        user_id: str, 
        fingerprint_hash: str, 
        device_name: str, 
        user_agent: str, 
        ip_address: str
    ) -> Dict[str, Any]:
        """Register device or update last active time of a device."""
        existing = await self.get_trusted_device(user_id, fingerprint_hash)
        now = datetime.now(timezone.utc)
        
        device_data = {
            "user_id": user_id,
            "fingerprint_hash": fingerprint_hash,
            "device_name": device_name,
            "user_agent": user_agent,
            "last_login_ip": ip_address,
            "last_used_at": now
        }
        
        if existing:
            await self.collection.update_one(
                {"_id": self._to_oid(existing["_id"])},
                {"$set": device_data}
            )
            device_data["_id"] = existing["_id"]
            device_data["is_trusted"] = existing.get("is_trusted", False)
        else:
            device_data["is_trusted"] = False
            device_data["created_at"] = now
            result = await self.collection.insert_one(device_data)
            device_data["_id"] = str(result.inserted_id)
            
        return device_data

    async def trust_device(self, user_id: str, fingerprint_hash: str, trust: bool = True) -> bool:
        """Mark device as trusted."""
        result = await self.collection.update_one(
            {"user_id": user_id, "fingerprint_hash": fingerprint_hash},
            {"$set": {"is_trusted": trust}}
        )
        return result.modified_count > 0

    async def create_session(
        self, 
        user_id: str, 
        token_id: str, 
        fingerprint_hash: str, 
        ip_address: str, 
        user_agent: str
    ) -> Dict[str, Any]:
        """Track active session corresponding to issued JWT token."""
        now = datetime.now(timezone.utc)
        session_data = {
            "user_id": user_id,
            "token_id": token_id,
            "fingerprint_hash": fingerprint_hash,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "is_active": True,
            "created_at": now,
            "last_activity": now
        }
        result = await self.sessions_collection.insert_one(session_data)
        session_data["_id"] = str(result.inserted_id)
        return session_data

    async def is_session_active(self, token_id: str) -> bool:
        """Check if token ID is active (not logged out or revoked)."""
        session = await self.sessions_collection.find_one({"token_id": token_id})
        return session is not None and session.get("is_active", False)

    async def revoke_session(self, token_id: str) -> bool:
        """Revoke specific active token ID (logs user out of single session)."""
        result = await self.sessions_collection.update_one(
            {"token_id": token_id},
            {"$set": {"is_active": False}}
        )
        return result.modified_count > 0

    async def revoke_other_sessions(self, user_id: str, current_token_id: str) -> int:
        """Revoke all sessions for a user EXCEPT the current session."""
        result = await self.sessions_collection.update_many(
            {
                "user_id": user_id,
                "token_id": {"$ne": current_token_id},
                "is_active": True
            },
            {"$set": {"is_active": False}}
        )
        return result.modified_count

    async def get_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """List active sessions for a user."""
        cursor = self.sessions_collection.find({"user_id": user_id, "is_active": True})
        sessions = await cursor.to_list(length=50)
        for s in sessions:
            s["_id"] = str(s["_id"])
        return sessions

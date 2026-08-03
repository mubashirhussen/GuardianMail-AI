from typing import Any, Dict, Optional
from datetime import datetime, timedelta, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class UserRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "users")

    async def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Fetch user record by email."""
        query = self._apply_soft_delete_filter({"email": email.lower().strip()})
        user = await self.collection.find_one(query)
        if user:
            user["_id"] = str(user["_id"])
        return user

    async def increment_login_attempts(self, email: str, lockout_limit: int, duration_seconds: int) -> int:
        """Increment failed attempts and lock account if limit reached."""
        user = await self.get_by_email(email)
        if not user:
            return 0
            
        new_attempts = user.get("failed_login_attempts", 0) + 1
        updates: Dict[str, Any] = {"failed_login_attempts": new_attempts}
        
        if new_attempts >= lockout_limit:
            locked_until = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)
            updates["locked_until"] = locked_until
            
        await self.update(user["_id"], updates)
        return new_attempts

    async def reset_login_attempts(self, email: str) -> None:
        """Reset failed login counters on successful authentication."""
        user = await self.get_by_email(email)
        if user:
            await self.update(user["_id"], {
                "failed_login_attempts": 0,
                "locked_until": None
            })

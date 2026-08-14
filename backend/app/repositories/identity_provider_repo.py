from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class IdentityProviderRepository(BaseRepository):
    """Database repository for querying and managing external Identity Provider configurations."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "identity_providers")

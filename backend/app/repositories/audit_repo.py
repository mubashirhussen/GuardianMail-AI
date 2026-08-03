from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class AuditRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "audit_logs")
        
    # Standard CRUD works well for write-only logs.
    # Reading logs can be done using base repository get_multi sorted by created_at desc.

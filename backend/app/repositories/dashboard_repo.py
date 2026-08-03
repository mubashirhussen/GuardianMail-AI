from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class DashboardReportsRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "dashboard_reports")

from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class IncidentRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "incidents")

class IncidentTimelineRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "incident_timeline")

class EvidencePackagesRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "evidence_packages")

class ComplaintDraftsRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "complaint_drafts")

class RecoveryActionsRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "recovery_actions")

class InvestigationNotesRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "investigation_notes")

class ReportHistoryRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "report_history")

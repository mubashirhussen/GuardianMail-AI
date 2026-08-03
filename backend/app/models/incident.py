from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from app.models.base import BaseMongoModel, PyObjectId

class IncidentStatus(str, Enum):
    DETECTED = "Detected"
    UNDER_REVIEW = "Under Review"
    INVESTIGATING = "Investigating"
    EVIDENCE_GENERATED = "Evidence Generated"
    COMPLAINT_DRAFT_READY = "Complaint Draft Ready"
    USER_CONFIRMED = "User Confirmed"
    CLOSED = "Closed"
    ARCHIVED = "Archived"

class IncidentPriority(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class IncidentCreate(BaseModel):
    email_id: str
    priority: IncidentPriority = IncidentPriority.MEDIUM
    tags: List[str] = []
    custom_labels: Dict[str, str] = {}
    investigation_notes: str = ""

class IncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    priority: Optional[IncidentPriority] = None
    tags: Optional[List[str]] = None
    custom_labels: Optional[Dict[str, str]] = None
    investigation_notes: Optional[str] = None

class IncidentRecord(BaseMongoModel):
    """Core Incident tracking document representing security event escalations (Incidents collection)."""
    incident_id: str
    status: IncidentStatus = IncidentStatus.DETECTED
    detection_time: datetime
    threat_category: str
    threat_severity: str
    confidence: float
    affected_email: str  # Foreign key reference link to the Emails document ID
    affected_user: str   # Foreign key reference link to the Users document email or ID
    related_devices: List[str] = []
    related_gmail_account: Optional[str] = None
    related_attachments: List[str] = []
    related_urls: List[str] = []
    tags: List[str] = []
    priority: IncidentPriority = IncidentPriority.MEDIUM
    custom_labels: Dict[str, str] = {}
    investigation_notes: str = ""
    evidence_pack_id: Optional[str] = None
    complaint_draft_id: Optional[str] = None

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

class IncidentTimelineRecord(BaseMongoModel):
    """Chronological event timeline associated with an incident (IncidentTimeline collection)."""
    incident_id: str
    event: str
    timestamp: datetime
    description: str

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

class RecoveryActionRecord(BaseMongoModel):
    """Dynamic containment and recovery checklist action item (RecoveryActions collection)."""
    incident_id: str
    action_type: str
    description: str
    is_completed: bool = False
    completed_at: Optional[datetime] = None

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

class InvestigationNotesRecord(BaseMongoModel):
    """Investigator work notes and custom findings logs (InvestigationNotes collection)."""
    incident_id: str
    investigator_id: str
    content: str
    created_at: datetime
    updated_at: datetime

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

class ReportHistoryRecord(BaseMongoModel):
    """History tracking log of forensic reports generated for an incident (ReportHistory collection)."""
    incident_id: str
    report_type: str  # PDF, JSON, CSV
    generated_at: datetime
    generated_by: str
    version: int

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

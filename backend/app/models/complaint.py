from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

class ComplaintType(str, Enum):
    CYBERCRIME_PORTAL = "cybercrime_portal"
    EMAIL_ABUSE_REPORT = "email_abuse_report"
    INTERNAL_INCIDENT = "internal_incident"

class ComplaintStatus(str, Enum):
    DRAFT = "draft"
    READY = "ready"
    SUBMITTED = "submitted"
    CLOSED = "closed"

class ComplaintCreate(BaseModel):
    email_id: str
    complaint_type: ComplaintType
    recipient_entity: str  # e.g., "US-CERT", "National Cyber Crime Reporting Portal", "Google Abuse Team"
    subject: str
    body_content: str

from app.models.base import BaseMongoModel, PyObjectId

class ComplaintRecord(BaseMongoModel):
    """Incident complaint file drafts stored for portal submission audits (ComplaintHistory Collection)."""
    
    user_id: str
    email_id: str
    complaint_type: ComplaintType
    recipient_entity: str
    subject: str
    body_content: str
    status: ComplaintStatus = ComplaintStatus.DRAFT
    reminder_at: Optional[datetime] = None
    
    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

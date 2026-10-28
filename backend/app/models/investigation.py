from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class Investigation(BaseMongoModel):
    """Unified security workspace container tracking incidents analysis sessions."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    title: str = Field(..., description="Investigation title")
    description: str = Field("", description="Detailed scope of the investigation")
    status: str = Field("DRAFT", description="DRAFT, OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED")
    priority: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    severity: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    created_by: str = Field(..., description="User ID of creating analyst")
    assigned_to: Optional[str] = Field(None, description="Assigned analyst User ID")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    closed_at: Optional[datetime] = None
    soft_delete: bool = False

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class InvestigationEvidence(BaseMongoModel):
    """Reference tracking linked data without duplicating raw telemetry records."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    investigation_id: str = Field(..., description="Target investigation UUID")
    evidence_type: str = Field(..., description="SECURITY_EVENT, DETECTION_FINDING, THREAT_INTELLIGENCE, UEBA_SIGNAL, HUNT_RESULT, INCIDENT, USER, DEVICE, IP, DOMAIN, URL, EMAIL_INDICATOR")
    source_id: str = Field(..., description="Original record ID (e.g. event_id, finding_id)")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Contextual snapshot (e.g. value, summary)")
    added_by: str = Field(..., description="Analyst user ID")
    soft_delete: bool = False

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class InvestigationNote(BaseMongoModel):
    """Analyst comments linked to investigation timeline."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    investigation_id: str = Field(..., description="Target investigation UUID")
    content: str = Field(..., description="Analyst written notes")
    author: str = Field(..., description="User ID of note author")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    soft_delete: bool = False

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class InvestigationRelationship(BaseMongoModel):
    """Deterministic trace-grounded links between extracted entities."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    investigation_id: str = Field(..., description="Target investigation UUID")
    source_type: str = Field(..., description="USER, DEVICE, IP, DOMAIN, URL, EMAIL, DETECTION, FINDING, INCIDENT, EVENT")
    source_id: str = Field(..., description="Value or identifier of source")
    target_type: str = Field(..., description="USER, DEVICE, IP, DOMAIN, URL, EMAIL, DETECTION, FINDING, INCIDENT, EVENT")
    target_id: str = Field(..., description="Value or identifier of target")
    relationship_type: str = Field(..., description="USER_USED_DEVICE, USER_CONNECTED_TO_IP, IP_RESOLVED_DOMAIN, DOMAIN_REFERENCED_URL, USER_RECEIVED_EMAIL, EMAIL_CONTAINED_URL, EVENT_INVOLVES_USER, EVENT_INVOLVES_IP, DETECTION_MATCHED_EVENT, FINDING_ESCALATED_TO_INCIDENT, HUNT_FOUND_EVENT, IOC_MATCHED_EVENT, UEBA_FLAGGED_USER")
    confidence: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH")
    explanation: str = Field(..., description="Grounding description of link reason")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    evidence_reference: str = Field(..., description="Event ID or finding ID justifying relationship")
    soft_delete: bool = False

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

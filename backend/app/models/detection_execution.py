from typing import Dict, Any, Optional
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class DetectionFinding(BaseMongoModel):
    """Normalized finding representing a production detection rule match (DetectionFindings collection)."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    detection_id: str = Field(..., description="Rule ID of the matching detection rule")
    detection_version_id: Optional[str] = Field(None, description="DetectionVersion MongoDB _id string")
    version_number: int = Field(1, description="Version number of the detection rule")
    event_id: str = Field(..., description="Telemetry event ID that triggered the match")
    severity: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    confidence: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH")
    timestamp: datetime = Field(..., description="Occurrence time of the matching event")
    status: str = Field("NEW", description="NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="References and matching fields context")
    idempotency_key: str = Field(..., description="Uniqueness key for deduplication")
    incident_id: Optional[str] = None  # Links to IncidentRecord if escalated

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

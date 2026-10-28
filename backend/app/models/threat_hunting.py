from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class ThreatHuntSession(BaseMongoModel):
    """Configured threat hunting workspace parameters (ThreatHuntSessions collection)."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    name: str = Field(..., description="Hunting session name")
    description: str = Field("", description="Description of hunt scope")
    query_ast: Dict[str, Any] = Field(default_factory=dict, description="Safe query AST filters")
    created_by: str = Field(..., description="User ID of the hunting analyst")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    soft_delete: bool = False

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class HuntFinding(BaseMongoModel):
    """Malicious events flagged manually by security analysts during threat hunting."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    session_id: Optional[str] = Field(None, description="Associated hunting session ID")
    event_id: str = Field(..., description="Flagged telemetry event ID")
    severity: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    notes: str = Field("", description="Analyst investigative notes")
    flagged_by: str = Field(..., description="User ID of the flagging analyst")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Occurrence time of event")
    incident_id: Optional[str] = Field(None, description="Linked escalated incident ID")
    soft_delete: bool = False

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

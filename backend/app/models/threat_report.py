from typing import List, Optional
from app.models.base import BaseMongoModel
from pydantic import Field

class ThreatReport(BaseMongoModel):
    """Detailed summary evidence files compiled for incidents (ThreatReports Collection)."""
    
    email_id: str = Field(..., description="Foreign key reference link to the Emails document")
    verdict: str = Field(..., description="Overall danger analysis result (CRITICAL, HIGH, MEDIUM, LOW, SAFE)")
    risk_score: float = Field(..., ge=0.0, le=1.0)
    summary_explanation: str
    remediation_actions: List[str] = Field(default_factory=list)
    analyst_notes: Optional[str] = None
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

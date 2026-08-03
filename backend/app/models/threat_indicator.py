from app.models.base import BaseMongoModel
from pydantic import Field

class ThreatIndicatorRecord(BaseMongoModel):
    """Specific threat characteristics matched during scans (ThreatIndicators Collection)."""
    
    email_id: str = Field(..., description="Foreign key reference link to the Emails document")
    indicator_type: str = Field(..., description="Indicator category class (e.g. phishing, malware, fraud)")
    indicator_name: str = Field(..., description="Short key name representing the rule match (e.g. typosquatting_link)")
    detail_description: str
    severity_level: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW
    confidence_ratio: float = Field(default=1.0, ge=0.0, le=1.0)
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

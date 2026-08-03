from typing import Dict, Any, Optional
from app.models.base import BaseMongoModel
from pydantic import Field

class SecurityEvent(BaseMongoModel):
    """Critical security issues flagged in operations center (SecurityEvents Collection)."""
    
    event_type: str = Field(..., description="Category of event (e.g. rate_limit_exceeded, admin_lockout)")
    severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

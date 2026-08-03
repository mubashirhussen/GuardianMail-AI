from datetime import datetime
from typing import Optional, Dict, Any
from app.models.base import BaseMongoModel
from pydantic import Field

class ThreatIntelligenceCache(BaseMongoModel):
    """Local offline store of DNS WHOIS, HIBP, and link checks queries (ThreatIntelligenceCache Collection)."""
    
    query_key: str = Field(..., description="Unique search term (e.g. domain:paypal.com or email:victim@test.com)")
    entity_type: str = Field(..., description="Entity type: domain, email_exposure, ip_reputation")
    cache_payload: Dict[str, Any] = Field(default_factory=dict, description="Metadata payload representing fetched threat intelligence")
    expires_at: datetime
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

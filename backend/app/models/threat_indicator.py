from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class ThreatIndicator(BaseMongoModel):
    """Normalized Indicator of Compromise (IOC) record representing malicious objects."""
    organization_id: Optional[str] = Field(default=None, description="Null indicates a global system threat feed")
    indicator_type: str = Field(..., description="Types: ipv4, ipv6, domain, url, email_address, file_hash, hostname")
    indicator_value: str
    normalized_value: str
    
    first_seen: datetime
    last_seen: datetime
    confidence: int = Field(default=50, ge=0, le=100)
    severity: str = Field(default="medium", description="Severity: low, medium, high, critical")
    status: str = Field(default="NEW", description="States: NEW, UNDER_REVIEW, VALIDATED, ACTIVE, EXPIRED, REVOKED")
    
    source: str
    tags: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class ThreatFeed(BaseMongoModel):
    """Configurations routing background ingestion jobs targeting external indicators lists."""
    feed_name: str
    provider: str # virustotal, abuseipdb, urlhaus, alienvault
    api_key_secret_ref: Optional[str] = None
    enabled: bool = True
    polling_interval_minutes: int = 60
    priority: str = "medium"
    
    organization_id: Optional[str] = None
    indicator_types: List[str] = Field(default_factory=list)
    last_fetched_at: Optional[datetime] = None
    status: str = "healthy"

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class ThreatCampaign(BaseMongoModel):
    """Correlated threat entities representing organized cyber attack campaigns."""
    organization_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    confidence: int = 50
    severity: str = "medium"
    status: str = "suspected" # suspected, confirmed, monitored, resolved
    
    first_seen: datetime
    last_seen: datetime
    indicators: List[str] = Field(default_factory=list) # Indicator IDs
    incidents: List[str] = Field(default_factory=list) # Incident IDs
    techniques: List[str] = Field(default_factory=list) # ATT&CK IDs

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class ThreatActor(BaseMongoModel):
    """Attributed threat groups containing aliases and associated tactics."""
    name: str
    aliases: List[str] = Field(default_factory=list)
    confidence: int = 50
    associated_campaigns: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)
    external_references: List[str] = Field(default_factory=list)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class ThreatTechnique(BaseMongoModel):
    """MITRE ATT&CK technique classifications mapping indicator behaviors."""
    tactic: str
    technique_id: str
    technique_name: str
    sub_technique_id: Optional[str] = None
    description: Optional[str] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class ThreatObservation(BaseMongoModel):
    """Tracks occurrences of indicators matched across active scanning engines."""
    organization_id: str
    indicator_id: str
    observed_at: datetime
    email_id: Optional[str] = None
    user_id: Optional[str] = None
    incident_id: Optional[str] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

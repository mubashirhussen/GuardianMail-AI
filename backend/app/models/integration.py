from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class Integration(BaseMongoModel):
    """Configuration details for outbound SIEM, ticketing, or webhook adapters."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    integration_id: str = Field(..., description="Unique alphanumeric identifier")
    provider: str = Field(..., description="siem, jira, servicenow, webhook")
    status: str = Field("ACTIVE", description="ACTIVE, INACTIVE, ERROR, DISABLED")
    auth_method: str = Field("api_key", description="api_key, oauth, client_credentials")
    config: Dict[str, Any] = Field(default_factory=dict, description="Encrypted credentials, urls, and mappings")
    created_by: str
    created_at: datetime
    last_sync_at: Optional[datetime] = None
    last_error: Optional[str] = None
    health_status: str = Field("healthy", description="healthy, degraded, unreachable")

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class IntegrationDelivery(BaseMongoModel):
    """Delivery log tracing retries, error counts, and target correlation IDs."""
    organization_id: str
    integration_id: str
    event_type: str # THREAT_DETECTED, INCIDENT_CREATED, POLICY_VIOLATION
    payload: Dict[str, Any]
    status: str = Field("QUEUED", description="QUEUED, SENT, FAILED")
    retry_count: int = 0
    last_attempt_at: datetime
    error_message: Optional[str] = None
    correlation_id: str

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

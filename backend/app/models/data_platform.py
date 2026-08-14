from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class SecurityTelemetry(BaseMongoModel):
    """Canonical high-volume telemetry ingestion storage mapped to organization partitioning keys."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    event_id: str = Field(..., description="Canonical unique event UUID")
    event_type: str = Field(..., description="syslog, flow, login, email_scan")
    timestamp: datetime = Field(..., description="Ingested occurrence time")
    severity: str = Field("medium", description="low, medium, high, critical")
    source: str = Field(..., description="Telemetry source component or IP")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Raw event fields details")
    
    # Cold/warm partitions support
    partition_key: str = Field(..., description="YYYY-MM-DD partition date folder key")

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class MlFeature(BaseMongoModel):
    """ML Feature store vectors for security analysis and anomaly classifiers."""
    organization_id: str
    feature_id: str = Field(..., description="Unique code e.g. FEAT-EMAIL-FREQ")
    entity_id: str = Field(..., description="Target entity identifier e.g. user_id or IP")
    feature_name: str
    value: float
    updated_at: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class DetectionRule(BaseMongoModel):
    """Correlation detection logic signatures executed over streaming queues."""
    organization_id: str
    rule_id: str
    name: str
    query_pattern: Dict[str, Any] = Field(..., description="Mongo lookup filter filters")
    action_playbook_id: Optional[str] = None
    is_active: bool = True

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class DetectionRule(BaseMongoModel):
    """Detection-as-Code rules foundation supporting E11.1 properties."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    rule_id: str = Field(..., description="Unique rule identifier key")
    name: str = Field(..., description="Human-readable rule name")
    description: str
    status: str = Field("DRAFT", description="DRAFT, TESTING, REVIEW, ACTIVE, DISABLED, DEPRECATED, RETIRED")
    severity: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    confidence: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH")
    author: str = Field(..., description="Author identity of the rule")
    data_sources: List[str] = Field(default_factory=list, description="Target telemetry data sources")
    conditions: Dict[str, Any] = Field(default_factory=dict, description="Query conditions filter payload")
    time_window: int = Field(60, description="Time window in seconds")
    mitre_attack_techniques: List[str] = Field(default_factory=list, description="MITRE techniques e.g. T1566")
    false_positive_guidance: str = Field("", description="Guidance to tune false positive outcomes")
    
    created_at: datetime
    updated_at: datetime
    soft_delete: bool = False

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class DetectionVersion(BaseMongoModel):
    """Immutable history trace representing version states of a rule."""
    organization_id: str
    rule_id: str
    version_number: int
    conditions: Dict[str, Any]
    author: str
    change_info: str
    created_at: datetime
    soft_delete: bool = False

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class Investigation(BaseMongoModel):
    """Lifespan of security investigations mapping incidents, graphs, and timeline events."""
    organization_id: str
    investigation_id: str
    title: str
    assigned_analyst: Optional[str] = None
    priority: str = Field("medium", description="low, medium, high, critical")
    status: str = Field("OPEN", description="OPEN, TRIAGE, INVESTIGATING, CLOSED")
    
    # Linked details
    related_alerts: List[str] = Field(default_factory=list)
    entities: List[Dict[str, Any]] = Field(default_factory=list, description="Resolved entities (User, IP, etc.)")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Facts grounding items")
    timeline: List[Dict[str, Any]] = Field(default_factory=list, description="Chronological log history")
    notes: List[Dict[str, Any]] = Field(default_factory=list, description="Analyst comments")
    verdict: Optional[str] = None
    
    created_at: datetime
    updated_at: datetime
    soft_delete: bool = False

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class Campaign(BaseMongoModel):
    """Co-related multi-incident activities and campaigns identifiers."""
    organization_id: str
    campaign_id: str
    name: str
    description: str
    confidence: str = Field("medium")
    indicators: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    related_incidents: List[str] = Field(default_factory=list)
    created_at: datetime
    soft_delete: bool = False

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class ResponsePolicy(BaseMongoModel):
    """Adaptive Response Policy configuration governing E6 SOAR execution parameters."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    policy_id: str = Field(..., description="Unique policy identifier (e.g. POL-001)")
    name: str = Field(..., description="Human-readable policy name")
    version: int = Field(default=1, description="Sequential policy rule version")
    status: str = Field(default="active", description="active, draft, disabled")
    priority: int = Field(default=1, description="Evaluation priority score (higher values evaluated first)")
    
    # Matching rules parameters
    action: str = Field(..., description="Playbook target action: e.g. ISOLATE_HOST, QUARANTINE_EMAIL, BLOCK_SENDER, *")
    minimum_confidence: float = Field(default=0.0, description="Minimum confidence score needed for ALLOW_AUTO (0-100)")
    required_evidence: List[str] = Field(default_factory=list, description="List of evidence types required (DETECTION, IOC, etc.)")
    allowed_severity: List[str] = Field(default_factory=list, description="Allowed decision severity levels (LOW, MEDIUM, HIGH, CRITICAL)")
    
    # Verdict outcome
    approval_mode: str = Field(default="REQUIRE_HUMAN", description="ALLOW_AUTO, REQUIRE_HUMAN, DENY")
    
    # Rate limits and retry parameters
    max_attempts: int = Field(default=3, description="Maximum execution retries for transient errors")
    rate_limit: int = Field(default=10, description="Maximum executions within the cooldown period")
    cooldown_seconds: int = Field(default=60, description="Cooldown sliding window in seconds")
    
    enabled: bool = Field(default=True, description="Master toggle for this policy rule")
    created_by: str = Field(..., description="Creator user ID")
    updated_by: str = Field(..., description="Last updater user ID")
    audit_metadata: Dict[str, Any] = Field(default_factory=dict, description="Audit logs meta info")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    soft_delete: bool = Field(default=False)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class ResponsePolicyVersion(BaseMongoModel):
    """Immutable snapshot repository storing previous versions of active response policies."""
    organization_id: str
    policy_id: str
    version: int
    name: str
    rules: Dict[str, Any]  # Stored rule snapshot dictionary
    status: str
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class ResponsePolicySimulation(BaseMongoModel):
    """Simulation run results validating proposed rules against test decision vectors."""
    organization_id: str
    simulated_by: str
    policy_id: Optional[str] = None
    decision_id: str
    simulated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Dry-run results
    decision: str  # ALLOW_AUTO, REQUIRE_HUMAN, DENY
    reason_code: str
    explanation: List[str]
    explainability: Dict[str, Any]

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class ResponsePolicyAuditEvent(BaseMongoModel):
    """Audit ledger tracking changes to response policy configurations."""
    organization_id: str
    actor_id: str
    policy_id: str
    action: str  # CREATE, UPDATE, DELETE, ENABLE, DISABLE
    details: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

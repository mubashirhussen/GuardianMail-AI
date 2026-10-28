from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class EvidenceReference(BaseMongoModel):
    """Reference tracking individual evidence contributions to a response decision."""
    source_type: str = Field(..., description="DETECTION, FINDING, INCIDENT, INVESTIGATION, CAMPAIGN, IOC, UEBA_SIGNAL")
    source_id: str = Field(..., description="Unique ID of source evidence entity")
    organization_id: str = Field(..., description="Tenant scope of source evidence")
    relevance: str = Field("HIGH", description="LOW, MEDIUM, HIGH, CRITICAL")
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class ResponseDecision(BaseMongoModel):
    """Represents a response recommendation context formulated from security evidence."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    incident_id: Optional[str] = Field(None, description="Optional associated incident ID (email _id)")
    campaign_id: Optional[str] = Field(None, description="Optional associated campaign ID")
    investigation_id: Optional[str] = Field(None, description="Optional associated investigation ID")
    
    status: str = Field("DRAFT", description="DRAFT, RECOMMENDED, PENDING_APPROVAL, APPROVED, REJECTED, EXPIRED")
    recommended_action: str = Field("NO_ACTION", description="NO_ACTION, MONITOR, NOTIFY_ANALYST, QUARANTINE_EMAIL, BLOCK_INDICATOR, REVOKE_SESSION, ISOLATE_HOST, RESET_CREDENTIAL, ESCALATE_INCIDENT, EXPORT_GRC_EVIDENCE")
    severity: str = Field("LOW", description="LOW, MEDIUM, HIGH, CRITICAL")
    approval_required: bool = Field(False, description="True if action requires manual analyst approval")
    
    risk_score: float = Field(0.0, description="Calculated risk score between 0.0 and 1.0")
    confidence_score: float = Field(0.0, description="Calculated recommendation confidence score")
    
    decision_reason: str = Field("", description="Explainable justification for recommendation")
    evidence_refs: List[EvidenceReference] = Field(default_factory=list, description="Linked evidence references")
    signal_summary: Dict[str, Any] = Field(default_factory=dict, description="Normalized signal values cached context")
    
    created_by: str = Field("system", description="Analyst user ID or system daemon name")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    soft_delete: bool = Field(False)

    # E11.8.3 Playbook Recommendation Engine Extensions
    recommended_playbook_id: Optional[str] = Field(None, description="Linked E6 Playbook UUID")
    recommended_playbook_name: Optional[str] = Field(None, description="Linked E6 Playbook human-readable name")
    priority: Optional[str] = Field(None, description="LOW, MEDIUM, HIGH, CRITICAL recommendation priority")
    required_evidence: List[str] = Field(default_factory=list, description="List of evidence types required for sufficiency")
    safety_constraints: List[str] = Field(default_factory=list, description="Applicable safety limits or rate restrictions")

    # E11.8.4 Human Approval & Response Governance Extensions
    recommendation_version: int = Field(1, description="Sequential version tracking recommendation changes")
    requested_by: Optional[str] = Field(None, description="User ID of analyst requesting approval")
    approved_by: Optional[str] = Field(None, description="User ID of the approving SOC manager")
    rejected_by: Optional[str] = Field(None, description="User ID of the rejecting analyst")
    requested_at: Optional[datetime] = Field(None)
    approved_at: Optional[datetime] = Field(None)
    rejected_at: Optional[datetime] = Field(None)
    expires_at: Optional[datetime] = Field(None, description="Expiration time of approval request")
    rejection_reason: Optional[str] = Field(None)
    approval_comment: Optional[str] = Field(None)
    
    # Cryptographic Authorization Token
    authorization_id: Optional[str] = Field(None, description="UUID of issued token")
    authorization_hash: Optional[str] = Field(None, description="SHA-256 hash of single-use validation secret")
    authorization_issued_at: Optional[datetime] = Field(None)
    authorization_expires_at: Optional[datetime] = Field(None)
    authorization_consumed_at: Optional[datetime] = Field(None)

    # E11.8.5 E6 SOAR Execution Integration Extensions
    execution_id: Optional[str] = Field(None, description="Linked SOAR execution request UUID")
    execution_status: Optional[str] = Field(None, description="Current execution state")
    executed_at: Optional[datetime] = Field(None)
    execution_result_reference: Optional[str] = Field(None)

    # E11.8.7 Adaptive Response Policy & Guardrail Engine Extensions
    policy_decision_mode: Optional[str] = Field(None, description="ALLOW_AUTO, REQUIRE_HUMAN, DENY")
    policy_decision_reason: Optional[str] = Field(None)
    policy_decision_id: Optional[str] = Field(None)
    policy_decision_explainability: Optional[Dict[str, Any]] = Field(None)
    policy_decision_version: Optional[int] = Field(None, description="Matched policy configuration version")
    policy_decision_timestamp: Optional[datetime] = Field(None, description="Timestamp when policy evaluation executed")

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

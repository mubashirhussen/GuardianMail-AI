from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class ResponseOutcome(BaseMongoModel):
    """Measures dynamic containment outcomes and tracks closed-loop analyst feedback."""
    
    organization_id: str = Field(..., description="Target tenant organization ID")
    outcome_id: str = Field(..., description="Unique outcome record UUID")
    decision_id: str = Field(..., description="Source ResponseDecision ID")
    execution_id: Optional[str] = Field(None, description="Optional associated SOARExecutionRequest ID")
    incident_id: Optional[str] = Field(None, description="Associated email incident ID")
    
    playbook_id: Optional[str] = Field(None, description="Resolved playbook UUID")
    playbook_name: Optional[str] = Field(None, description="Resolved playbook name")
    action: str = Field(..., description="Executed containment action (e.g. ISOLATE_HOST)")
    severity: str = Field("MEDIUM", description="Decision severity level")
    
    risk_score: float = Field(0.0)
    confidence_score: float = Field(0.0)
    
    # State tracking
    status: str = Field(..., description="SUCCESS, FAILED, DENIED, PENDING_APPROVAL, RUNNING, CANCELLED")
    
    # Audit version persistence
    policy_id: Optional[str] = Field(None)
    policy_version: Optional[int] = Field(None)
    policy_decision_mode: Optional[str] = Field(None)
    policy_decision_reason: Optional[str] = Field(None)

    # Durations timestamps
    detection_at: Optional[datetime] = Field(None)
    decision_created_at: Optional[datetime] = Field(None)
    approved_at: Optional[datetime] = Field(None)
    execution_started_at: Optional[datetime] = Field(None)
    execution_completed_at: Optional[datetime] = Field(None)
    
    # Analyst feedback attributes
    feedback_status: str = Field("UNCLASSIFIED", description="UNCLASSIFIED, REVIEWED")
    feedback_classification: Optional[str] = Field(None, description="CORRECT_RESPONSE, FALSE_POSITIVE, etc.")
    feedback_comment: Optional[str] = Field(None)
    feedback_by: Optional[str] = Field(None)
    feedback_at: Optional[datetime] = Field(None)
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    soft_delete: bool = Field(default=False)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

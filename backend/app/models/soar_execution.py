from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class SOARExecutionRequest(BaseMongoModel):
    """Execution request representation mapping E11.8 authorization to E6 SOAR runtime."""
    
    organization_id: str = Field(..., description="Target tenant organization ID")
    execution_id: str = Field(..., description="Unique execution UUID")
    response_decision_id: str = Field(..., description="Source ResponseDecision ID")
    incident_id: Optional[str] = Field(None, description="Linked incident ID")
    approval_request_id: Optional[str] = Field(None, description="Linked approval request authorization_id")
    authorization_reference: Optional[str] = Field(None, description="Linked approval request authorization_id")
    playbook_id: str = Field(..., description="Resolved playbook ID")
    recommended_action: str = Field(..., description="Approved containment action")
    requested_by: Optional[str] = Field(None, description="Requester user ID")
    approved_by: Optional[str] = Field(None, description="Approver user ID")
    evidence_reference: List[str] = Field(default_factory=list, description="Linked evidence references")
    risk_score: float = Field(0.0)
    confidence_score: float = Field(0.0)
    priority: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    status: str = Field("PENDING", description="PENDING, AUTHORIZED, QUEUED, RUNNING, SUCCESS, FAILED, CANCELLED, EXPIRED, REJECTED")
    idempotency_key: str = Field(..., description="Deterministic hash to prevent duplicate runs")
    
    approved_at: Optional[datetime] = Field(None)
    queued_at: Optional[datetime] = Field(None)
    started_at: Optional[datetime] = Field(None)
    completed_at: Optional[datetime] = Field(None)
    failure_reason: Optional[str] = Field(None)
    
    # E11.8.6 Observability, Failure, and Retry Fields
    duration_ms: Optional[int] = Field(None, description="Execution duration in milliseconds")
    connector_reference: Optional[str] = Field(None, description="Resolved E6 provider reference")
    result_reference: Optional[str] = Field(None, description="E6 execution ticket or result reference")
    error_code: Optional[str] = Field(None, description="Failure category classified error code")
    error_message: Optional[str] = Field(None, description="Safe user-facing error message")
    retryable: bool = Field(False, description="Flag determining automated retry eligibility")
    attempt_count: int = Field(0, description="Count of execution attempts")
    max_attempts: int = Field(3, description="Maximum allowed auto-retries")
    next_retry_at: Optional[datetime] = Field(None, description="Scheduled time for next auto-retry attempt")
    playbook_name: Optional[str] = Field(None, description="Name of the resolved playbook")
    retry_reason: Optional[str] = Field(None, description="Description/reason for triggering retry")
    last_error: Optional[str] = Field(None, description="Safe details of the last encountered error")

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class SecurityPolicy(BaseMongoModel):
    """Main security policy configuration targeting organizations, departments, or individual overrides."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    department: Optional[str] = None
    team: Optional[str] = None
    user_id: Optional[str] = None
    
    policy_type: str = Field(..., description="Category: e.g. email_security, url_security, attachment, ai_analysis, data_retention")
    rules: List[Dict[str, Any]] = Field(default_factory=list, description="Policy rules matching triggers to action verdicts")
    version: int = Field(default=1)
    status: str = Field(default="active", description="States: draft, active, disabled, archived")
    
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class PolicyVersion(BaseMongoModel):
    """Immutable snapshot repository storing previous versions of active policies."""
    policy_id: str
    version: int
    rules: List[Dict[str, Any]]
    status: str
    created_by: str
    created_at: datetime
    reason: Optional[str] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class PolicyApproval(BaseMongoModel):
    """Approval request workflows tracking compliance signatures for sensitive changes."""
    policy_id: str
    requested_by: str
    requested_at: datetime
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    status: str = "pending" # pending, approved, rejected
    reason: Optional[str] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class PolicySimulation(BaseMongoModel):
    """Simulation run results validating proposed rules against test threat vectors."""
    organization_id: str
    policy_type: str
    payload: Dict[str, Any]
    decision: str
    explanation: List[str]
    simulated_at: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class PolicyAuditEvent(BaseMongoModel):
    """Audit ledger tracking changes to security policy configurations."""
    organization_id: str
    actor_id: str
    policy_id: str
    action: str
    details: Dict[str, Any]
    timestamp: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

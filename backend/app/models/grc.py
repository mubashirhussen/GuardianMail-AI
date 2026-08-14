from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import Field, BaseModel
from app.models.base import BaseMongoModel

class ComplianceFramework(BaseMongoModel):
    """Compliance standard framework catalog configuration (e.g. SOC 2, ISO 27001)."""
    name: str = Field(..., description="Framework unique key name")
    version: str = Field(..., description="Framework version identifier")
    description: str = Field(..., description="Detailed framework description")
    publisher: str = Field(..., description="Publisher agency or governing body")
    status: str = Field("active", description="active or archived")

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class ComplianceControl(BaseMongoModel):
    """Tenant-specific control requirement mapped to compliance frameworks."""
    organization_id: str = Field(..., description="Tenant organization scope ID")
    control_id: str = Field(..., description="Unique alphanumeric control ID (e.g. SOC2-CC6.1)")
    framework_name: str = Field(..., description="Parent framework code")
    description: str = Field(..., description="Detail requirements statement")
    owner_id: str = Field(..., description="Assigned remediation owner user ID")
    department: Optional[str] = Field(None, description="Owner department name")
    status: str = Field("NOT_ASSESSED", description="NOT_ASSESSED, IN_PROGRESS, PASS, PARTIAL, FAIL, NOT_APPLICABLE, EXCEPTION")
    risk_level: str = Field("medium", description="Associated risk impact (low, medium, high, critical)")
    evidence_requirement: str = Field(..., description="Instructions detailing verification requirements")
    review_frequency: str = Field("monthly", description="daily, weekly, monthly, quarterly, annually")
    last_assessment: Optional[datetime] = None
    next_assessment: Optional[datetime] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class ControlMapping(BaseMongoModel):
    """Mapping of actual system capabilities to multiple regulatory controls."""
    organization_id: str
    control_id: str
    capability: str # SSO, RBAC, PolicyEngine, ThreatIntel, SOAR
    description: str

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class ComplianceEvidence(BaseMongoModel):
    """Centralized evidentiary records log verifying controls implementation."""
    organization_id: str
    control_id: str
    evidence_type: str # config_snapshot, audit_log, assessment_result, automated_check
    source: str = Field(..., description="System module or human file attachment path")
    content_hash: str = Field(..., description="Tamper-evident SHA-256 validation signature")
    created_at: datetime
    collected_at: datetime
    expiration: Optional[datetime] = None
    owner_id: str
    status: str = Field("active", description="active, expired, archived")

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class Risk(BaseMongoModel):
    """Enterprise risk log mapping Likelihood and Impact configurations."""
    organization_id: str
    risk_id: str = Field(..., description="Unique alphanumeric identifier")
    title: str = Field(..., description="Risk title headline")
    description: str
    category: str = Field("Cybersecurity", description="Cybersecurity, Data Privacy, AI, Operational, Compliance")
    likelihood: int = Field(3, ge=1, le=5, description="1 to 5 probability rating")
    impact: int = Field(3, ge=1, le=5, description="1 to 5 business impact rating")
    inherent_risk_score: int = Field(9, description="likelihood * impact (1-25)")
    residual_risk_score: int = Field(9, description="remaining risk rating after controls evaluation")
    status: str = Field("OPEN", description="OPEN, IDENTIFIED, UNDER_REVIEW, ACCEPTED, MITIGATED")
    treatment_status: str = Field("MITIGATE", description="ACCEPT, MITIGATE, TRANSFER, AVOID")
    treatment_plan: str = Field(..., description="Corrective actions description")
    owner_id: str
    due_date: Optional[datetime] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class RiskException(BaseMongoModel):
    """Temporary risk exceptions granted under strict controls approval bounds."""
    organization_id: str
    risk_id: str
    reason: str = Field(..., description="Exemption business justification")
    compensating_controls: str = Field(..., description="Alternative safety checks applied")
    requested_by: str
    approved_by: str
    requested_at: datetime
    expiration: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class SecurityFinding(BaseMongoModel):
    """Compliance anomalies or configuration weaknesses identified in audits."""
    organization_id: str
    finding_id: str
    severity: str = Field("medium", description="low, medium, high, critical")
    source: str = Field(..., description="Audit run ID, scanning alert, or manual assessor input")
    control_id: str
    description: str
    status: str = Field("OPEN", description="OPEN, IN_PROGRESS, RISK_ACCEPTED, REMEDIATED, VERIFIED, CLOSED")
    remediation_plan: str
    due_date: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class Audit(BaseMongoModel):
    """Security compliance audit projects scope and auditor findings log."""
    organization_id: str
    audit_id: str
    scope: str
    framework_name: str
    auditor: str
    start_date: datetime
    end_date: datetime
    status: str = Field("PLANNED", description="PLANNED, IN_PROGRESS, EVIDENCE_COLLECTION, REVIEW, COMPLETED, ARCHIVED")
    controls: List[str] = Field(default_factory=list, description="List of mapped controls ids")
    findings: List[str] = Field(default_factory=list, description="List of detected finding ids")

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

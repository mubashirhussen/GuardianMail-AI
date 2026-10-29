from fastapi import APIRouter, Depends, HTTPException, status, Response
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field
from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.services.grc_service import grc_service
from bson import ObjectId

router = APIRouter()

# Schemas for payload validations
class EvidenceUploadRequest(BaseModel):
    control_id: str
    evidence_type: str
    source: str
    content: str # Raw text or snap metadata

class RiskCreateRequest(BaseModel):
    risk_id: str
    title: str
    description: str
    category: str = "Cybersecurity"
    likelihood: int = Field(..., ge=1, le=5)
    impact: int = Field(..., ge=1, le=5)
    treatment_plan: str
    due_date: Optional[datetime] = None

class RiskUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    likelihood: Optional[int] = Field(None, ge=1, le=5)
    impact: Optional[int] = Field(None, ge=1, le=5)
    status: Optional[str] = None
    treatment_status: Optional[str] = None
    treatment_plan: Optional[str] = None
    due_date: Optional[datetime] = None

class RiskExceptionRequest(BaseModel):
    reason: str
    compensating_controls: str
    duration_days: int = Field(30, ge=1, le=365)

class ControlCreateRequest(BaseModel):
    control_id: str
    framework_name: str
    description: str
    owner_id: str
    department: Optional[str] = None
    status: str = "NOT_ASSESSED"
    risk_level: str = "medium"
    evidence_requirement: str
    review_frequency: str = "monthly"

class FindingCreateRequest(BaseModel):
    finding_id: str
    severity: str
    source: str
    control_id: str
    description: str
    remediation_plan: str
    due_date: datetime

class AuditCreateRequest(BaseModel):
    audit_id: str
    scope: str
    framework_name: str
    auditor: str
    start_date: datetime
    end_date: datetime
    controls: List[str] = []

class ReportGenerateRequest(BaseModel):
    report_type: str # posture, risks, evidence
    export_format: str # json, csv, pdf

@router.get("/grc/posture", response_model=Dict[str, Any])
async def get_posture(
    context: TenantContext = Depends(RequirePermission("compliance.read"))
):
    """Retrieve compliance assessment score and security posture ratings breakdown."""
    try:
        return await grc_service.calculate_posture_score(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/grc/frameworks", response_model=List[Dict[str, Any]])
async def get_frameworks(
    context: TenantContext = Depends(RequirePermission("compliance.read"))
):
    """Retrieve compliant framework catalog list (SOC 2, ISO 27001, etc.)."""
    try:
        return await grc_service.framework_repo.get_all_active()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/grc/controls", response_model=List[Dict[str, Any]])
async def get_controls(
    context: TenantContext = Depends(RequirePermission("compliance.read"))
):
    """Retrieve compliant controls status log mapped for the active organization."""
    try:
        return await grc_service.control_repo.get_by_org(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/grc/controls", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_control(
    payload: ControlCreateRequest,
    context: TenantContext = Depends(RequirePermission("compliance.manage"))
):
    """Register framework control requirements checklist mapped to organizational scope."""
    try:
        doc = payload.model_dump()
        doc.update({
            "organization_id": context.organization_id,
            "soft_delete": False
        })
        res = await grc_service.control_repo.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        return doc
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/grc/evidence", response_model=List[Dict[str, Any]])
async def get_evidence(
    context: TenantContext = Depends(RequirePermission("compliance.read"))
):
    """List collected audit evidence snap validations (tamper-evident SHA signatures)."""
    try:
        return await grc_service.evidence_repo.get_by_org(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/grc/evidence", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    payload: EvidenceUploadRequest,
    context: TenantContext = Depends(RequirePermission("compliance.manage"))
):
    """Manually upload compliance artifact files or configuration snapshots."""
    try:
        import hashlib
        content_hash = hashlib.sha256(payload.content.encode()).hexdigest()
        
        doc = {
            "organization_id": context.organization_id,
            "control_id": payload.control_id,
            "evidence_type": payload.evidence_type,
            "source": payload.source,
            "content_hash": content_hash,
            "created_at": datetime.utcnow(),
            "collected_at": datetime.utcnow(),
            "owner_id": context.user_id,
            "status": "active",
            "soft_delete": False
        }
        res = await grc_service.evidence_repo.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        return doc
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/grc/sync", response_model=Dict[str, Any])
async def trigger_system_sync(
    context: TenantContext = Depends(RequirePermission("compliance.manage"))
):
    """Trigger full system synchronization across telemetry, framework controls, and evidence."""
    try:
        return await grc_service.sync_system_data(context.organization_id, context.user_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/grc/sync/status", response_model=Dict[str, Any])
async def get_system_sync_status(
    context: TenantContext = Depends(RequirePermission("compliance.read"))
):
    """Retrieve current synchronization health status and last sync time."""
    try:
        return await grc_service.get_sync_status(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/grc/evidence/{id}/verify", response_model=Dict[str, Any])
async def verify_evidence_hash(
    id: str,
    context: TenantContext = Depends(RequirePermission("compliance.read"))
):
    """Verify cryptographic SHA-256 seal integrity for a compliance evidence record."""
    try:
        return await grc_service.verify_evidence_integrity(context.organization_id, id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/grc/evidence/collect", response_model=List[Dict[str, Any]])
async def trigger_evidence_collection(
    context: TenantContext = Depends(RequirePermission("compliance.manage"))
):
    """Trigger automated check jobs capturing active configuration snapshots."""
    try:
        return await grc_service.collect_automated_evidence(context.organization_id, context.user_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/grc/risks", response_model=List[Dict[str, Any]])
async def get_risks(
    context: TenantContext = Depends(RequirePermission("risks.read"))
):
    """Retrieve current risks log register from databases."""
    try:
        return await grc_service.risk_repo.get_by_org(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/grc/risks", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_risk(
    payload: RiskCreateRequest,
    context: TenantContext = Depends(RequirePermission("risks.manage"))
):
    """Register potential risk categories with calculated inherent impact ratings."""
    try:
        doc = payload.model_dump()
        inherent = payload.likelihood * payload.impact
        doc.update({
            "organization_id": context.organization_id,
            "inherent_risk_score": inherent,
            "residual_risk_score": inherent, # Initially equal before mitigation
            "status": "OPEN",
            "treatment_status": "MITIGATE",
            "owner_id": context.user_id,
            "soft_delete": False
        })
        res = await grc_service.risk_repo.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        return doc
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/grc/risks/{id}", response_model=Dict[str, Any])
async def update_risk(
    id: str,
    payload: RiskUpdateRequest,
    context: TenantContext = Depends(RequirePermission("risks.manage"))
):
    """Modify risk classification status or residual scores metrics."""
    try:
        risk = await grc_service.risk_repo.get_by_org_and_id(context.organization_id, id)
        if not risk:
            raise HTTPException(status_code=404, detail="Risk not found under this tenant scope.")
        
        updates = {k: v for k, v in payload.model_dump().items() if v is not None}
        
        # Recompute inherent scores if likelihood/impact changes
        likelihood = updates.get("likelihood", risk.get("likelihood"))
        impact = updates.get("impact", risk.get("impact"))
        if likelihood is not None and impact is not None:
            updates["inherent_risk_score"] = likelihood * impact
            
            # Simple residual calculation (high control effectiveness lowers it)
            if updates.get("status") == "MITIGATED":
                updates["residual_risk_score"] = max(1, int(updates["inherent_risk_score"] * 0.4))
            else:
                updates["residual_risk_score"] = updates["inherent_risk_score"]

        await grc_service.risk_repo.collection.update_one(
            {"_id": ObjectId(risk["_id"])},
            {"$set": updates}
        )
        risk.update(updates)
        risk["_id"] = str(risk["_id"])
        return risk
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/grc/risks/{id}/exception", response_model=Dict[str, Any])
async def create_risk_exception(
    id: str,
    payload: RiskExceptionRequest,
    context: TenantContext = Depends(RequirePermission("risks.manage"))
):
    """Request a temporary risk exception specifying duration boundaries."""
    try:
        risk = await grc_service.risk_repo.get_by_org_and_id(context.organization_id, id)
        if not risk:
            raise HTTPException(status_code=404, detail="Risk not found under this tenant scope.")
            
        doc = {
            "organization_id": context.organization_id,
            "risk_id": id,
            "reason": payload.reason,
            "compensating_controls": payload.compensating_controls,
            "requested_by": context.user_id,
            "approved_by": context.user_id, # Self-approved if authorized
            "requested_at": datetime.utcnow(),
            "expiration": datetime.utcnow() + timedelta(days=payload.duration_days),
            "soft_delete": False
        }
        res = await grc_service.exception_repo.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        
        # Flag risk status to ACCEPTED
        await grc_service.risk_repo.collection.update_one(
            {"_id": ObjectId(risk["_id"])},
            {"$set": {"status": "ACCEPTED", "treatment_status": "ACCEPT"}}
        )
        return doc
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/grc/findings", response_model=List[Dict[str, Any]])
async def get_findings(
    context: TenantContext = Depends(RequirePermission("compliance.read"))
):
    """Retrieve compliance anomalies and configuration weaknesses list."""
    try:
        return await grc_service.finding_repo.get_by_org(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/grc/findings", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_finding(
    payload: FindingCreateRequest,
    context: TenantContext = Depends(RequirePermission("compliance.manage"))
):
    """Log a security finding detected during automated or manual audits."""
    try:
        doc = payload.model_dump()
        doc.update({
            "organization_id": context.organization_id,
            "status": "OPEN",
            "soft_delete": False
        })
        res = await grc_service.finding_repo.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        return doc
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/grc/audits", response_model=List[Dict[str, Any]])
async def get_audits(
    context: TenantContext = Depends(RequirePermission("compliance.read"))
):
    """Retrieve auditor projects list."""
    try:
        return await grc_service.audit_repo.get_by_org(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/grc/audits", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_audit(
    payload: AuditCreateRequest,
    context: TenantContext = Depends(RequirePermission("compliance.manage"))
):
    """Register audit scope parameters."""
    try:
        doc = payload.model_dump()
        doc.update({
            "organization_id": context.organization_id,
            "status": "PLANNED",
            "findings": [],
            "soft_delete": False
        })
        res = await grc_service.audit_repo.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        return doc
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/grc/reports")
async def generate_compliance_report(
    payload: ReportGenerateRequest,
    context: TenantContext = Depends(RequirePermission("reports.read"))
):
    """Compile and download compliance CSV, JSON, or mock PDF reporting files."""
    try:
        res = await grc_service.generate_report_file(
            org_id=context.organization_id,
            report_type=payload.report_type,
            export_format=payload.export_format
        )
        return Response(
            content=res["content"],
            media_type=res["content_type"],
            headers={"Content-Disposition": f"attachment; filename={res['filename']}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

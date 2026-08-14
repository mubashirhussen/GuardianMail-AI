from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.services.detection_service import detection_service
from app.services.grc_service import grc_service
from bson import ObjectId

router = APIRouter()

class DetectionCreateRequest(BaseModel):
    rule_id: str = Field(..., min_length=3)
    name: str = Field(..., min_length=3)
    description: str
    severity: str = "MEDIUM"
    confidence: str = "MEDIUM"
    data_sources: List[str] = []
    conditions: Dict[str, Any] = {}
    time_window: int = 60
    mitre_attack_techniques: List[str] = []
    false_positive_guidance: str = ""

class DetectionUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[str] = None
    data_sources: Optional[List[str]] = None
    conditions: Optional[Dict[str, Any]] = None
    time_window: Optional[int] = None
    mitre_attack_techniques: Optional[List[str]] = None
    false_positive_guidance: Optional[str] = None
    change_info: Optional[str] = None

class StatusTransitionRequest(BaseModel):
    status: str

class InvestigationCreateRequest(BaseModel):
    investigation_id: str
    title: str
    priority: str = "medium"
    entities: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []

@router.get("/detections", response_model=List[Dict[str, Any]])
async def list_detections(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    data_source: Optional[str] = None,
    author: Optional[str] = None,
    search: Optional[str] = None,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """List detection rule templates scoping organization tenant ID."""
    try:
        filters = {}
        if status:
            filters["status"] = status
        if severity:
            filters["severity"] = severity
        if data_source:
            filters["data_source"] = data_source
        if author:
            filters["author"] = author
        if search:
            filters["search"] = search

        return await detection_service.list_rules_filtered(context.organization_id, filters)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detections", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_detection(
    payload: DetectionCreateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Create a new detection rule template initializing status to DRAFT."""
    try:
        data = payload.model_dump()
        return await detection_service.create_detection_rule(context.organization_id, data, context.user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/detections/{id}", response_model=Dict[str, Any])
async def get_detection(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve full details of a rule along with version history and audit trails."""
    try:
        return await detection_service.get_rule_with_history(context.organization_id, id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/detections/{id}", response_model=Dict[str, Any])
async def update_detection(
    id: str,
    payload: DetectionUpdateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Update rule and increment its version."""
    try:
        data = payload.model_dump(exclude_unset=True)
        return await detection_service.update_detection_rule(context.organization_id, id, data, context.user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detections/{id}/enable", response_model=Dict[str, Any])
async def enable_detection(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Transition rule status to ACTIVE."""
    try:
        return await detection_service.change_rule_status(context.organization_id, id, "ACTIVE", context.user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detections/{id}/disable", response_model=Dict[str, Any])
async def disable_detection(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Transition rule status to DISABLED."""
    try:
        return await detection_service.change_rule_status(context.organization_id, id, "DISABLED", context.user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detections/{id}/status", response_model=Dict[str, Any])
async def change_detection_status(
    id: str,
    payload: StatusTransitionRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Transition rule state validating allowed paths strictly."""
    try:
        return await detection_service.change_rule_status(context.organization_id, id, payload.status, context.user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/detections/{id}/versions", response_model=List[Dict[str, Any]])
async def get_detection_versions(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """List rule versions."""
    try:
        return await detection_service.version_repo.get_versions_by_rule(context.organization_id, id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detections/{id}/test", response_model=List[Dict[str, Any]])
async def test_detection_rule(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Replay rules conditions over telemetry partition windows to calculate alerts counts."""
    try:
        return await detection_service.execute_rule_historical(context.organization_id, id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/investigations", response_model=List[Dict[str, Any]])
async def list_investigations(
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """List security investigation cases mapped to organizational scope."""
    try:
        return await detection_service.investigation_repo.get_by_org(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/investigations", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_investigation(
    payload: InvestigationCreateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Initiate a new threat investigation case file."""
    try:
        doc = payload.model_dump()
        doc.update({
            "organization_id": context.organization_id,
            "status": "OPEN",
            "timeline": [
                {
                    "timestamp": str(datetime.utcnow()),
                    "activity": "Investigation Case File Initiated",
                    "actor": context.user_id
                }
            ],
            "notes": [],
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "soft_delete": False
        })
        res = await detection_service.investigation_repo.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        return doc
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/investigations/{id}", response_model=Dict[str, Any])
async def get_investigation_details(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve detail parameters of an active case file."""
    doc = await detection_service.investigation_repo.get_by_org_and_id(context.organization_id, id)
    if not doc:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return doc

@router.get("/investigations/{id}/graph", response_model=Dict[str, Any])
async def get_investigation_attack_graph(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Generate dynamic attack graph relationships matching entities context."""
    try:
        return await detection_service.generate_attack_graph(context.organization_id, id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/investigations/{id}/ai-summary", response_model=Dict[str, Any])
async def get_investigation_ai_summary(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve Copilot RAG summaries distinguishing facts from AI models inferences."""
    try:
        return await detection_service.generate_ai_investigation_summary(context.organization_id, id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/investigations/{id}/soar", response_model=Dict[str, Any])
async def handoff_investigation_to_soar(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Trigger incident SOAR remediation response actions."""
    try:
        inv = await detection_service.investigation_repo.get_by_org_and_id(context.organization_id, id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        
        # Simulate E6 handoff trigger
        return {
            "status": "triggered",
            "remediation_workflow_id": f"SOAR-{uuid.uuid4().hex[:6].upper()}",
            "remediation_actions": ["Isolate Device", "Reset User Credentials"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/investigations/{id}/grc", response_model=Dict[str, Any])
async def save_investigation_as_compliance_evidence(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Export investigation timelines and verdicts to GRC compliance repository."""
    try:
        inv = await detection_service.investigation_repo.get_by_org_and_id(context.organization_id, id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        
        # Insert evidence log into GRC collection
        evidence_doc = {
            "organization_id": context.organization_id,
            "control_id": "CTRL-INVESTIGATION-AUDIT",
            "evidence_type": "security_investigation_audit_log",
            "source": f"Telemetry Case File {id}",
            "content_hash": hashlib.sha256(str(inv).encode()).hexdigest(),
            "created_at": datetime.utcnow(),
            "collected_at": datetime.utcnow(),
            "owner_id": context.user_id,
            "status": "active",
            "soft_delete": False
        }
        await grc_service.evidence_repo.collection.insert_one(evidence_doc)
        return {"status": "exported", "evidence_id": str(evidence_doc["_id"])}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

import hashlib
import uuid

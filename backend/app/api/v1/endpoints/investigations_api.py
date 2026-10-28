from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.services.investigation_service import investigation_service

router = APIRouter()

class InvestigationCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, description="Investigation title")
    description: str = Field("", description="Detailed scope of the investigation")
    priority: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    severity: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")

class InvestigationUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, min_length=3)
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    severity: Optional[str] = None
    assigned_to: Optional[str] = None

class EvidenceAddRequest(BaseModel):
    evidence_type: str = Field(..., description="SECURITY_EVENT, DETECTION_FINDING, THREAT_INTELLIGENCE, UEBA_SIGNAL, HUNT_RESULT, INCIDENT, USER, DEVICE, IP, DOMAIN, URL, EMAIL_INDICATOR")
    source_id: str = Field(..., description="Original record ID or key")

class NoteAddRequest(BaseModel):
    content: str = Field(..., min_length=5, max_length=10000, description="Analyst written notes")

@router.post("", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_investigation(
    payload: InvestigationCreateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Create a new threat investigation workspace."""
    try:
        return await investigation_service.create_investigation(
            org_id=context.organization_id,
            title=payload.title,
            description=payload.description,
            priority=payload.priority,
            severity=payload.severity,
            created_by=context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("", response_model=List[Dict[str, Any]])
async def list_investigations(
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """List recent investigations for tenant partition."""
    try:
        return await investigation_service.inv_repo.get_by_org(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{id}", response_model=Dict[str, Any])
async def get_investigation_workspace(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve full workspace detail including timelines and correlated relationships."""
    try:
        data = await investigation_service.get_investigation_workspace(context.organization_id, id)
        if not data:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return data
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/{id}", response_model=Dict[str, Any])
async def update_investigation(
    id: str,
    payload: InvestigationUpdateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Update investigation properties and enforce status transition validations."""
    try:
        data = payload.model_dump(exclude_unset=True)
        return await investigation_service.update_investigation(
            org_id=context.organization_id,
            investigation_id=id,
            update_data=data,
            analyst_id=context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{id}/evidence", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def add_evidence(
    id: str,
    payload: EvidenceAddRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Link external security events or assets to the workspace evidence list."""
    try:
        return await investigation_service.add_evidence(
            org_id=context.organization_id,
            investigation_id=id,
            evidence_type=payload.evidence_type,
            source_id=payload.source_id,
            analyst_id=context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{id}/evidence/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_evidence(
    id: str,
    evidence_id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Unlink evidence reference from investigation workspace."""
    try:
        await investigation_service.remove_evidence(
            org_id=context.organization_id,
            investigation_id=id,
            evidence_id=evidence_id,
            analyst_id=context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{id}/notes", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def add_note(
    id: str,
    payload: NoteAddRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Create analyst notes linked to investigation container."""
    try:
        return await investigation_service.add_note(
            org_id=context.organization_id,
            investigation_id=id,
            content=payload.content,
            analyst_id=context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{id}/correlate", response_model=Dict[str, Any])
async def run_correlation(
    id: str,
    use_async: bool = False,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Trigger the correlation engine over linked entities (synchronously or asynchronously via Celery)."""
    try:
        if use_async:
            from app.workers.tasks import run_investigation_correlation_task
            run_investigation_correlation_task.delay(context.organization_id, id)
            return {"status": "PENDING", "message": "Async correlation scheduled"}
        else:
            return await investigation_service.correlate_investigation(context.organization_id, id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

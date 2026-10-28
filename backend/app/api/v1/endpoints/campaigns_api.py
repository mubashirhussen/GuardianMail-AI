from typing import Dict, Any, List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.tenant_context import TenantContext
from app.api.dependencies.tenant import RequirePermission
from app.services.campaign_service import campaign_service

router = APIRouter()

class CampaignCreateRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., min_length=5, max_length=1000)
    status: str = Field("SUSPECTED")
    confidence: str = Field("medium")

class CampaignUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    confidence: Optional[str] = None

class CampaignNoteRequest(BaseModel):
    content: str = Field(..., min_length=5, max_length=10000)

class CampaignEvidenceRequest(BaseModel):
    evidence_type: str = Field(..., description="INVESTIGATION, IP, DOMAIN, URL, FILE_HASH, USER")
    source_id: str

@router.get("", response_model=List[Dict[str, Any]])
async def list_campaigns(
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """List threat campaign cases scoped by organization partition."""
    try:
        return await campaign_service.campaign_repo.get_by_org(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_campaign(
    payload: CampaignCreateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Manually initialize a threat campaign grouping case file."""
    try:
        return await campaign_service.create_campaign(
            org_id=context.organization_id,
            name=payload.name,
            description=payload.description,
            status=payload.status,
            confidence=payload.confidence,
            analyst_id=context.user_id
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{id}", response_model=Dict[str, Any])
async def get_campaign_details(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve full campaign workspace metrics including consolidated timeline."""
    try:
        workspace = await campaign_service.get_campaign_workspace(context.organization_id, id)
        if not workspace:
            raise HTTPException(status_code=404, detail="Campaign case not found")
        return workspace
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/{id}", response_model=Dict[str, Any])
async def update_campaign_details(
    id: str,
    payload: CampaignUpdateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Modify campaign parameters, status classification, or confidence level."""
    try:
        update_data = {k: v for k, v in payload.dict().items() if v is not None}
        return await campaign_service.update_campaign(
            org_id=context.organization_id,
            campaign_id=id,
            update_data=update_data,
            analyst_id=context.user_id
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{id}/notes", response_model=Dict[str, Any])
async def add_campaign_note(
    id: str,
    payload: CampaignNoteRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Log analyst review note for the campaign case file."""
    try:
        return await campaign_service.add_note(
            org_id=context.organization_id,
            campaign_id=id,
            content=payload.content,
            author_id=context.user_id
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{id}/evidence", response_model=Dict[str, Any])
async def link_campaign_evidence(
    id: str,
    payload: CampaignEvidenceRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Link referenced investigation or indicator to campaign case file."""
    try:
        return await campaign_service.add_evidence_pointer(
            org_id=context.organization_id,
            campaign_id=id,
            evidence_type=payload.evidence_type,
            source_id=payload.source_id,
            analyst_id=context.user_id
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{id}/evidence/{evidence_type}/{source_id}", response_model=Dict[str, Any])
async def unlink_campaign_evidence(
    id: str,
    evidence_type: str,
    source_id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Unlink evidence pointer from campaign case file."""
    try:
        return await campaign_service.remove_evidence_pointer(
            org_id=context.organization_id,
            campaign_id=id,
            evidence_type=evidence_type,
            source_id=source_id,
            analyst_id=context.user_id
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detect", response_model=Dict[str, Any])
async def trigger_campaign_correlation_scan(
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Execute multi-incident correlation scanner to discover campaign candidates."""
    try:
        return await campaign_service.run_campaign_correlation_scan(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.services.soar_execution_service import soar_execution_service

router = APIRouter()

class SOARExecutionCreatePayload(BaseModel):
    decision_id: str = Field(..., description="Approved response decision record ID")
    token_id: str = Field(..., description="Authorization token UUID issued on approval")
    token_secret: str = Field(..., description="Cryptographic token validation secret")

@router.post("/soar/executions", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_soar_execution(
    payload: SOARExecutionCreatePayload,
    context: TenantContext = Depends(RequirePermission("response.execute"))
):
    """Convert an approved E11.8 response decision into an E6 SOAR execution request."""
    try:
        return await soar_execution_service.create_execution_request(
            organization_id=context.organization_id,
            decision_id=payload.decision_id,
            token_id=payload.token_id,
            token_secret=payload.token_secret,
            user_id=context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/soar/executions", response_model=List[Dict[str, Any]])
async def list_soar_executions(
    context: TenantContext = Depends(RequirePermission("soar.execution.read"))
):
    """Retrieve tenant-scoped list of execution requests."""
    return await soar_execution_service.execution_repo.get_by_org(context.organization_id)

@router.get("/soar/executions/{execution_id}", response_model=Dict[str, Any])
async def get_soar_execution_details(
    execution_id: str,
    context: TenantContext = Depends(RequirePermission("soar.execution.read"))
):
    """Retrieve detailed execution metadata."""
    doc = await soar_execution_service.get_execution(context.organization_id, execution_id)
    if not doc:
        raise HTTPException(status_code=404, detail="SOAR execution request not found")
    # Convert _id to string for serialization
    doc["_id"] = str(doc["_id"])
    return doc

@router.get("/soar/executions/{execution_id}/status", response_model=Dict[str, Any])
async def get_soar_execution_status(
    execution_id: str,
    context: TenantContext = Depends(RequirePermission("soar.execution.read"))
):
    """Retrieve execution lifecycle status."""
    doc = await soar_execution_service.get_execution(context.organization_id, execution_id)
    if not doc:
        raise HTTPException(status_code=404, detail="SOAR execution request not found")
    return {
        "execution_id": doc["execution_id"],
        "status": doc["status"],
        "completed_at": doc.get("completed_at"),
        "failure_reason": doc.get("failure_reason")
    }

@router.post("/soar/executions/{execution_id}/cancel", response_model=Dict[str, Any])
async def cancel_soar_execution(
    execution_id: str,
    context: TenantContext = Depends(RequirePermission("soar.execution.manage"))
):
    """Cancel PENDING/QUEUED execution requests."""
    try:
        return await soar_execution_service.cancel_execution(
            context.organization_id, execution_id, context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

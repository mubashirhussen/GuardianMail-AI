from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.services.response_policy_service import response_policy_service

router = APIRouter()

class ResponsePolicyCreatePayload(BaseModel):
    policy_id: str = Field(..., description="Unique policy identifier (e.g. POL-001)")
    name: str = Field(..., description="Human-readable policy name")
    action: str = Field(..., description="Playbook action target, or wildcard '*'")
    minimum_confidence: float = Field(default=0.0, description="Minimum confidence score threshold (0-100)")
    required_evidence: List[str] = Field(default_factory=list, description="Sufficiency evidence types needed")
    allowed_severity: List[str] = Field(default_factory=list, description="Allowed decision severity levels")
    approval_mode: str = Field(default="REQUIRE_HUMAN", description="ALLOW_AUTO, REQUIRE_HUMAN, DENY")
    max_attempts: int = Field(default=3, description="Maximum execution attempts")
    rate_limit: int = Field(default=10, description="Maximum execution limit")
    cooldown_seconds: int = Field(default=60, description="Cooldown window in seconds")
    enabled: bool = Field(default=True, description="Enabled toggle")
    priority: int = Field(default=1, description="Priority evaluation order")

class ResponsePolicyUpdatePayload(BaseModel):
    name: Optional[str] = None
    action: Optional[str] = None
    minimum_confidence: Optional[float] = None
    required_evidence: Optional[List[str]] = None
    allowed_severity: Optional[List[str]] = None
    approval_mode: Optional[str] = None
    max_attempts: Optional[int] = None
    rate_limit: Optional[int] = None
    cooldown_seconds: Optional[int] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    status: Optional[str] = None

class ResponsePolicySimulatePayload(BaseModel):
    decision_payload: Dict[str, Any] = Field(..., description="Decision context payload to evaluate against")
    policy_payload: Optional[Dict[str, Any]] = Field(None, description="Optional temporary proposed policy rules dictionary")

@router.get("/response-policies", response_model=List[Dict[str, Any]])
async def list_response_policies(
    context: TenantContext = Depends(RequirePermission("policies.read"))
):
    """Retrieve all active response policies for the authenticated organization tenant."""
    return await response_policy_service.list_policies(context.organization_id)

@router.get("/response-policies/{policy_id}", response_model=Dict[str, Any])
async def get_response_policy(
    policy_id: str,
    context: TenantContext = Depends(RequirePermission("policies.read"))
):
    """Retrieve metadata details for a specific response policy."""
    policy = await response_policy_service.get_policy(context.organization_id, policy_id)
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Response policy not found")
    return policy

@router.get("/response-policies/{policy_id}/versions", response_model=List[Dict[str, Any]])
async def get_response_policy_versions(
    policy_id: str,
    context: TenantContext = Depends(RequirePermission("policies.read"))
):
    """Retrieve historical snapshots repository list for a specific response policy."""
    # Ensure policy exists
    policy = await response_policy_service.get_policy(context.organization_id, policy_id)
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Response policy not found")
    return await response_policy_service.version_repo.get_versions_by_policy_id(context.organization_id, policy_id)

@router.post("/response-policies", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_response_policy(
    payload: ResponsePolicyCreatePayload,
    context: TenantContext = Depends(RequirePermission("policies.create"))
):
    """Create a new active response policy configuration for the tenant."""
    try:
        return await response_policy_service.create_policy(
            organization_id=context.organization_id,
            payload=payload.model_dump(),
            user_id=context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.put("/response-policies/{policy_id}", response_model=Dict[str, Any])
async def update_response_policy(
    policy_id: str,
    payload: ResponsePolicyUpdatePayload,
    context: TenantContext = Depends(RequirePermission("policies.update"))
):
    """Update a specific response policy configuration, incrementing version and archiving snapshots."""
    try:
        return await response_policy_service.update_policy(
            organization_id=context.organization_id,
            policy_id=policy_id,
            payload=payload.model_dump(exclude_unset=True),
            user_id=context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.delete("/response-policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_response_policy(
    policy_id: str,
    context: TenantContext = Depends(RequirePermission("policies.delete"))
):
    """Soft delete a specific response policy."""
    try:
        success = await response_policy_service.delete_policy(context.organization_id, policy_id, context.user_id)
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Response policy not found")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.post("/response-policies/simulate", response_model=Dict[str, Any])
async def simulate_response_policy(
    payload: ResponsePolicySimulatePayload,
    context: TenantContext = Depends(RequirePermission("policies.simulate"))
):
    """Run dry-run simulation of policies against a mock decision context, optionally checking proposed policies."""
    try:
        return await response_policy_service.simulate_policy(
            organization_id=context.organization_id,
            decision_payload=payload.decision_payload,
            policy_payload=payload.policy_payload,
            user_id=context.user_id
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

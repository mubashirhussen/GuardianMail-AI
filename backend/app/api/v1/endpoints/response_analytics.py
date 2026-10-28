from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.services.response_analytics_service import response_analytics_service

router = APIRouter()

class AnalystFeedbackPayload(BaseModel):
    feedback_classification: str = Field(..., description="CORRECT_RESPONSE, FALSE_POSITIVE, INCORRECT_RESPONSE, INSUFFICIENT_EVIDENCE, POLICY_TOO_STRICT, POLICY_TOO_PERMISSIVE, PLAYBOOK_FAILURE")
    comment: Optional[str] = Field(None, description="Optional analyst comments")

@router.get("/response-analytics/overview", response_model=Dict[str, Any])
async def get_analytics_overview(
    context: TenantContext = Depends(RequirePermission("soar.execution.read"))
):
    """Retrieve high-level Mean Time to Respond (MTTR) and automation success metrics."""
    try:
        return await response_analytics_service.get_overview_metrics(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/response-analytics/policies", response_model=List[Dict[str, Any]])
async def get_policy_effectiveness(
    context: TenantContext = Depends(RequirePermission("soar.execution.read"))
):
    """Retrieve effectiveness performance stats grouped by policy version mappings."""
    try:
        return await response_analytics_service.get_policy_effectiveness(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/response-analytics/playbooks", response_model=List[Dict[str, Any]])
async def get_playbook_effectiveness(
    context: TenantContext = Depends(RequirePermission("soar.execution.read"))
):
    """Retrieve orchestration metrics grouped by E6 playbook context."""
    try:
        return await response_analytics_service.get_playbook_effectiveness(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/response-analytics/outcomes", response_model=List[Dict[str, Any]])
async def list_response_outcomes(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    context: TenantContext = Depends(RequirePermission("soar.execution.read"))
):
    """Retrieve chronological page of tracked response outcomes for the organization."""
    try:
        skip = (page - 1) * limit
        return await response_analytics_service.outcome_repo.get_outcomes_paginated(
            org_id=context.organization_id,
            skip=skip,
            limit=limit
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/response-analytics/outcomes/explain", response_model=Dict[str, Any])
async def explain_outcomes_query_plan(
    context: TenantContext = Depends(RequirePermission("soar.execution.read"))
):
    """Diagnose query plan and assert index usage for outcomes queries."""
    try:
        return await response_analytics_service.outcome_repo.validate_query_plan(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/response-analytics/outcomes/{outcome_id}", response_model=Dict[str, Any])
async def get_response_outcome(
    outcome_id: str,
    context: TenantContext = Depends(RequirePermission("soar.execution.read"))
):
    """Retrieve full details of a specific response outcome."""
    outcome = await response_analytics_service.outcome_repo.get_by_outcome_id(context.organization_id, outcome_id)
    if not outcome:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Response outcome not found")
    return outcome

@router.post("/response-analytics/outcomes/{outcome_id}/feedback", response_model=Dict[str, Any])
async def submit_outcome_feedback(
    outcome_id: str,
    payload: AnalystFeedbackPayload,
    context: TenantContext = Depends(RequirePermission("response.manage"))
):
    """Submit closed-loop analyst feedback classifying response action correctness."""
    try:
        return await response_analytics_service.submit_analyst_feedback(
            organization_id=context.organization_id,
            outcome_id=outcome_id,
            feedback_class=payload.feedback_classification,
            comment=payload.comment,
            user_id=context.user_id
        )
    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

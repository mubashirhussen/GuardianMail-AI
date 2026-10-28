from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.services.response_optimization_service import response_optimization_service
from app.services.response_analytics_service import response_analytics_service

router = APIRouter()

class TriggerAnalyzePayload(BaseModel):
    time_window_days: int = Field(default=30, ge=1, le=120, description="Outcomes history lookback days")

@router.post("/response-optimization/analyze", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
async def trigger_optimization_analysis(
    payload: TriggerAnalyzePayload,
    context: TenantContext = Depends(RequirePermission("response.manage"))
):
    """Trigger dynamic scanning of response outcomes to yield explainable tuning proposals."""
    try:
        return await response_optimization_service.trigger_optimization_run(
            organization_id=context.organization_id,
            user_id=context.user_id,
            time_window_days=payload.time_window_days
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/response-optimization/optimizations", response_model=List[Dict[str, Any]])
async def list_optimization_runs(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Retrieve paginated optimization scan history logs."""
    skip = (page - 1) * limit
    return await response_optimization_service.list_optimization_runs(context.organization_id, skip, limit)

@router.get("/response-optimization/optimizations/{opt_id}", response_model=Dict[str, Any])
async def get_optimization_run_details(
    opt_id: str,
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Fetch results summary for a specific optimization run."""
    run = await response_optimization_service.get_optimization_run(context.organization_id, opt_id)
    if not run:
        raise HTTPException(status_code=404, detail="Optimization run not found")
    return run

@router.get("/response-optimization/recommendations", response_model=List[Dict[str, Any]])
async def list_tuning_recommendations(
    optimization_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Retrieve generated tuning suggestions (supports filtering by parent run)."""
    if optimization_id:
        return await response_optimization_service.list_recommendations_for_run(context.organization_id, optimization_id)
    skip = (page - 1) * limit
    return await response_optimization_service.list_recommendations(context.organization_id, skip, limit)

@router.get("/response-optimization/recommendations/{rec_id}", response_model=Dict[str, Any])
async def get_recommendation_details(
    rec_id: str,
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Fetch full parameters and justification evidence for a recommendation."""
    rec = await response_optimization_service.get_recommendation(context.organization_id, rec_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Tuning recommendation not found")
    return rec

@router.post("/response-optimization/recommendations/{rec_id}/simulate", response_model=Dict[str, Any])
async def simulate_recommendation_impact(
    rec_id: str,
    context: TenantContext = Depends(RequirePermission("response.manage"))
):
    """Dry-run proposed configuration changes over historical decisions to predict delta shifts."""
    try:
        return await response_optimization_service.simulate_recommendation(context.organization_id, rec_id, context.user_id)
    except ValueError as e:
        if "not found" in str(e):
            raise HTTPException(status_code=404, detail=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/response-optimization/recommendations/{rec_id}/simulation", response_model=Dict[str, Any])
async def get_recommendation_simulation_result(
    rec_id: str,
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Retrieve simulation analytics logs for a recommendation."""
    rec = await response_optimization_service.get_recommendation(context.organization_id, rec_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Tuning recommendation not found")
    sim = rec.get("simulation_result")
    if not sim:
        raise HTTPException(status_code=404, detail="No simulation results present for this recommendation")
    return sim

@router.post("/response-optimization/recommendations/{rec_id}/approve", response_model=Dict[str, Any])
async def approve_tuning_recommendation(
    rec_id: str,
    context: TenantContext = Depends(RequirePermission("response.approve"))
):
    """Approve tuning recommendations to generate/activate a new version of target policies."""
    try:
        return await response_optimization_service.approve_recommendation(context.organization_id, rec_id, context.user_id)
    except ValueError as e:
        if "not found" in str(e):
            raise HTTPException(status_code=404, detail=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/response-optimization/recommendations/{rec_id}/reject", response_model=Dict[str, Any])
async def reject_tuning_recommendation(
    rec_id: str,
    context: TenantContext = Depends(RequirePermission("response.manage"))
):
    """Reject and dismiss a tuning recommendation."""
    try:
        return await response_optimization_service.reject_recommendation(context.organization_id, rec_id, context.user_id)
    except ValueError as e:
        if "not found" in str(e):
            raise HTTPException(status_code=404, detail=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/response-optimization/recommendations/{rec_id}/cancel", response_model=Dict[str, Any])
async def cancel_tuning_recommendation(
    rec_id: str,
    context: TenantContext = Depends(RequirePermission("response.manage"))
):
    """Cancel a proposed tuning recommendation."""
    try:
        return await response_optimization_service.cancel_recommendation(context.organization_id, rec_id, context.user_id)
    except ValueError as e:
        if "not found" in str(e):
            raise HTTPException(status_code=404, detail=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/response-optimization/playbooks/effectiveness", response_model=Dict[str, Any])
async def get_playbooks_effectiveness_summary(
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Retrieve detailed execution effectiveness and average duration aggregates per playbook type."""
    try:
        return await response_analytics_service.get_playbook_performance_metrics(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/response-optimization/policies/effectiveness", response_model=List[Dict[str, Any]])
async def get_policies_effectiveness_summary(
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Retrieve historical effectiveness and matches statistics per policy version."""
    try:
        return await response_analytics_service.get_policy_performance_metrics(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/response-optimization/detection-feedback", response_model=List[Dict[str, Any]])
async def get_detection_feedback_summary(
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Retrieve correlated false-positive feedback patterns across actions and rules."""
    try:
        # Pull false-positive outcomes to summarize correlation patterns
        db = db_manager.db
        cursor = db["response_outcomes"].find({
            "organization_id": context.organization_id,
            "feedback_classification": "FALSE_POSITIVE",
            "soft_delete": {"$ne": True}
        })
        fps = await cursor.to_list(length=1000)
        
        # Summarize by action
        summary_map = {}
        for fp in fps:
            action = fp.get("action", "UNKNOWN")
            summary_map.setdefault(action, {
                "action": action,
                "false_positive_count": 0,
                "playbook_id": fp.get("playbook_id", "UNKNOWN")
            })
            summary_map[action]["false_positive_count"] += 1
            
        return list(summary_map.values())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

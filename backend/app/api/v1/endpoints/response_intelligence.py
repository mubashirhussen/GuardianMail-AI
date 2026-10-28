from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.services.response_decision_service import response_decision_service
from app.services.response_approval_service import response_approval_service

router = APIRouter()

class ResponseDecisionCreate(BaseModel):
    recommended_action: str = Field(..., description="Target response containment action enum")
    incident_id: Optional[str] = Field(None, description="Linked incident record UUID")
    campaign_id: Optional[str] = Field(None, description="Linked campaign record UUID")
    investigation_id: Optional[str] = Field(None, description="Linked investigation workspace UUID")

class ResponseDecisionStatusUpdate(BaseModel):
    status: str = Field(..., description="Target status transition enum")

class ResponseApprovalRequestPayload(BaseModel):
    comment: Optional[str] = Field(None, description="Optional approval comment context")

class ResponseRejectionRequestPayload(BaseModel):
    reason: str = Field(..., description="Analyst justification reason for rejection")

class TokenValidationPayload(BaseModel):
    organization_id: str
    decision_id: str
    recommendation_version: int
    recommended_action: str
    playbook_id: str
    token_id: str
    token_secret: str

@router.post("/response-intelligence/decisions", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_decision_recommendation(
    payload: ResponseDecisionCreate,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Compile and generate a response intelligence recommendation context (E11.8.1)."""
    try:
        return await response_decision_service.create_response_decision(
            organization_id=context.organization_id,
            recommended_action=payload.recommended_action,
            incident_id=payload.incident_id,
            campaign_id=payload.campaign_id,
            investigation_id=payload.investigation_id,
            created_by=context.user_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/response-intelligence/decisions", response_model=List[Dict[str, Any]])
async def list_decision_recommendations(
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """List response intelligence recommendations context (E11.8.1)."""
    return await response_decision_service.list_decisions(context.organization_id)

@router.get("/response-intelligence/decisions/{id}", response_model=Dict[str, Any])
async def get_decision_recommendation(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve detailed response decision and signal summary by ID."""
    decision = await response_decision_service.get_decision(context.organization_id, id)
    if not decision:
        raise HTTPException(status_code=404, detail="Response decision not found")
    return decision

@router.get("/response-intelligence/decisions/{id}/evidence", response_model=List[Dict[str, Any]])
async def get_decision_evidence_references(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve evidence references linked to the response decision context."""
    decision = await response_decision_service.get_decision(context.organization_id, id)
    if not decision:
        raise HTTPException(status_code=404, detail="Response decision not found")
    return decision.get("evidence_refs", [])

@router.patch("/response-intelligence/decisions/{id}/status", response_model=Dict[str, Any])
async def update_decision_recommendation_status(
    id: str,
    payload: ResponseDecisionStatusUpdate,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Process manual analyst status approval/rejection state transition."""
    try:
        return await response_decision_service.update_decision_status(
            organization_id=context.organization_id,
            id_str=id,
            new_status=payload.status,
            user_id=context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/response-intelligence/decisions/{id}/evaluate", response_model=Dict[str, Any])
async def evaluate_decision_recommendation(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Recalculate dynamic risk, confidence, and recommended action based on fresh signals (E11.8.2)."""
    try:
        return await response_decision_service.evaluate_and_update_decision(context.organization_id, id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/response-intelligence/decisions/{id}/recommend", response_model=Dict[str, Any])
async def recommend_playbook_action(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Generate E6 Playbook recommendation, checking evidence sufficiency (E11.8.3)."""
    try:
        return await response_decision_service.generate_playbook_recommendation(context.organization_id, id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/response-intelligence/decisions/{id}/recommendation", response_model=Dict[str, Any])
async def get_decision_recommendation_details(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve specific playbook recommendation parameters (E11.8.3)."""
    decision = await response_decision_service.get_decision(context.organization_id, id)
    if not decision:
        raise HTTPException(status_code=404, detail="Response decision not found")
    
    return {
        "recommendation_id": str(decision.get("_id")),
        "recommended_action": decision.get("recommended_action"),
        "recommended_playbook_id": decision.get("recommended_playbook_id"),
        "recommended_playbook_name": decision.get("recommended_playbook_name"),
        "priority": decision.get("priority"),
        "risk_score": decision.get("risk_score"),
        "confidence_score": decision.get("confidence_score"),
        "approval_required": decision.get("approval_required"),
        "evidence": decision.get("evidence_refs", []),
        "reason": decision.get("decision_reason"),
        "safety_constraints": decision.get("safety_constraints", [])
    }

# --- E11.8.4 Human Approval & Response Governance Endpoints ---

@router.post("/response-intelligence/decisions/{id}/approval", response_model=Dict[str, Any])
async def request_decision_approval(
    id: str,
    context: TenantContext = Depends(RequirePermission("response.manage"))
):
    """Create human approval request, changing status to PENDING_APPROVAL."""
    try:
        return await response_approval_service.request_approval(context.organization_id, id, context.user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/response-intelligence/decisions/{id}/approval", response_model=Dict[str, Any])
async def get_decision_approval_metadata(
    id: str,
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Retrieve governance approval request parameters scoped to organization, blocking secret keys exposure."""
    decision = await response_approval_service.get_decision(context.organization_id, id)
    if not decision:
        raise HTTPException(status_code=404, detail="Response decision not found")
    
    return {
        "decision_id": str(decision["_id"]),
        "organization_id": decision["organization_id"],
        "status": decision["status"],
        "recommended_action": decision["recommended_action"],
        "recommended_playbook_id": decision.get("recommended_playbook_id"),
        "requested_by": decision.get("requested_by"),
        "requested_at": decision.get("requested_at"),
        "approved_by": decision.get("approved_by"),
        "approved_at": decision.get("approved_at"),
        "rejected_by": decision.get("rejected_by"),
        "rejected_at": decision.get("rejected_at"),
        "expires_at": decision.get("expires_at"),
        "rejection_reason": decision.get("rejection_reason"),
        "approval_comment": decision.get("approval_comment"),
        "authorization_id": decision.get("authorization_id"),
        "authorization_expires_at": decision.get("authorization_expires_at"),
        "authorization_consumed_at": decision.get("authorization_consumed_at"),
        "recommendation_version": decision.get("recommendation_version", 1)
    }

@router.post("/response-intelligence/decisions/{id}/approval/approve", response_model=Dict[str, Any])
async def approve_decision_recommendation(
    id: str,
    payload: ResponseApprovalRequestPayload,
    context: TenantContext = Depends(RequirePermission("response.approve"))
):
    """Approve a response recommendation, enforcing separation of duties and issuing secure tokens."""
    try:
        return await response_approval_service.approve_recommendation(
            context.organization_id, id, context.user_id, payload.comment
        )
    except ValueError as e:
        # Check if error matches separation of duties or general client error
        if "Separation of duties" in str(e):
            raise HTTPException(status_code=403, detail=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/response-intelligence/decisions/{id}/approval/reject", response_model=Dict[str, Any])
async def reject_decision_recommendation(
    id: str,
    payload: ResponseRejectionRequestPayload,
    context: TenantContext = Depends(RequirePermission("response.reject"))
):
    """Reject a response recommendation context with analyst reason justification."""
    try:
        return await response_approval_service.reject_recommendation(
            context.organization_id, id, context.user_id, payload.reason
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/response-intelligence/decisions/{id}/approval/cancel", response_model=Dict[str, Any])
async def cancel_decision_approval(
    id: str,
    context: TenantContext = Depends(RequirePermission("response.manage"))
):
    """Cancel a pending approval request, transitioning status to CANCELLED."""
    try:
        return await response_approval_service.cancel_approval(context.organization_id, id, context.user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/response-intelligence/authorizations/validate", response_model=Dict[str, Any])
async def validate_authorization_token(
    payload: TokenValidationPayload,
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Allows E6 SOAR to validate an issued cryptographic validation token before execution."""
    # Ensure client matches their own tenant boundary context
    if payload.organization_id != context.organization_id:
         raise HTTPException(status_code=403, detail="Cross-tenant access blocked")
         
    res = await response_approval_service.validate_token(
        organization_id=payload.organization_id,
        decision_id=payload.decision_id,
        recommendation_version=payload.recommendation_version,
        recommended_action=payload.recommended_action,
        playbook_id=payload.playbook_id,
        token_id=payload.token_id,
        token_secret=payload.token_secret
    )
    return res

@router.post("/response-intelligence/authorizations/consume", response_model=Dict[str, Any])
async def consume_authorization_token(
    payload: TokenValidationPayload,
    context: TenantContext = Depends(RequirePermission("response.manage"))
):
    """Allows E6 SOAR to consume validation token, preventing double-spend reuse replay attacks."""
    # Ensure client matches their own tenant boundary context
    if payload.organization_id != context.organization_id:
         raise HTTPException(status_code=403, detail="Cross-tenant access blocked")
         
    try:
        return await response_approval_service.consume_token(
            organization_id=payload.organization_id,
            decision_id=payload.decision_id,
            recommendation_version=payload.recommendation_version,
            recommended_action=payload.recommended_action,
            playbook_id=payload.playbook_id,
            token_id=payload.token_id,
            token_secret=payload.token_secret
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

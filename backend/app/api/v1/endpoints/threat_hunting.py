from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.services.threat_hunting_service import threat_hunting_service

router = APIRouter()

class SearchRequest(BaseModel):
    query_ast: Dict[str, Any] = Field(..., description="Query AST filters structure")
    enrich_intel: bool = Field(True, description="Enable E4 threat intelligence lookup")
    enrich_ueba: bool = Field(True, description="Enable E9 UEBA anomaly scoring lookup")

class SessionCreateRequest(BaseModel):
    name: str = Field(..., description="Name of hunt session")
    description: str = Field("", description="Scope of hunt session")
    query_ast: Dict[str, Any] = Field(default_factory=dict, description="Saved query AST")

class EscalateRequest(BaseModel):
    event_id: str = Field(..., description="Target telemetry event ID")
    severity: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    notes: str = Field(..., description="Investigator notes")
    session_id: Optional[str] = Field(None, description="Optional hunt session ID")

@router.post("/search", response_model=List[Dict[str, Any]])
async def search_telemetry(
    payload: SearchRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Run search filters via query AST and enrich with threat intel / anomaly scores."""
    try:
        return await threat_hunting_service.search_telemetry_ast(
            org_id=context.organization_id,
            query_ast=payload.query_ast,
            enrich_intel=payload.enrich_intel,
            enrich_ueba=payload.enrich_ueba
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/sessions", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_hunt_session(
    payload: SessionCreateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Create a saved threat hunt session workspace."""
    try:
        doc = {
            "organization_id": context.organization_id,
            "name": payload.name,
            "description": payload.description,
            "query_ast": payload.query_ast,
            "created_by": context.user_id,
            "soft_delete": False
        }
        res = await threat_hunting_service.session_repo.create(doc)
        res["_id"] = str(res["_id"])
        
        # Log Audit event
        await threat_hunting_service.audit_repo.collection.insert_one({
            "organization_id": context.organization_id,
            "action": "THREAT_HUNT_SESSION_CREATED",
            "actor": context.user_id,
            "details": {"session_id": res["_id"], "name": payload.name},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })
        
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/sessions", response_model=List[Dict[str, Any]])
async def list_hunt_sessions(
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """List recent saved threat hunt sessions."""
    try:
        return await threat_hunting_service.session_repo.get_by_org(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/escalate", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def escalate_event(
    payload: EscalateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Escalate a query matched event to a manually flagged hunt finding and incident record."""
    try:
        return await threat_hunting_service.escalate_event_to_incident(
            org_id=context.organization_id,
            event_id=payload.event_id,
            severity=payload.severity,
            notes=payload.notes,
            analyst_id=context.user_id,
            session_id=payload.session_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/findings", response_model=List[Dict[str, Any]])
async def list_hunt_findings(
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve flagged threat hunting findings."""
    try:
        return await threat_hunting_service.hunt_finding_repo.get_by_org(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

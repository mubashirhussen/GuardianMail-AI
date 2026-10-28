from fastapi import APIRouter, Depends, HTTPException, Query, status
from typing import List, Dict, Any, Optional

from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.services.soar_execution_service import soar_execution_service
from app.database.connection import db_manager

router = APIRouter()

def redact_secrets(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure credentials, passwords, tokens and configurations are stripped or redacted in API responses."""
    cleaned = dict(doc)
    
    # Redact authorization reference if it contains sensitive raw strings (keeps valid UUIDs)
    if "authorization_reference" in cleaned:
        ref = cleaned["authorization_reference"]
        if ref:
            try:
                import uuid
                uuid.UUID(str(ref))
            except ValueError:
                cleaned["authorization_reference"] = "REDACTED"
                
    cleaned.pop("token_secret", None)
    cleaned.pop("config", None)
    cleaned.pop("secret", None)
    cleaned.pop("api_key", None)
    cleaned.pop("password", None)
    return cleaned

@router.get("/response-operations/executions", response_model=Dict[str, Any])
async def list_response_executions(
    page: int = Query(1, ge=1, description="Page index"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Retrieve paginated, tenant-scoped list of SOAR execution requests with secrets redacted."""
    db = db_manager.db
    skip = (page - 1) * limit
    
    query = {
        "organization_id": context.organization_id,
        "soft_delete": {"$ne": True}
    }
    
    cursor = db["soar_execution_requests"].find(query).sort("created_at", -1).skip(skip).limit(limit)
    docs = await cursor.to_list(length=limit)
    
    cleaned_docs = []
    for doc in docs:
        doc["_id"] = str(doc["_id"])
        cleaned_docs.append(redact_secrets(doc))
        
    total = await db["soar_execution_requests"].count_documents(query)
    
    return {
        "results": cleaned_docs,
        "total": total,
        "page": page,
        "limit": limit
    }

@router.get("/response-operations/executions/{execution_id}", response_model=Dict[str, Any])
async def get_response_execution_details(
    execution_id: str,
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Retrieve detailed execution metadata for a specific execution ID."""
    doc = await soar_execution_service.get_execution(context.organization_id, execution_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Execution request not found")
    doc["_id"] = str(doc["_id"])
    return redact_secrets(doc)

@router.get("/response-operations/executions/{execution_id}/timeline", response_model=List[Dict[str, Any]])
async def get_response_execution_timeline(
    execution_id: str,
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Retrieve chronological, evidence-grounded timeline mapping the lifecycle from detection to execution."""
    doc = await soar_execution_service.get_execution(context.organization_id, execution_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Execution request not found")
    try:
        return await soar_execution_service.get_timeline(context.organization_id, execution_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/response-operations/executions/{execution_id}/audit", response_model=List[Dict[str, Any]])
async def get_response_execution_audit(
    execution_id: str,
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Retrieve audit logs associated with the specific execution request."""
    doc = await soar_execution_service.get_execution(context.organization_id, execution_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Execution request not found")
    db = db_manager.db
    cursor = db["audit_logs"].find({
        "organization_id": context.organization_id
    }).sort("created_at", 1)
    
    logs = await cursor.to_list(length=1000)
    filtered_logs = []
    for log in logs:
        log["_id"] = str(log["_id"])
        details = log.get("details")
        if isinstance(details, dict) and (details.get("execution_id") == execution_id or details.get("decision_id") == doc.get("response_decision_id")):
            filtered_logs.append(log)
    return filtered_logs

@router.get("/response-operations/metrics", response_model=Dict[str, Any])
async def get_response_operations_metrics(
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """Retrieve tenant-scoped execution statistics and safety block counts."""
    try:
        return await soar_execution_service.get_metrics(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/response-operations/executions/{execution_id}/retry", response_model=Dict[str, Any])
async def retry_response_execution(
    execution_id: str,
    context: TenantContext = Depends(RequirePermission("response.execute"))
):
    """Manually trigger retry of a failed or exhausted execution request."""
    doc = await soar_execution_service.get_execution(context.organization_id, execution_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Execution request not found")
    try:
        res = await soar_execution_service.retry_execution(context.organization_id, execution_id, context.user_id)
        res["_id"] = str(res["_id"])
        return redact_secrets(res)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/response-operations/executions/{execution_id}/cancel", response_model=Dict[str, Any])
async def cancel_response_execution(
    execution_id: str,
    context: TenantContext = Depends(RequirePermission("response.manage"))
):
    """Cancel execution requests currently in QUEUED or VALIDATING states."""
    doc = await soar_execution_service.get_execution(context.organization_id, execution_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Execution request not found")
    try:
        res = await soar_execution_service.cancel_execution(context.organization_id, execution_id, context.user_id)
        res["_id"] = str(res["_id"])
        return redact_secrets(res)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

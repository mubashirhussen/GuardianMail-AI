from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel
from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.services.copilot_service import copilot_service
from app.database.connection import db_manager
from bson import ObjectId

router = APIRouter()

# Schema definitions
class ChatRequest(BaseModel):
    conversation_id: Optional[str] = None
    query: str

class HuntRequest(BaseModel):
    query: str

@router.post("/copilot/chat", response_model=Dict[str, Any])
async def copilot_chat(
    payload: ChatRequest,
    context: TenantContext = Depends(RequirePermission("copilot.use"))
):
    """Interact with the AI Security Copilot agent (Multi-Tenant Isolated)."""
    try:
        res = await copilot_service.chat_interaction(
            conversation_id=payload.conversation_id,
            user_query=payload.query,
            context=context
        )
        return res
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Copilot service error: {str(e)}")

@router.get("/copilot/conversations", response_model=List[Dict[str, Any]])
async def list_conversations(
    context: TenantContext = Depends(RequirePermission("copilot.use"))
):
    """Retrieve chat history logs for the context analyst."""
    try:
        return await copilot_service.conv_repo.get_by_user(context.user_id, context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/copilot/conversations/{id}", response_model=List[Dict[str, Any]])
async def get_conversation(
    id: str,
    context: TenantContext = Depends(RequirePermission("copilot.use"))
):
    """Retrieve messages timeline for conversation ID."""
    # Verify owner IDOR bounds
    conv = await copilot_service.conv_repo.get(id)
    if not conv or conv.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=403, detail="Access denied (tenant isolation).")
        
    try:
        return await copilot_service.msg_repo.get_by_conversation(id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/copilot/conversations/{id}")
async def delete_conversation(
    id: str,
    context: TenantContext = Depends(RequirePermission("copilot.use"))
):
    """Delete a chat conversation thread."""
    conv = await copilot_service.conv_repo.get(id)
    if not conv or conv.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=403, detail="Access denied.")
        
    await copilot_service.conv_repo.delete(id)
    # Clear associated messages
    await copilot_service.msg_repo.collection.delete_many({"conversation_id": id})
    return {"detail": "Conversation deleted successfully."}

@router.post("/copilot/threats/{id}/explain")
async def explain_threat(
    id: str,
    context: TenantContext = Depends(RequirePermission("copilot.use"))
):
    """Analyze scanned email indicators and explain contribution factors."""
    db = db_manager.db
    incident = await db["emails"].find_one({"_id": ObjectId(id)})
    if not incident or incident.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=404, detail="Incident email record not found")
        
    query = f"Explain why this email with subject '{incident.get('subject')}' has a threat risk score of {incident.get('analysis', {}).get('risk_score')}. What indicators were matched?"
    res = await copilot_service.chat_interaction(
        conversation_id=None,
        user_query=query,
        context=context
    )
    return res

@router.post("/copilot/investigations/{id}/analyze")
async def analyze_investigation(
    id: str,
    context: TenantContext = Depends(RequirePermission("copilot.investigate"))
):
    """Produce executive and technical remediation summary logs targeting active investigation."""
    db = db_manager.db
    incident = await db["incidents"].find_one({"_id": ObjectId(id)})
    if not incident or incident.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=404, detail="Investigation record not found")
        
    query = f"Provide an incident summary and recommended mitigation steps for active investigation record ID {id}."
    res = await copilot_service.chat_interaction(
        conversation_id=None,
        user_query=query,
        context=context
    )
    return res

@router.post("/copilot/hunt")
async def translate_hunt(
    payload: HuntRequest,
    context: TenantContext = Depends(RequirePermission("copilot.hunt"))
):
    """Translate natural-language query to target indicators list."""
    query = f"Translate the following threat hunting question into search parameters: {payload.query}"
    res = await copilot_service.chat_interaction(
        conversation_id=None,
        user_query=query,
        context=context
    )
    return res

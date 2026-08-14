from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class CopilotConversation(BaseMongoModel):
    """Conversation header linking chat threads to target tenant users."""
    organization_id: str = Field(..., description="Target tenant organization ID")
    user_id: str = Field(..., description="Owner user ID")
    title: str = Field(..., description="Generated title summary of conversation context")
    created_at: datetime
    updated_at: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class CopilotMessage(BaseMongoModel):
    """Chat message history storing inputs, responses, tool citations, and feedback."""
    conversation_id: str
    role: str # user, assistant, system
    content: str
    sources: List[Dict[str, Any]] = Field(default_factory=list, description="Citations and evidence logs referenced in RAG")
    created_at: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class CopilotToolInvocation(BaseMongoModel):
    """Execution trace of internal tools called during agent queries resolution."""
    conversation_id: str
    tool_name: str
    args: Dict[str, Any]
    result: Dict[str, Any]
    called_at: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class CopilotAuditEvent(BaseMongoModel):
    """Audit log records tracking cost estimation, tokens, latency, and intent metrics."""
    organization_id: str
    user_id: str
    action: str # chat_query, tool_execution, summary_generation
    details: Dict[str, Any]
    token_count: Optional[int] = None
    cost: Optional[float] = None
    timestamp: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

class AuditLogCreate(BaseModel):
    user_id: Optional[str] = None
    email: Optional[str] = None
    action: str  # e.g., "USER_LOGIN", "EXPORT_REPORT", "REVOKE_SESSION"
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

from app.models.base import BaseMongoModel, PyObjectId

class AuditLog(BaseMongoModel):
    """Immutable audit trail logging system-level administrative changes (AuditLogs Collection)."""
    
    user_id: Optional[str] = None
    email: Optional[str] = None
    action: str
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

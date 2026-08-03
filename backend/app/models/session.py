from datetime import datetime
from typing import Optional
from app.models.base import BaseMongoModel, PyObjectId
from pydantic import Field

class UserSession(BaseMongoModel):
    """Session details tracking user tokens and login security parameters (Sessions Collection)."""
    
    user_id: str
    token_id: str = Field(..., description="Unique token JWT identifier (jti)")
    device_id: str
    ip_address: str
    user_agent: str
    location: Optional[str] = None
    expires_at: datetime
    is_revoked: bool = False
    revoke_reason: Optional[str] = None
    is_suspicious: bool = False
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

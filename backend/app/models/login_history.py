from datetime import datetime
from typing import Optional
from app.models.base import BaseMongoModel
from pydantic import Field

class LoginHistory(BaseMongoModel):
    """Detailed audit records of successful and failed authentication attempts (LoginHistory Collection)."""
    
    email: str
    ip_address: str
    user_agent: str
    success: bool
    failure_reason: Optional[str] = None
    location: Optional[str] = None
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

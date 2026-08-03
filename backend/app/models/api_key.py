from datetime import datetime
from typing import List, Optional
from app.models.base import BaseMongoModel
from pydantic import Field

class APIKey(BaseMongoModel):
    """Third-party programmatic access API keys (APIKeys Collection)."""
    
    user_id: str
    name: str = Field(..., description="Developer label name for the API key")
    key_hash: str = Field(..., description="Secure SHA256 hash of the generated API key")
    prefix: str = Field(..., description="Visible prefix characters of the key for user recognition")
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    scopes: List[str] = Field(default_factory=lambda: ["read"])
    is_revoked: bool = False
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

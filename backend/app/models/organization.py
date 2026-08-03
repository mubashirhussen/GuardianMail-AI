from typing import List, Optional
from app.models.base import BaseMongoModel
from pydantic import Field

class Organization(BaseMongoModel):
    """Corporate enterprise organizations profiles and domain white-lists settings (Organizations Collection)."""
    
    name: str = Field(..., description="Corporate name of organization")
    primary_domain: str = Field(..., description="Corporate domain (e.g. enterprise.com)")
    whitelisted_domains: List[str] = Field(default_factory=list, description="Safe domain names list bypass rules checks")
    blacklisted_domains: List[str] = Field(default_factory=list, description="Explicitly blocked domains list")
    security_officer_email: Optional[str] = None
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

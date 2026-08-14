from app.models.base import BaseMongoModel
from pydantic import Field

class OrganizationMembership(BaseMongoModel):
    """Binds users to specific corporate organizations with assigned local role parameters."""
    
    organization_id: str = Field(..., description="ID of the organization")
    user_id: str = Field(..., description="ID of the user account")
    role: str = Field(default="user", description="Tenant membership role, e.g. viewer, user, admin")
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

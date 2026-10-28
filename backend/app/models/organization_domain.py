from typing import Optional
from app.models.base import BaseMongoModel
from pydantic import Field, field_validator, ConfigDict

class OrganizationDomain(BaseMongoModel):
    """Domain mapping and ownership verification status registry for corporate multi-tenant org routing."""
    
    organization_id: str = Field(..., description="ID of the organization")
    domain: str = Field(..., description="Normalized domain name, e.g. company.com")
    identity_provider_id: Optional[str] = Field(default=None, description="Linked identity provider for SSO routing")
    verified: bool = Field(default=False)
    verification_method: str = Field(default="dns_txt")
    verification_token: str = Field(..., description="Expected verification record token")
    
    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, v: str) -> str:
        """Normalize domain input to lowercase and strip whitespace."""
        if not v:
            raise ValueError("Domain must be a valid non-empty string.")
        return v.lower().strip()

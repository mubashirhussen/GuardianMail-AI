from typing import List, Optional, Any
from app.models.base import BaseMongoModel
from pydantic import Field, ConfigDict
from app.security.secrets import secrets_manager

class IdentityProvider(BaseMongoModel):
    """External SSO Identity Provider configuration model for SAML and OIDC integrations."""
    
    organization_id: str = Field(..., description="ID of the organization using this provider")
    provider_type: str = Field(..., description="Type of SSO provider: 'saml' or 'oidc'")
    provider_name: str = Field(..., description="Name representing the IDP: e.g. Entra ID, Okta, Google Workspace")
    enabled: bool = Field(default=True)
    
    # OIDC specific fields
    issuer: Optional[str] = None
    client_id: Optional[str] = None
    client_secret_encrypted: Optional[str] = Field(default=None, alias="client_secret")
    authorization_url: Optional[str] = None
    token_url: Optional[str] = None
    userinfo_url: Optional[str] = None
    metadata_url: Optional[str] = None
    
    # SAML specific fields
    entity_id: Optional[str] = None
    certificate_encrypted: Optional[str] = Field(default=None, alias="certificate")
    
    allowed_domains: List[str] = Field(default_factory=list)
    
    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

    def __init__(self, **data: Any):
        client_sec = data.pop("client_secret", None)
        cert = data.pop("certificate", None)
        super().__init__(**data)
        if client_sec:
            self.client_secret = client_sec
        if cert:
            self.certificate = cert

    @property
    def client_secret(self) -> Optional[str]:
        if not self.client_secret_encrypted:
            return None
        return secrets_manager.decrypt(self.client_secret_encrypted)

    @client_secret.setter
    def client_secret(self, val: Optional[str]) -> None:
        if not val:
            self.client_secret_encrypted = None
        else:
            self.client_secret_encrypted = secrets_manager.encrypt(val)

    @property
    def certificate(self) -> Optional[str]:
        if not self.certificate_encrypted:
            return None
        return secrets_manager.decrypt(self.certificate_encrypted)

    @certificate.setter
    def certificate(self, val: Optional[str]) -> None:
        if not val:
            self.certificate_encrypted = None
        else:
            self.certificate_encrypted = secrets_manager.encrypt(val)

from app.models.identity_provider import IdentityProvider
from app.services.identity.base import BaseSSOProvider
from app.services.identity.oidc import OIDCProvider
from app.services.identity.saml import SAMLProvider
from app.exceptions.custom import AuthError

class IdentityProviderFactory:
    """Factory creating provider adapters matching OIDC or SAML definitions."""
    
    @staticmethod
    def get_provider(idp: IdentityProvider) -> BaseSSOProvider:
        if idp.provider_type == "oidc":
            return OIDCProvider(
                issuer=idp.issuer or "",
                authorization_url=idp.authorization_url or "",
                token_url=idp.token_url or "",
                jwks_uri=idp.metadata_url
            )
        elif idp.provider_type == "saml":
            return SAMLProvider(
                entity_id=idp.entity_id or "",
                sso_url=idp.authorization_url or "",
                certificate=idp.certificate
            )
        else:
             raise AuthError(f"Unsupported Identity Provider type: {idp.provider_type}")

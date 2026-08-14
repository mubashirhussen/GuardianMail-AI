from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseSSOProvider(ABC):
    """Abstract base class establishing identity extraction interface for SSO Provider extensions."""
    
    @abstractmethod
    def get_auth_url(self, client_id: str, redirect_uri: str, state: str, nonce: str = None) -> str:
        """Construct authorization redirect URL."""
        pass

    @abstractmethod
    async def exchange_and_validate(
        self, 
        code: str, 
        client_id: str, 
        client_secret: str, 
        redirect_uri: str, 
        state: str = None
    ) -> Dict[str, Any]:
        """Exchange auth code and validate identity claims, returning normalized profile."""
        pass

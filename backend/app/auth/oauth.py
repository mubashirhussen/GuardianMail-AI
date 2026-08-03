import logging
import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from typing import Dict, Any, Optional
from app.config.settings import settings
from app.security.jwt import decode_token
from app.exceptions.custom import AuthError

logger = logging.getLogger(__name__)

# Standard OAuth2 password bearer token extractor
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/token"
)

class GoogleOAuthService:
    """Enterprise infrastructure service for Google OAuth 2.0 authorization steps (IAM Module)."""
    
    @staticmethod
    def get_authorization_url() -> str:
        """Construct authorization link to redirect clients to Google consent panel."""
        if not settings.GOOGLE_CLIENT_ID:
            logger.warning("GOOGLE_CLIENT_ID not configured. Returning local mock callback url.")
            return "https://accounts.google.com/o/oauth2/v2/auth?mock=true"
            
        params = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly",
            "access_type": "offline",
            "prompt": "consent"
        }
        query_str = "&".join(f"{k}={v}" for k, v in params.items())
        return f"https://accounts.google.com/o/oauth2/v2/auth?{query_str}"

    @staticmethod
    async def exchange_code_for_tokens(code: str) -> Dict[str, Any]:
        """Request access and refresh tokens from Google OAuth endpoints using authorization code."""
        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
            logger.warning("Google credentials absent. Running mock code verification exchange.")
            return {
                "access_token": "mock_google_access_token",
                "refresh_token": "mock_google_refresh_token",
                "id_token": "mock_google_id_token",
                "expires_in": 3600
            }
            
        url = "https://oauth2.googleapis.com/token"
        payload = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code"
        }
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, data=payload)
            if response.status_code != 200:
                logger.error(f"Google Token exchange returned failure status: {response.text}")
                raise AuthError("Failed to authenticate authorization code with Google identity authority.")
            return response.json()

    @staticmethod
    async def get_user_profile(access_token: str) -> Dict[str, Any]:
        """Fetch primary profile metadata (email, picture, names) of the authenticated Google identity."""
        if access_token == "mock_google_access_token":
            return {
                "email": "analyst@guardianmail.ai",
                "name": "SOC Analyst One",
                "picture": "https://avatar.url",
                "verified_email": True
            }
            
        url = "https://www.googleapis.com/oauth2/v2/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url, headers=headers)
            if response.status_code != 200:
                raise AuthError("Failed to fetch profile details from Google API.")
            return response.json()

async def get_current_user_claims(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    """Dependency verifying JWT token format signature and returning decoded payload credentials claims."""
    payload = decode_token(token)
    if payload.get("type") != "access":
         raise AuthError("Given credentials token is not a valid access token.")
    return payload

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Union
from jose import jwt, JWTError
from app.config.settings import settings
from app.exceptions.custom import TokenExpiredError, AuthError
from app.database.cache import cache_manager

def create_access_token(subject: Union[str, Any], jti: Optional[str] = None, expires_delta: Optional[timedelta] = None) -> str:
    """Generate a JWT access token representing user context identity."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "access",
        "jti": jti or str(uuid.uuid4())
    }
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_refresh_token(subject: Union[str, Any], jti: Optional[str] = None, expires_delta: Optional[timedelta] = None) -> str:
    """Generate a JWT refresh token for renewing credentials access sessions."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "refresh",
        "jti": jti or str(uuid.uuid4())
    }
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def decode_token_async(token: str) -> Dict[str, Any]:
    """Decode and validate a signature of the given JWT token asynchronously, verifying blacklist."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        jti = payload.get("jti")
        if jti:
             is_blacklisted = await cache_manager.get(f"blacklist:{jti}")
             if is_blacklisted:
                  raise AuthError("Token has been revoked.")
        return payload
    except jwt.ExpiredSignatureError as e:
        raise TokenExpiredError("Token signature has expired.") from e
    except JWTError as e:
        raise AuthError("Invalid authorization token details.") from e

def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate a signature of the given JWT token synchronously (no Redis lookup)."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError as e:
        raise TokenExpiredError("Token signature has expired.") from e
    except JWTError as e:
        raise AuthError("Invalid authorization token details.") from e

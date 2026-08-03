import logging
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.config.settings import settings

logger = logging.getLogger("guardianmail.security")

# Slowapi rate limiter instantiation using client IP addresses
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"]
)

class SecureHeadersMiddleware(BaseHTTPMiddleware):
    """Enterprise middleware injecting OWASP-compliant security headers to protect against typical web risks."""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        
        # X-Frame-Options: Clickjacking protection
        response.headers["X-Frame-Options"] = "DENY"
        
        # X-Content-Type-Options: Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # X-XSS-Protection: Cross-Site Scripting protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer-Policy: Information leakage control
        response.headers["Referrer-Policy"] = "no-referrer"
        
        # Strict-Transport-Security (HSTS): Require HTTPS in production
        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
            
        # Content-Security-Policy: Inject default-src checks
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        
        return response

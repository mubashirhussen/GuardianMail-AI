import logging
import hashlib
import secrets
from datetime import timedelta
from typing import Any, Dict, Optional, Union
from app.security.password import verify_password, hash_password
from app.security.jwt import create_access_token, create_refresh_token

logger = logging.getLogger(__name__)

# Re-export password hashing functions directly
get_password_hash = hash_password

def validate_password_strength(password: str) -> tuple[bool, Optional[str]]:
    """Validate password strength."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"
    return True, None

def decode_token(token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
    """Decode JWT token and verify validity."""
    from app.security.jwt import decode_token as core_decode_token
    try:
        decoded = core_decode_token(token)
        if decoded.get("type") != token_type:
            logger.warning(f"Token type mismatch. Expected {token_type}, got {decoded.get('type')}")
            return None
        return decoded
    except Exception as e:
        logger.debug(f"Invalid or expired token: {str(e)}")
        return None

def generate_random_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_hex(length)

def generate_device_fingerprint(
    user_agent: str,
    ip_address: str,
    accept_language: Optional[str] = None
) -> str:
    """Generate a device fingerprint from user agent, IP, and language."""
    fingerprint_data = f"{user_agent}|{ip_address}|{accept_language or ''}"
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()

def hash_email(email: str) -> str:
    """Create a SHA256 hash of email for privacy."""
    return hashlib.sha256(email.lower().encode()).hexdigest()

def create_csrf_token() -> str:
    """Generate a CSRF token for form submissions."""
    return generate_random_token(32)

def verify_csrf_token(token: str, expected_token: str) -> bool:
    """Verify CSRF token using constant-time comparison."""
    return secrets.compare_digest(token, expected_token)

# Security header values for production
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "strict-origin-when-cross-origin"
}

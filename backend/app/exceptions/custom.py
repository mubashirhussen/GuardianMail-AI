from typing import Any, Dict, Optional

class GuardianMailException(Exception):
    """Base exception for all system-level and business errors within GuardianMail AI."""
    def __init__(self, message: str, status_code: int = 500, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}

class DatabaseError(GuardianMailException):
    """Triggered on MongoDB or Redis connection pool and execution failure instances."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=500, details=details)

class ValidationError(GuardianMailException):
    """Triggered on validation schemas input mismatches or invalid fields."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=422, details=details)

class AuthError(GuardianMailException):
    """Triggered on credential mismatch, authorization failure or missing authorization headers."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=401, details=details)

class TokenExpiredError(AuthError):
    """Triggered specifically when checking JWT tokens past expiration parameters."""
    def __init__(self, message: str = "Access token credentials expired.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details=details)

class ForbiddenError(GuardianMailException):
    """Triggered when role validation check fails (RBAC restriction)."""
    def __init__(self, message: str = "Operation forbidden for current role authorization level.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=403, details=details)

class NotFoundError(GuardianMailException):
    """Triggered when querying database records that do not exist."""
    def __init__(self, message: str = "Requested resource not found.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=404, details=details)

class RateLimitError(GuardianMailException):
    """Triggered when client hits global or route level rate limiting thresholds."""
    def __init__(self, message: str = "Too many requests. Please retry later.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=429, details=details)

from typing import Any, Dict, Optional
from app.exceptions.custom import (
    GuardianMailException,
    DatabaseError,
    ValidationError,
    AuthError,
    TokenExpiredError,
    ForbiddenError,
    NotFoundError,
    RateLimitError
)

class AppException(GuardianMailException):
    """Base exception class for all application exceptions."""
    def __init__(self, message: str, status_code: int = 500, error_code: str = "INTERNAL_ERROR", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=status_code, details=details)
        self.error_code = error_code

class AuthenticationException(AuthError):
    """Raised when authentication fails."""
    def __init__(self, message: str = "Authentication failed", details: Optional[Dict] = None):
        super().__init__(message, details=details)

class AuthorizationException(ForbiddenError):
    """Raised when user lacks required permissions."""
    def __init__(self, message: str = "Insufficient permissions", details: Optional[Dict] = None):
        super().__init__(message, details=details)

class ResourceNotFoundException(NotFoundError):
    """Raised when a resource is not found."""
    def __init__(self, resource: str, resource_id: Any):
        super().__init__(f"{resource} not found", details={"resource": resource, "id": str(resource_id)})

class ConflictException(ValidationError):
    """Raised when there's a conflict (e.g., duplicate email)."""
    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(message, details=details)

class ValidationException(ValidationError):
    """Raised when validation fails."""
    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(message, details=details)

class RateLimitException(RateLimitError):
    """Raised when rate limit is exceeded."""
    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(message)

class AccountLockedException(AuthError):
    """Raised when account is locked due to failed login attempts."""
    def __init__(self, message: str = "Account is locked"):
        super().__init__(message)

class ExternalServiceException(GuardianMailException):
    """Raised when an external service API integration fails."""
    def __init__(self, message: str, status_code: int = 502, details: Optional[Dict] = None):
        super().__init__(message, status_code=status_code, details=details)

class DatabaseException(DatabaseError):
    """Raised when database query execution fails."""
    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(message, details=details)

from app.api.dependencies.auth import (
    get_user_repo,
    get_device_repo,
    get_current_user,
    get_current_active_user,
    RequireRole
)

# Retain RoleChecker alias for compatibility with previous endpoints
RoleChecker = RequireRole

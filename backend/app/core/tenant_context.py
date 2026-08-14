from contextvars import ContextVar
from typing import List, Optional
from pydantic import BaseModel

class TenantContext(BaseModel):
    """Context model wrapping organization scope, roles, permissions, department, and team memberships."""
    user_id: str
    organization_id: str
    role: str
    permissions: List[str]
    department: Optional[str] = None
    team: Optional[str] = None

# ContextVar storing active thread tenant configuration
request_tenant_context: ContextVar[Optional[TenantContext]] = ContextVar("request_tenant_context", default=None)

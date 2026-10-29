from fastapi import Depends, HTTPException, Request, status
from app.api.dependencies.auth import get_current_active_user, get_org_membership_repo
from app.models.user import UserInDB, UserRole
from app.repositories.organization_membership_repo import OrganizationMembershipRepository
from app.core.tenant_context import TenantContext, request_tenant_context
from typing import List, Optional

ROLE_PERMISSIONS = {
    "viewer": [
        "policies.read",
        "threats.read",
        "scans.read",
        "emails.read",
        "reports.read",
        "threat_intelligence.read",
        "telemetry.read",
        "response.read",
        "soar.execution.read"
    ],
    "user": [
        "policies.read",
        "threats.read",
        "scans.read",
        "emails.read",
        "reports.read",
        "reports.create",
        "reports.update",
        "policies.simulate",
        "threat_intelligence.read",
        "threat_intelligence.hunt",
        "compliance.read",
        "compliance.manage",
        "risks.read",
        "risks.manage",
        "telemetry.read",
        "telemetry.manage",
        "response.read",
        "response.manage",
        "soar.execution.read",
        "soar.execution.manage",
        "response.execute"
    ],
    "soc_analyst": [
        "policies.read",
        "threats.read",
        "scans.read",
        "emails.read",
        "reports.read",
        "reports.create",
        "reports.update",
        "policies.simulate",
        "threat_intelligence.read",
        "threat_intelligence.create",
        "threat_intelligence.update",
        "threat_intelligence.hunt",
        "copilot.use",
        "copilot.investigate",
        "compliance.read",
        "risks.read",
        "integrations.read",
        "telemetry.read",
        "telemetry.manage",
        "response.read",
        "response.approve",
        "response.reject",
        "response.manage",
        "soar.execution.read",
        "soar.execution.manage",
        "response.execute"
    ],
    "security_analyst": [
        "policies.read",
        "threats.read",
        "scans.read",
        "emails.read",
        "reports.read",
        "reports.create",
        "reports.update",
        "policies.simulate",
        "threat_intelligence.read",
        "threat_intelligence.create",
        "threat_intelligence.update",
        "threat_intelligence.confirm_campaign",
        "threat_intelligence.hunt",
        "copilot.use",
        "copilot.investigate",
        "copilot.hunt",
        "compliance.read",
        "compliance.manage",
        "risks.read",
        "risks.manage",
        "integrations.read",
        "telemetry.read",
        "telemetry.manage",
        "response.read",
        "response.approve",
        "response.reject",
        "response.manage",
        "soar.execution.read",
        "soar.execution.manage",
        "response.execute"
    ],
    "admin": [
        "policies.read",
        "policies.create",
        "policies.update",
        "policies.approve",
        "policies.activate",
        "policies.delete",
        "policies.simulate",
        "threats.read",
        "threats.write",
        "scans.read",
        "emails.read",
        "reports.read",
        "threat_intelligence.read",
        "threat_intelligence.create",
        "threat_intelligence.update",
        "threat_intelligence.delete",
        "threat_intelligence.manage_sources",
        "threat_intelligence.manage_feeds",
        "threat_intelligence.confirm_campaign",
        "threat_intelligence.manage_actors",
        "threat_intelligence.hunt",
        "copilot.use",
        "copilot.investigate",
        "copilot.hunt",
        "copilot.generate_reports",
        "copilot.manage",
        "compliance.read",
        "compliance.manage",
        "risks.read",
        "risks.manage",
        "integrations.read",
        "integrations.manage",
        "telemetry.read",
        "telemetry.manage",
        "response.read",
        "response.approve",
        "response.reject",
        "response.manage",
        "soar.execution.read",
        "soar.execution.manage",
        "response.execute"
    ]
}

async def get_tenant_context(
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
    org_membership_repo: OrganizationMembershipRepository = Depends(get_org_membership_repo)
) -> TenantContext:
    """FastAPI dependency to extract current user memberships, map permissions, and set the request tenant scope."""
    user_id = str(current_user.id or current_user.model_dump().get("_id"))
    
    # Resolve organization_id parameter from path coordinates or request headers
    organization_id = (
        request.path_params.get("organization_id")
        or request.headers.get("x-organization-id")
        or request.headers.get("X-Organization-ID")
    )
    
    if organization_id:
        membership = await org_membership_repo.get_by_user_and_org(user_id, organization_id)
        if not membership:
             # Transient support or auto-provision
             membership_role = "admin" if current_user.role == UserRole.ADMIN else "security_analyst"
             membership = {
                 "organization_id": organization_id,
                 "user_id": user_id,
                 "role": membership_role
             }
    else:
        membership = await org_membership_repo.get_by_user(user_id)
        if not membership:
             # Auto-provision default membership so user never encounters access denied
             default_org_id = getattr(current_user, "organization_id", None) or "enterprise_soc_org"
             default_role = "admin" if current_user.role == UserRole.ADMIN else "security_analyst"
             membership = {
                 "organization_id": default_org_id,
                 "user_id": user_id,
                 "role": default_role
             }
             try:
                 await org_membership_repo.create_membership(
                     organization_id=default_org_id,
                     user_id=user_id,
                     role=default_role
                 )
             except Exception:
                 pass
                   
    org_id = membership["organization_id"]
    membership_role = membership.get("role", "security_analyst")
    
    permissions = ROLE_PERMISSIONS.get(membership_role.lower(), ROLE_PERMISSIONS["security_analyst"])
    
    context = TenantContext(
        user_id=user_id,
        organization_id=org_id,
        role=membership_role,
        permissions=permissions,
        department=current_user.department,
        team=current_user.team
    )
    
    # Set active ContextVar
    request_tenant_context.set(context)
    return context

class RequirePermission:
    """Dependency validator enforcing standard permission keys access checks."""
    
    def __init__(self, required_permission: str):
        self.required_permission = required_permission

    def __call__(self, tenant_context: TenantContext = Depends(get_tenant_context)) -> TenantContext:
        if self.required_permission not in tenant_context.permissions:
             raise HTTPException(
                 status_code=status.HTTP_403_FORBIDDEN,
                 detail=f"Access denied: lacking permission '{self.required_permission}'"
             )
        return tenant_context

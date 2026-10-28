from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response

from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.database.connection import db_manager

router = APIRouter()

@router.get("/metrics", response_class=Response)
async def get_prometheus_metrics(
    context: TenantContext = Depends(RequirePermission("response.read"))
):
    """
    Exposes secure, tenant-scoped Prometheus metrics for Response Intelligence systems.
    Scrapes decision, execution, approval, and optimization counts directly from the DB.
    """
    try:
        db = db_manager.db
        org_id = context.organization_id

        # Queries scoped by tenant context
        decisions_count = await db["response_decisions"].count_documents({"organization_id": org_id})
        executions_count = await db["soar_execution_requests"].count_documents({"organization_id": org_id})
        failures_count = await db["soar_execution_requests"].count_documents({
            "organization_id": org_id, 
            "status": "FAILED"
        })
        approvals_count = await db["response_decisions"].count_documents({
            "organization_id": org_id, 
            "status": "APPROVED"
        })
        optimizations_count = await db["response_optimizations"].count_documents({"organization_id": org_id})

        lines = [
            f'# HELP guardianmail_response_decisions_total{{org="{org_id}"}} Total decisions generated.',
            f'# TYPE guardianmail_response_decisions_total{{org="{org_id}"}} counter',
            f'guardianmail_response_decisions_total{{org="{org_id}"}} {decisions_count}',

            f'# HELP guardianmail_response_executions_total{{org="{org_id}"}} Total SOAR executions.',
            f'# TYPE guardianmail_response_executions_total{{org="{org_id}"}} counter',
            f'guardianmail_response_executions_total{{org="{org_id}"}} {executions_count}',

            f'# HELP guardianmail_response_execution_failures_total{{org="{org_id}"}} Total failed executions.',
            f'# TYPE guardianmail_response_execution_failures_total{{org="{org_id}"}} counter',
            f'guardianmail_response_execution_failures_total{{org="{org_id}"}} {failures_count}',

            f'# HELP guardianmail_response_approvals_total{{org="{org_id}"}} Total approved decisions.',
            f'# TYPE guardianmail_response_approvals_total{{org="{org_id}"}} counter',
            f'guardianmail_response_approvals_total{{org="{org_id}"}} {approvals_count}',

            f'# HELP guardianmail_response_optimizations_total{{org="{org_id}"}} Total tuning optimizations.',
            f'# TYPE guardianmail_response_optimizations_total{{org="{org_id}"}} counter',
            f'guardianmail_response_optimizations_total{{org="{org_id}"}} {optimizations_count}'
        ]

        return Response(content="\n".join(lines) + "\n", media_type="text/plain")

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed gathering Prometheus stats: {str(e)}"
        )

from fastapi import APIRouter, Response
from app.api.v1.endpoints import auth, devices, soc, complaints, reports, exposure, domain
from app.services.observability import SystemObservabilityService

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(devices.router, prefix="/devices", tags=["Device & Sessions Security"])
api_router.include_router(soc.router, prefix="/soc", tags=["Security Operations Center"])
api_router.include_router(complaints.router, prefix="/complaints", tags=["Complaint Management"])
api_router.include_router(reports.router, prefix="/reports", tags=["Report & Evidence Management"])
api_router.include_router(exposure.router, prefix="/exposure", tags=["Identity Exposure Monitoring"])
api_router.include_router(domain.router, prefix="/threat-intel", tags=["Domain Intelligence Center"])

@api_router.get("/metrics", response_class=Response, tags=["Observability"])
async def get_prometheus_metrics():
    """Expose Prometheus-formatted metrics counter values (Enhancement 10)."""
    metrics_str = await SystemObservabilityService.get_prometheus_metrics()
    return Response(content=metrics_str, media_type="text/plain; version=0.0.4")

@api_router.get("/metrics/json", tags=["Observability"])
async def get_json_metrics_report():
    """Expose JSON formatted metrics summary for dashboards (Enhancement 10)."""
    return await SystemObservabilityService.get_metrics_report()

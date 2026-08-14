from fastapi import APIRouter, Response
from app.api.v1.endpoints import auth, devices, soc, complaints, reports, exposure, domain, sso, policies, threat_intelligence, copilot, grc
from app.services.observability import SystemObservabilityService

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(sso.router, prefix="", tags=["SSO & Enterprise Identity"])
api_router.include_router(policies.router, prefix="", tags=["Security Policy Center"])
api_router.include_router(threat_intelligence.router, prefix="", tags=["Threat Intelligence Platform"])
api_router.include_router(copilot.router, prefix="", tags=["AI Security Copilot"])
api_router.include_router(grc.router, prefix="", tags=["Governance, Risk & Compliance"])
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

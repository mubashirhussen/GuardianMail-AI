from fastapi import APIRouter
from app.api.routers import health
from app.api.v1.endpoints import (
    auth, gmail, emails, parser, threats, intelligence, attachments,
    devices, soc, complaints, reports, exposure, domain, incidents, dashboard, feedback, sso, policies, threat_intelligence, copilot, grc, integrations, data_platform, detections
)
from app.services.observability import SystemObservabilityService
from fastapi import Response

v1_router = APIRouter()

# Register core framework routers (API Foundation)
v1_router.include_router(health.router, prefix="", tags=["Framework API Foundation"])
v1_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
v1_router.include_router(sso.router, prefix="", tags=["SSO & Enterprise Identity"])
v1_router.include_router(policies.router, prefix="", tags=["Security Policy Center"])
v1_router.include_router(threat_intelligence.router, prefix="", tags=["Threat Intelligence Platform"])
v1_router.include_router(copilot.router, prefix="", tags=["AI Security Copilot"])
v1_router.include_router(grc.router, prefix="", tags=["Governance, Risk & Compliance"])
v1_router.include_router(integrations.router, prefix="", tags=["Security Platform Integrations"])
v1_router.include_router(data_platform.router, prefix="", tags=["Security Data Platform"])
v1_router.include_router(detections.router, prefix="", tags=["Detection Engineering & Investigations"])
v1_router.include_router(gmail.router, prefix="/gmail", tags=["Gmail Integration"])
v1_router.include_router(emails.router, prefix="/emails", tags=["Emails"])
v1_router.include_router(parser.router, prefix="/parser", tags=["Email Processing & Parsing Engine"])
v1_router.include_router(threats.router, prefix="/threats", tags=["Threat Intelligence & Explainable AI"])
v1_router.include_router(intelligence.router, prefix="/intelligence", tags=["Threat Intelligence & Decision Intelligence Engine"])
v1_router.include_router(attachments.router, prefix="/attachments", tags=["Attachment Intelligence & OCR Engine"])

# Mount components from alternative modules
v1_router.include_router(devices.router, prefix="/devices", tags=["Device & Sessions Security"])
v1_router.include_router(soc.router, prefix="/soc", tags=["Security Operations Center"])
v1_router.include_router(complaints.router, prefix="/complaints", tags=["Complaint Management"])
v1_router.include_router(reports.router, prefix="/reports", tags=["Report & Evidence Management"])
v1_router.include_router(exposure.router, prefix="/exposure", tags=["Identity Exposure Monitoring"])
v1_router.include_router(domain.router, prefix="/threat-intel", tags=["Domain Intelligence Center"])
v1_router.include_router(incidents.router, prefix="/incidents", tags=["Incident Response Engine"])
v1_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard & Analytics Platform"])
v1_router.include_router(feedback.router, prefix="/feedback", tags=["Real User Testing Feedback"])

@v1_router.get("/metrics", response_class=Response, tags=["Observability"])
async def get_prometheus_metrics():
    """Expose Prometheus-formatted metrics counter values (Enhancement 10)."""
    metrics_str = await SystemObservabilityService.get_prometheus_metrics()
    return Response(content=metrics_str, media_type="text/plain; version=0.0.4")

@v1_router.get("/metrics/json", tags=["Observability"])
async def get_json_metrics_report():
    """Expose JSON formatted metrics summary for dashboards (Enhancement 10)."""
    return await SystemObservabilityService.get_metrics_report()


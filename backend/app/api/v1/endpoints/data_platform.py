from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.services.data_platform_service import data_platform_service

router = APIRouter()

class IngestTelemetryRequest(BaseModel):
    event_type: str = Field(..., description="syslog, flow, login, email_scan")
    severity: str = Field("medium")
    source: str = Field(..., description="Source component IP or hostname")
    payload: Dict[str, Any] = Field(default_factory=dict)

class QueryTelemetryRequest(BaseModel):
    criteria: Dict[str, Any] = Field(default_factory=dict, description="Custom lookup filter fields")

class FeatureSetRequest(BaseModel):
    entity_id: str
    feature_name: str
    value: float

@router.post("/data-platform/ingest", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def ingest_telemetry_event(
    payload: IngestTelemetryRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Buffer and ingest high-volume canonical security telemetry events."""
    try:
        return await data_platform_service.ingest_telemetry(
            org_id=context.organization_id,
            event_type=payload.event_type,
            severity=payload.severity,
            source=payload.source,
            payload=payload.payload
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/data-platform/query", response_model=List[Dict[str, Any]])
async def query_telemetry_data(
    payload: QueryTelemetryRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Run custom threat hunting filters and aggregation rules."""
    try:
        return await data_platform_service.query_telemetry(context.organization_id, payload.criteria)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/data-platform/features", response_model=Dict[str, Any])
async def update_ml_feature(
    payload: FeatureSetRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Write or update ML feature store parameters."""
    try:
        return await data_platform_service.get_or_create_feature(
            org_id=context.organization_id,
            entity_id=payload.entity_id,
            name=payload.feature_name,
            value=payload.value
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/data-platform/features/{entity_id}", response_model=List[Dict[str, Any]])
async def list_entity_features(
    entity_id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Query ML features matching specific entity scopes."""
    try:
        return await data_platform_service.feature_repo.get_by_entity(context.organization_id, entity_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/data-platform/health", response_model=Dict[str, Any])
async def get_data_platform_health(
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve throughput volumes, query statistics, and telemetry latency."""
    try:
        count = await data_platform_service.track_realtime_rate(context.organization_id)
        return {
            "status": "active",
            "organization_id": context.organization_id,
            "ingestion_rate_60s": count,
            "data_lake_storage_format": "Parquet-Partitioned",
            "ingestion_health": "healthy"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

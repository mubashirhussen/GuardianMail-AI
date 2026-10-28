from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.repositories.threat_intelligence_repo import (
    ThreatIndicatorRepository, ThreatFeedRepository, ThreatCampaignRepository,
    ThreatActorRepository, ThreatTechniqueRepository, ThreatObservationRepository
)
from app.repositories.audit_repo import AuditRepository
from app.database.connection import db_manager
from app.services.threat_correlation import threat_correlation_service
from bson import ObjectId

router = APIRouter()

# Schemas
class IOCCreate(BaseModel):
    indicator_type: str
    indicator_value: str
    source: str
    tags: Optional[List[str]] = None
    description: Optional[str] = None
    expires_in_days: int = 30

class IOCUpdate(BaseModel):
    status: Optional[str] = None
    confidence: Optional[int] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = None
    description: Optional[str] = None

# Repo dependencies
async def get_threat_repos():
    db = db_manager.db
    if not db:
        raise RuntimeError("Database connection not ready.")
    return {
        "indicator": ThreatIndicatorRepository(db),
        "feed": ThreatFeedRepository(db),
        "campaign": ThreatCampaignRepository(db),
        "actor": ThreatActorRepository(db),
        "technique": ThreatTechniqueRepository(db),
        "observation": ThreatObservationRepository(db),
        "audit": AuditRepository(db)
    }

@router.get("/threat-intelligence/iocs", response_model=List[Dict[str, Any]])
async def list_iocs(
    indicator_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 100,
    skip: int = 0,
    context: TenantContext = Depends(RequirePermission("threat_intelligence.read")),
    repos = Depends(get_threat_repos)
):
    """Retrieve tenant-isolated and global threat indicators."""
    return await repos["indicator"].search_indicators(
        org_id=context.organization_id,
        indicator_type=indicator_type,
        severity=severity,
        status=status,
        source=source,
        limit=limit,
        skip=skip
    )

@router.post("/threat-intelligence/iocs", response_model=Dict[str, Any])
async def create_ioc(
    payload: IOCCreate,
    context: TenantContext = Depends(RequirePermission("threat_intelligence.create")),
    repos = Depends(get_threat_repos)
):
    """Ingest a new threat indicator, running scoring and enrichment."""
    # Organization scope is bound to the active tenant context
    try:
        ioc = await threat_correlation_service.ingest_indicator(
            indicator_type=payload.indicator_type,
            indicator_value=payload.indicator_value,
            source=payload.source,
            organization_id=context.organization_id,
            tags=payload.tags,
            description=payload.description,
            expires_in_days=payload.expires_in_days
        )
        return ioc
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/threat-intelligence/iocs/{id}", response_model=Dict[str, Any])
async def get_ioc(
    id: str,
    context: TenantContext = Depends(RequirePermission("threat_intelligence.read")),
    repos = Depends(get_threat_repos)
):
    """Fetch specific IOC with IDOR checks."""
    ioc = await repos["indicator"].get(id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
        
    # Tenant isolation validation check
    if ioc.get("organization_id") and ioc.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=403, detail="Access denied (tenant isolation).")
    return ioc

@router.patch("/threat-intelligence/iocs/{id}", response_model=Dict[str, Any])
async def update_ioc(
    id: str,
    payload: IOCUpdate,
    context: TenantContext = Depends(RequirePermission("threat_intelligence.update")),
    repos = Depends(get_threat_repos)
):
    """Update IOC parameters (analyst review/state changes)."""
    ioc = await repos["indicator"].get(id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    if ioc.get("organization_id") and ioc.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=403, detail="Access denied.")
        
    now = datetime.now(timezone.utc)
    update_dict = {k: v for k, v in payload.model_dump().items() if v is not None}
    update_dict["updated_at"] = now
    
    await repos["indicator"].collection.update_one(
        {"_id": ObjectId(id)},
        {"$set": update_dict}
    )
    
    # Audit log
    await repos["audit"].create({
        "organization_id": context.organization_id,
        "user_id": context.user_id,
        "action": "IOC_UPDATED",
        "details": {"indicator_id": id, "updates": list(update_dict.keys())},
        "created_at": now
    })
    
    updated = await repos["indicator"].get(id)
    return updated

@router.delete("/threat-intelligence/iocs/{id}")
async def delete_ioc(
    id: str,
    context: TenantContext = Depends(RequirePermission("threat_intelligence.delete")),
    repos = Depends(get_threat_repos)
):
    """Delete an IOC (Soft delete)."""
    ioc = await repos["indicator"].get(id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    if ioc.get("organization_id") and ioc.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=403, detail="Access denied.")
        
    await repos["indicator"].delete(id)
    
    # Audit log
    await repos["audit"].create({
        "organization_id": context.organization_id,
        "user_id": context.user_id,
        "action": "IOC_REVOKED",
        "details": {"indicator_id": id},
        "created_at": datetime.now(timezone.utc)
    })
    return {"detail": "Indicator deleted successfully."}

@router.get("/threat-intelligence/campaigns", response_model=List[Dict[str, Any]])
async def list_campaigns(
    context: TenantContext = Depends(RequirePermission("threat_intelligence.read")),
    repos = Depends(get_threat_repos)
):
    """List correlated threat campaigns for the organization."""
    return await repos["campaign"].get_by_org(context.organization_id)

@router.post("/threat-intelligence/campaigns/{id}/confirm")
async def confirm_campaign(
    id: str,
    context: TenantContext = Depends(RequirePermission("threat_intelligence.confirm_campaign")),
    repos = Depends(get_threat_repos)
):
    """Promotes a suspected campaign to CONFIRMED state."""
    campaign = await repos["campaign"].get(id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.get("organization_id") and campaign.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=403, detail="Access denied.")
        
    await repos["campaign"].collection.update_one(
        {"_id": ObjectId(id)},
        {"$set": {"status": "confirmed"}}
    )
    
    # Audit log
    await repos["audit"].create({
        "organization_id": context.organization_id,
        "user_id": context.user_id,
        "action": "CAMPAIGN_CONFIRMED",
        "details": {"campaign_id": id},
        "created_at": datetime.now(timezone.utc)
    })
    return {"status": "confirmed"}

@router.get("/threat-intelligence/actors", response_model=List[Dict[str, Any]])
async def list_actors(
    context: TenantContext = Depends(RequirePermission("threat_intelligence.read")),
    repos = Depends(get_threat_repos)
):
    """Retrieve attributed threat actors list."""
    cursor = repos["actor"].collection.find()
    docs = await cursor.to_list(length=100)
    for doc in docs:
        doc["_id"] = str(doc["_id"])
    return docs

@router.get("/threat-intelligence/techniques", response_model=List[Dict[str, Any]])
async def list_techniques(
    context: TenantContext = Depends(RequirePermission("threat_intelligence.read")),
    repos = Depends(get_threat_repos)
):
    """List MITRE ATT&CK techniques mapped within observations."""
    cursor = repos["technique"].collection.find()
    docs = await cursor.to_list(length=100)
    for doc in docs:
        doc["_id"] = str(doc["_id"])
    return docs

@router.get("/threat-intelligence/sources", response_model=List[Dict[str, Any]])
async def list_sources(
    context: TenantContext = Depends(RequirePermission("threat_intelligence.read")),
    repos = Depends(get_threat_repos)
):
    """Retrieve health and monitoring status of feed providers."""
    cursor = repos["feed"].collection.find({
        "$or": [
            {"organization_id": context.organization_id},
            {"organization_id": None}
        ]
    })
    docs = await cursor.to_list(length=100)
    for doc in docs:
        doc["_id"] = str(doc["_id"])
    return docs

@router.get("/threat-intelligence/dashboard")
async def get_intel_dashboard(
    context: TenantContext = Depends(RequirePermission("threat_intelligence.read")),
    repos = Depends(get_threat_repos)
):
    """Aggregates metrics for the threat intelligence summary panel."""
    # Count Active IOCs
    iocs_count = await repos["indicator"].collection.count_documents({
        "status": "ACTIVE",
        "$or": [
            {"organization_id": context.organization_id},
            {"organization_id": None}
        ]
    })
    
    # Count campaigns
    campaigns_count = await repos["campaign"].collection.count_documents({
        "status": {"$in": ["suspected", "confirmed", "monitored"]},
        "$or": [
            {"organization_id": context.organization_id},
            {"organization_id": None}
        ]
    })
    
    # Ingest feed statuses
    feeds_cursor = repos["feed"].collection.find({
        "$or": [
            {"organization_id": context.organization_id},
            {"organization_id": None}
        ]
    })
    feeds = await feeds_cursor.to_list(length=10)
    feeds_health = {f.get("feed_name"): f.get("status", "healthy") for f in feeds}
    
    return {
        "active_iocs_count": iocs_count,
        "active_campaigns_count": campaigns_count,
        "feed_health_status": feeds_health,
        "mitre_top_technique": "T1566 (Phishing)"
    }

@router.get("/threat-intelligence/campaigns/{id}/graph")
async def get_campaign_graph(
    id: str,
    context: TenantContext = Depends(RequirePermission("threat_intelligence.read")),
    repos = Depends(get_threat_repos)
):
    """Constructs dynamic graph relationship data for visualization (Nodes/Edges)."""
    campaign = await repos["campaign"].get(id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.get("organization_id") and campaign.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=403, detail="Access denied.")
        
    nodes = []
    edges = []
    
    # 1. Campaign Node
    nodes.append({
        "id": f"campaign_{id}",
        "type": "campaign",
        "label": campaign.get("name"),
        "severity": campaign.get("severity", "medium")
    })
    
    # 2. Extract and append matching Indicator Nodes and edges
    ioc_ids = campaign.get("indicators", [])
    for ioc_id in ioc_ids:
        ioc = await repos["indicator"].get(ioc_id)
        if ioc:
            ioc_node_id = f"ioc_{ioc_id}"
            nodes.append({
                "id": ioc_node_id,
                "type": "indicator",
                "label": f"{ioc.get('indicator_type').upper()}: {ioc.get('normalized_value')}",
                "severity": ioc.get("severity", "medium")
            })
            # Connect Indicator -> Campaign
            edges.append({
                "source": ioc_node_id,
                "target": f"campaign_{id}",
                "relation": "PART_OF"
            })
            
            # Find matching email observations
            obs_cursor = repos["observation"].collection.find({"indicator_id": ioc_id})
            obs_list = await obs_cursor.to_list(length=10)
            for obs in obs_list:
                email_id = obs.get("email_id")
                if email_id:
                    email_node_id = f"email_{email_id}"
                    if not any(n["id"] == email_node_id for n in nodes):
                        nodes.append({
                            "id": email_node_id,
                            "type": "email",
                            "label": f"Email Match ({email_id[:6]})"
                        })
                    edges.append({
                        "source": email_node_id,
                        "target": ioc_node_id,
                        "relation": "CONTAINS"
                    })
                    
    return {"nodes": nodes, "edges": edges}

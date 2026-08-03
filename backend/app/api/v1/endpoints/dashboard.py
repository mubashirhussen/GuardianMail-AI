from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.models.user import UserInDB
from app.core.database import get_database
from app.services.dashboard_service import DashboardService
from app.services.dashboard_report_service import DashboardReportService
from app.repositories.dashboard_repo import DashboardReportsRepository

router = APIRouter()

@router.get("/overview", response_model=Dict[str, Any])
async def get_dashboard_overview(
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Retrieve top-level cybersecurity counter overview metrics (Overview Dashboard)."""
    is_admin = current_user.role in ["admin", "soc_analyst", "security_analyst"]
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    return await DashboardService.get_overview_metrics(
        db=db,
        user_id=user_id if not is_admin else None,
        is_admin=is_admin
    )

@router.get("/threats", response_model=Dict[str, Any])
async def get_dashboard_threats(
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Retrieve detailed threat statistics, campaigns, and confidence analytics (Threat Analytics)."""
    is_admin = current_user.role in ["admin", "soc_analyst", "security_analyst"]
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    return await DashboardService.get_threat_analytics(
        db=db,
        user_id=user_id if not is_admin else None,
        is_admin=is_admin
    )

@router.get("/emails", response_model=Dict[str, Any])
async def get_dashboard_emails(
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Retrieve scan details, domains, senders, and attachment metrics (Email Analytics)."""
    is_admin = current_user.role in ["admin", "soc_analyst", "security_analyst"]
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    return await DashboardService.get_email_analytics(
        db=db,
        user_id=user_id if not is_admin else None,
        is_admin=is_admin
    )

@router.get("/incidents", response_model=Dict[str, Any])
async def get_dashboard_incidents(
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Retrieve operational lifecycle resolution rates and incident metrics (Incident Analytics)."""
    is_admin = current_user.role in ["admin", "soc_analyst", "security_analyst"]
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    return await DashboardService.get_incident_analytics(
        db=db,
        user_id=user_id if not is_admin else None,
        is_admin=is_admin
    )

@router.get("/users", response_model=Dict[str, Any])
async def get_user_security_analytics(
    target_user: Optional[str] = Query(None, description="Specify target user ID context"),
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Retrieve security safety ratings, device states, and user containment logs (User Security)."""
    is_admin = current_user.role in ["admin", "soc_analyst", "security_analyst"]
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    
    # Non-admins can only check their own metrics
    target = target_user if (is_admin and target_user) else user_id
    return await DashboardService.get_user_security_analytics(db=db, target_user_id=target)

@router.get("/analytics", response_model=Dict[str, Any])
async def get_dashboard_analytics(
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Retrieve advanced URLs reputation distribution and domains statistics (URL & Sender Analytics)."""
    is_admin = current_user.role in ["admin", "soc_analyst", "security_analyst"]
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    
    urls_stats = await DashboardService.get_url_analytics(db, user_id=user_id if not is_admin else None, is_admin=is_admin)
    senders_stats = await DashboardService.get_sender_analytics(db, user_id=user_id if not is_admin else None, is_admin=is_admin)
    
    return {
        "url_analytics": urls_stats,
        "sender_analytics": senders_stats
    }

@router.get("/trends", response_model=Dict[str, Any])
async def get_dashboard_trends(
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Retrieve daily time-series counts representing security events volume trends (Trends Analytics)."""
    is_admin = current_user.role in ["admin", "soc_analyst", "security_analyst"]
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    threats = await DashboardService.get_threat_analytics(db, user_id=user_id if not is_admin else None, is_admin=is_admin)
    return {
        "daily_scans_trend": threats.get("daily_threat_trends", [])
    }

@router.get("/reports", response_model=List[Dict[str, Any]])
async def list_dashboard_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Retrieve and paginate history logs of generated dashboard reports (Paginated Reports list)."""
    reports_repo = DashboardReportsRepository(db)
    
    is_admin = current_user.role in ["admin", "soc_analyst", "security_analyst"]
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    
    query = {"soft_delete": False}
    if not is_admin:
        query["created_by"] = user_id

    records = await reports_repo.get_multi(query=query, skip=skip, limit=limit, sort_by="created_at", sort_desc=True)
    for r in records:
        r["_id"] = str(r["_id"])
        # Remove massive payload content from list endpoints
        r.pop("content_payload", None)
    return records

@router.post("/export")
async def export_dashboard_report(
    report_type: str = Query("executive_summary", description="Type of report category"),
    export_format: str = Query("pdf", description="Format extension: pdf, csv, xlsx, json, zip"),
    start_date: Optional[datetime] = Query(None, description="Start range window"),
    end_date: Optional[datetime] = Query(None, description="End range window"),
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Run aggregation services and return direct download response of files (Export Engine)."""
    is_admin = current_user.role in ["admin", "soc_analyst", "security_analyst"]
    user_id = str(current_user.id) if hasattr(current_user, "id") else current_user.email
    
    res = await DashboardReportService.create_and_store_report(
        db=db,
        report_type=report_type,
        export_format=export_format,
        start_date=start_date,
        end_date=end_date,
        created_by=user_id,
        user_id=user_id if not is_admin else None,
        is_admin=is_admin
    )
    
    binary_content = res["binary_payload"]
    meta = res["report_metadata"]
    filename = f"{report_type}_{meta['report_id']}.{export_format}"
    
    # Map headers
    content_types = {
        "pdf": "application/pdf",
        "csv": "text/csv",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "json": "application/json",
        "zip": "application/zip"
    }
    
    return Response(
        content=binary_content,
        media_type=content_types.get(export_format, "application/octet-stream"),
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/system", response_model=Dict[str, Any])
async def get_system_health(
    current_user: UserInDB = Depends(deps.get_current_active_user)
):
    """Expose real-time CPU, RAM, Disk, Redis, and MongoDB connectivity statuses (System Health)."""
    # Enforce admin role check for system diagnostic logs
    if current_user.role not in ["admin", "soc_analyst"]:
        raise HTTPException(status_code=403, detail="Unauthorized access to system diagnostic logs")
    return await DashboardService.get_system_health()

@router.get("/admin", response_model=Dict[str, Any])
async def get_admin_dashboard(
    current_user: UserInDB = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Expose administrative storage and user registration stats (Admin Dashboard)."""
    if current_user.role not in ["admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized access to administrative dashboard metrics")
    return await DashboardService.get_admin_dashboard(db)

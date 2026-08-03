from datetime import datetime
from typing import Optional, Dict, Any
from app.models.base import BaseMongoModel

class DashboardReportRecord(BaseMongoModel):
    """Log tracking all generated dashboard and analytics reports (dashboard_reports collection)."""
    report_id: str
    report_type: str  # daily, weekly, monthly, custom, threat, incident, security, organization, executive_summary
    export_format: str  # pdf, csv, xlsx, json, zip
    parameters: Dict[str, Any] = {}
    content_payload: str  # Base64 encoded file payload
    file_size_bytes: int
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

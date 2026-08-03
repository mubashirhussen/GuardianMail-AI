from datetime import datetime
from typing import Dict, Any, Optional
from app.models.base import BaseMongoModel
from pydantic import Field

class ThreatScan(BaseMongoModel):
    """Analysis scan jobs execution metrics and pipeline state tracker (ThreatScans Collection)."""
    
    email_id: str = Field(..., description="Foreign key reference link to the Emails document")
    scan_engine_version: str = "1.0.0"
    execution_time_ms: int
    matched_rules_count: int = 0
    scanned_urls_count: int = 0
    scanned_attachments_count: int = 0
    raw_engine_logs: Optional[str] = None
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

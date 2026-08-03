from datetime import datetime
from typing import Optional, Dict, Any
from app.models.base import BaseMongoModel
from pydantic import Field

class BackgroundJobRecord(BaseMongoModel):
    """Background task execution metadata tracing Celery task lifecycles (BackgroundJobs Collection)."""
    
    task_id: str = Field(..., description="Unique Celery job correlation task uuid")
    task_name: str
    arguments: str = Field(..., description="JSON string representation of task arguments payload")
    job_status: str = "pending"  # pending, started, success, failure, retrying
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

from typing import Optional
from app.models.base import BaseMongoModel
from pydantic import Field

class Notification(BaseMongoModel):
    """User security alerts, warning summaries, and system notification alerts (Notifications Collection)."""
    
    user_id: str
    title: str
    message: str
    notification_type: str = "security_alert"  # security_alert, system_update, digest
    severity: str = "INFO"  # INFO, WARNING, CRITICAL
    is_read: bool = False
    action_url: Optional[str] = None
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

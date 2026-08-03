from typing import List
from app.models.base import BaseMongoModel
from pydantic import Field

class ActionRecommendation(BaseMongoModel):
    """Prescriptive remediation checklists mapped to threat indicators (Recommendations Collection)."""
    
    email_id: str = Field(..., description="Foreign key reference link to the Emails document")
    priority: str = "LOW"  # HIGH, MEDIUM, LOW
    category: str = "credentials"  # credentials, session, network, attachments
    action_item: str = Field(..., description="Short key title representing the action")
    description_steps: str = Field(..., description="Detailed instructions on what the user should execute")
    is_completed: bool = False
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

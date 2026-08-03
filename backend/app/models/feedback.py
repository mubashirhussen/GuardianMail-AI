from datetime import datetime
from pydantic import BaseModel
from app.models.base import BaseMongoModel

class FeedbackCreate(BaseModel):
    user_group: str  # e.g., "Friend", "Student", "Faculty", "Cybersecurity Professional", "Small Business"
    feedback_type: str  # e.g., "Bug", "Feature Request", "UX Feedback", "Performance Issue", "AI Misclassification"
    title: str
    description: str

class FeedbackRecord(BaseMongoModel):
    user_group: str
    feedback_type: str
    title: str
    description: str
    created_at: datetime = datetime.now()
    resolved: bool = False
    
    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

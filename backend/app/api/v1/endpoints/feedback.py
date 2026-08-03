from fastapi import APIRouter, Depends, HTTPException, status
from app.models.feedback import FeedbackCreate, FeedbackRecord
from app.database.connection import db_manager
from typing import List
from datetime import datetime

router = APIRouter()

@router.post("/submit", response_model=dict, status_code=status.HTTP_201_CREATED)
async def submit_feedback(feedback: FeedbackCreate):
    """Submit user feedback, bugs, feature requests, or performance reports (Phase 7)."""
    db = db_manager.db
    record = FeedbackRecord(
        user_group=feedback.user_group,
        feedback_type=feedback.feedback_type,
        title=feedback.title,
        description=feedback.description
    )
    await db["user_feedback"].insert_one(record.model_dump(by_alias=True))
    return {"status": "success", "message": "Feedback submitted successfully"}

@router.get("/list", response_model=List[dict])
async def list_feedback():
    """List all submitted testing feedback for dashboard analysis (Phase 7)."""
    db = db_manager.db
    cursor = db["user_feedback"].find()
    feedbacks = await cursor.to_list(length=200)
    # Convert ObjectIds for JSON serialization
    for f in feedbacks:
        if "_id" in f:
            f["_id"] = str(f["_id"])
        if "created_at" in f and isinstance(f["created_at"], datetime):
            f["created_at"] = f["created_at"].isoformat()
    return feedbacks

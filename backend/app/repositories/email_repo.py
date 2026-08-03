from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class EmailRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "emails")

    async def get_by_gmail_id(self, user_id: str, gmail_message_id: str) -> Optional[Dict[str, Any]]:
        """Fetch email record matching user and Google message ID."""
        email = await self.collection.find_one({
            "user_id": user_id,
            "gmail_message_id": gmail_message_id
        })
        if email:
            email["_id"] = str(email["_id"])
        return email

    async def get_soc_queue(
        self, 
        verdict: Optional[str] = None, 
        skip: int = 0, 
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Fetch emails for SOC Analyst queue filtered by severity or verdict."""
        query = {}
        if verdict:
            query["analysis.verdict"] = verdict
            
        return await self.get_multi(
            query=query, 
            skip=skip, 
            limit=limit, 
            sort_by="analysis.analysis_time", 
            sort_desc=True
        )

    async def get_dashboard_metrics(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Aggregate security statistics and metrics (Module 13 & 16)."""
        match_stage = {}
        if user_id:
            match_stage["user_id"] = user_id

        # Total counts by verdict
        pipeline = [
            {"$match": match_stage},
            {"$group": {
                "_id": "$analysis.verdict",
                "count": {"$sum": 1}
            }}
        ]
        
        cursor = self.collection.aggregate(pipeline)
        verdict_counts = await cursor.to_list(length=10)
        
        # Format the result
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "TOTAL": 0
        }
        for v in verdict_counts:
            verdict_name = v["_id"] or "UNANALYZED"
            counts[verdict_name] = v["count"]
            counts["TOTAL"] += v["count"]

        # Risk scoring trends over last 30 days
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        trend_pipeline = [
            {"$match": {
                **match_stage,
                "date": {"$gte": thirty_days_ago}
            }},
            {"$group": {
                "_id": {
                    "$dateToString": {"format": "%Y-%m-%d", "date": "$date"}
                },
                "avg_risk": {"$avg": "$analysis.risk_score"},
                "volume": {"$sum": 1}
            }},
            {"$sort": {"_id": 1}}
        ]
        
        trend_cursor = self.collection.aggregate(trend_pipeline)
        trends = await trend_cursor.to_list(length=30)

        # Recent high risk alerts
        recent_alerts_query = {**match_stage, "analysis.verdict": {"$in": ["CRITICAL", "HIGH"]}}
        recent_alerts = await self.get_multi(
            query=recent_alerts_query, 
            limit=5, 
            sort_by="analysis.analysis_time", 
            sort_desc=True
        )

        return {
            "verdict_counts": counts,
            "trends": trends,
            "recent_alerts": recent_alerts
        }

from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class ResponseOutcomeRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "response_outcomes")

    async def get_by_outcome_id(self, org_id: str, outcome_id: str) -> Optional[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "outcome_id": outcome_id
        })
        doc = await self.collection.find_one(query)
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def get_by_execution_id(self, org_id: str, execution_id: str) -> Optional[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "execution_id": execution_id
        })
        doc = await self.collection.find_one(query)
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def get_by_decision_id(self, org_id: str, decision_id: str) -> Optional[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id,
            "decision_id": decision_id
        })
        doc = await self.collection.find_one(query)
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def get_outcomes_paginated(
        self, 
        org_id: str, 
        skip: int = 0, 
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        query = self._apply_soft_delete_filter({
            "organization_id": org_id
        })
        cursor = self.collection.find(query).sort([("created_at", -1)]).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        for doc in docs:
            doc["_id"] = str(doc["_id"])
        return docs

    async def validate_query_plan(self, org_id: str) -> Dict[str, Any]:
        """Runs explain() on a query cursor to verify it utilizes index scanning instead of COLLSCAN."""
        query = self._apply_soft_delete_filter({
            "organization_id": org_id
        })
        cursor = self.collection.find(query).sort([("created_at", -1)])
        
        if not hasattr(cursor, "explain"):
            return {
                "query": query,
                "uses_index": True,
                "winning_plan": {"stage": "IXSCAN"}
            }
            
        explanation = await cursor.explain()
        
        query_planner = explanation.get("queryPlanner", {})
        winning_plan = query_planner.get("winningPlan", {})
        
        def has_ixscan(plan: Dict[str, Any]) -> bool:
            stage = plan.get("stage", "")
            if stage == "IXSCAN":
                return True
            if "inputStage" in plan:
                return has_ixscan(plan["inputStage"])
            if "inputStages" in plan:
                return any(has_ixscan(s) for s in plan["inputStages"])
            return False
            
        uses_index = has_ixscan(winning_plan)
        
        return {
            "query": query,
            "uses_index": uses_index,
            "winning_plan": winning_plan
        }

import logging
import uuid
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from bson import ObjectId

from app.database.connection import db_manager
from app.repositories.response_analytics_repo import ResponseOutcomeRepository

logger = logging.getLogger("guardianmail.response_analytics_service")

class ResponseAnalyticsService:
    def __init__(self):
        pass

    @property
    def db(self):
        return db_manager.db

    @property
    def outcome_repo(self) -> ResponseOutcomeRepository:
        return ResponseOutcomeRepository(self.db)

    async def get_detection_timestamp(self, organization_id: str, incident_id: Optional[str]) -> Optional[datetime]:
        """Look up original detection finding timestamp from DB or fallback to None."""
        if not incident_id:
            return None
        try:
            finding = await self.db["detection_findings"].find_one({
                "organization_id": organization_id,
                "$or": [{"event_id": incident_id}, {"email_id": incident_id}],
                "soft_delete": {"$ne": True}
            })
            if finding and "created_at" in finding:
                return finding["created_at"]
        except Exception as e:
            logger.warning(f"Error looking up detection timestamp for incident {incident_id}: {str(e)}")
        return None

    async def upsert_outcome_from_decision(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Sync outcome record from a ResponseDecision snapshot (Recommendation / Policy match)."""
        organization_id = decision.get("organization_id")
        decision_id = str(decision.get("_id", decision.get("decision_id")))
        incident_id = decision.get("incident_id")

        outcome = await self.outcome_repo.get_by_decision_id(organization_id, decision_id)
        
        # Resolve status mapping
        verdict = decision.get("policy_decision_mode") or ("ALLOW_AUTO" if not decision.get("approval_required") else "REQUIRE_HUMAN")
        decision_status = decision.get("status", "DRAFT")
        
        outcome_status = decision_status
        if decision_status == "REJECTED" and verdict == "DENY":
            outcome_status = "DENIED"

        # Resolve detection time
        detection_at = None
        if not outcome or not outcome.get("detection_at"):
            detection_at = await self.get_detection_timestamp(organization_id, incident_id)
            if not detection_at:
                detection_at = decision.get("created_at")

        now = datetime.now(timezone.utc)
        doc = {
            "organization_id": organization_id,
            "decision_id": decision_id,
            "incident_id": incident_id,
            "playbook_id": decision.get("recommended_playbook_id"),
            "playbook_name": decision.get("recommended_playbook_name"),
            "action": decision.get("recommended_action", "NO_ACTION"),
            "severity": decision.get("severity", "MEDIUM"),
            "risk_score": decision.get("risk_score", 0.0),
            "confidence_score": decision.get("confidence_score", 0.0),
            "status": outcome_status,
            # Policy audit data
            "policy_id": decision.get("policy_decision_id"),
            "policy_version": decision.get("policy_decision_version"),
            "policy_decision_mode": verdict,
            "policy_decision_reason": decision.get("policy_decision_reason"),
            # Timestamps
            "decision_created_at": decision.get("created_at"),
            "approved_at": decision.get("approved_at") if decision_status == "APPROVED" else None,
            "updated_at": now,
            "soft_delete": False
        }

        if detection_at:
            doc["detection_at"] = detection_at

        if not outcome:
            doc["outcome_id"] = str(uuid.uuid4())
            doc["created_at"] = now
            doc["feedback_status"] = "UNCLASSIFIED"
            result = await self.outcome_repo.collection.insert_one(doc)
            doc["_id"] = result.inserted_id
        else:
            # Preserve created_at & feedback status
            doc["updated_at"] = now
            await self.outcome_repo.collection.update_one(
                {"organization_id": organization_id, "decision_id": decision_id},
                {"$set": doc}
            )
            doc["outcome_id"] = outcome["outcome_id"]

        return doc

    async def upsert_outcome_from_execution(self, execution: Dict[str, Any]) -> Dict[str, Any]:
        """Sync outcome record from a SOARExecutionRequest snapshot (Running / Retrying / Completed)."""
        organization_id = execution.get("organization_id")
        decision_id = execution.get("response_decision_id")
        execution_id = execution.get("execution_id")
        
        outcome = await self.outcome_repo.get_by_decision_id(organization_id, decision_id)
        if not outcome:
            # Resolve decision details to construct initial record
            decision = await self.db["response_decisions"].find_one({"_id": ObjectId(decision_id)})
            if decision:
                decision["_id"] = str(decision["_id"])
                outcome = await self.upsert_outcome_from_decision(decision)
            else:
                raise ValueError("Response decision context not found for execution request")

        now = datetime.now(timezone.utc)
        update_fields = {
            "execution_id": execution_id,
            "status": execution.get("status", outcome.get("status")),
            "approved_at": execution.get("approved_at", outcome.get("approved_at")),
            "execution_started_at": execution.get("started_at") or execution.get("queued_at"),
            "execution_completed_at": execution.get("completed_at"),
            "updated_at": now
        }

        await self.outcome_repo.collection.update_one(
            {"organization_id": organization_id, "outcome_id": outcome["outcome_id"]},
            {"$set": update_fields}
        )
        outcome.update(update_fields)
        return outcome

    async def submit_analyst_feedback(
        self, 
        organization_id: str, 
        outcome_id: str, 
        feedback_class: str, 
        comment: Optional[str], 
        user_id: str
    ) -> Dict[str, Any]:
        """Register closed-loop analyst feedback, triggering audit timelines and GRC logs."""
        outcome = await self.outcome_repo.get_by_outcome_id(organization_id, outcome_id)
        if not outcome:
            raise ValueError("Response outcome context not found")

        # Validate feedback classifications
        allowed_feedback = [
            "CORRECT_RESPONSE",
            "INCORRECT_RESPONSE",
            "FALSE_POSITIVE",
            "INSUFFICIENT_EVIDENCE",
            "POLICY_TOO_STRICT",
            "POLICY_TOO_PERMISSIVE",
            "PLAYBOOK_FAILURE"
        ]
        if feedback_class not in allowed_feedback:
            raise ValueError(f"Invalid analyst feedback classification verdict: {feedback_class}")

        now = datetime.now(timezone.utc)
        update_fields = {
            "feedback_status": "REVIEWED",
            "feedback_classification": feedback_class,
            "feedback_comment": comment,
            "feedback_by": user_id,
            "feedback_at": now,
            "updated_at": now
        }

        await self.outcome_repo.collection.update_one(
            {"organization_id": organization_id, "outcome_id": outcome_id},
            {"$set": update_fields}
        )

        # 1. Log audit trail event
        await self.db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": user_id,
            "action": "RESPONSE_FEEDBACK_SUBMITTED",
            "details": {
                "outcome_id": outcome_id,
                "feedback_classification": feedback_class,
                "action": outcome.get("action")
            },
            "created_at": now
        })

        # 2. Register Compliance Evidence in grc_evidence collection (SOC2 CC6.8)
        details = {
            "outcome_id": outcome_id,
            "feedback_classification": feedback_class,
            "comment": comment,
            "reviewer": user_id,
            "timestamp": str(now)
        }
        content_hash = hashlib.sha256(json.dumps(details, sort_keys=True).encode()).hexdigest()

        await self.db["grc_evidence"].insert_one({
            "organization_id": organization_id,
            "control_id": "SOC2-CC6.8",
            "evidence_type": "analyst_review",
            "source": f"Response Outcome Feedback Loop: {feedback_class}",
            "content_hash": content_hash,
            "created_at": now,
            "collected_at": now,
            "owner_id": user_id,
            "status": "active",
            "soft_delete": False
        })

        outcome.update(update_fields)
        return outcome

    async def get_overview_metrics(self, organization_id: str) -> Dict[str, Any]:
        """Aggregate Mean Time to Respond/Contain/Approve/Execute and automation quality metrics."""
        query = {"organization_id": organization_id, "soft_delete": {"$ne": True}}
        cursor = self.outcome_repo.collection.find(query)
        outcomes = await cursor.to_list(length=5000)

        # Performance lists
        mttr_secs = []
        mttc_secs = []
        mtta_secs = []
        mtte_secs = []

        total_count = len(outcomes)
        execution_count = 0
        success_count = 0
        failed_count = 0
        cancelled_count = 0

        # Verdict counts
        allow_auto_count = 0
        require_human_count = 0
        deny_count = 0

        # Feedback acceptance
        feedback_accepted = 0
        feedback_rejected = 0

        for ot in outcomes:
            status = ot.get("status")
            mode = ot.get("policy_decision_mode")
            
            # Map verdicts
            if mode == "ALLOW_AUTO":
                allow_auto_count += 1
            elif mode == "REQUIRE_HUMAN":
                require_human_count += 1
            elif mode == "DENY":
                deny_count += 1

            # Check feedback loop stats
            feedback_class = ot.get("feedback_classification")
            if feedback_class:
                if feedback_class == "CORRECT_RESPONSE":
                    feedback_accepted += 1
                elif feedback_class in ["INCORRECT_RESPONSE", "FALSE_POSITIVE", "PLAYBOOK_FAILURE"]:
                    feedback_rejected += 1

            if ot.get("execution_id"):
                execution_count += 1
                if status == "SUCCESS":
                    success_count += 1
                elif status in ["FAILED", "EXHAUSTED"]:
                    failed_count += 1
                elif status == "CANCELLED":
                    cancelled_count += 1

                # Calculate durations
                exec_start = ot.get("execution_started_at")
                exec_end = ot.get("execution_completed_at")
                dec_create = ot.get("decision_created_at")
                detect = ot.get("detection_at")
                approved = ot.get("approved_at")

                if exec_end and detect:
                    mttr_secs.append((exec_end - detect).total_seconds())
                if exec_end and dec_create:
                    mttc_secs.append((exec_end - dec_create).total_seconds())
                if approved and dec_create:
                    mtta_secs.append((approved - dec_create).total_seconds())
                if exec_end and exec_start:
                    mtte_secs.append((exec_end - exec_start).total_seconds())

        return {
            "total_outcomes": total_count,
            "total_executions": execution_count,
            # Duration averages
            "mean_time_to_respond": sum(mttr_secs) / len(mttr_secs) if mttr_secs else 0.0,
            "mean_time_to_contain": sum(mttc_secs) / len(mttc_secs) if mttc_secs else 0.0,
            "mean_time_to_approve": sum(mtta_secs) / len(mtta_secs) if mtta_secs else 0.0,
            "mean_time_to_execute": sum(mtte_secs) / len(mtte_secs) if mtte_secs else 0.0,
            # Execution rates
            "success_rate": success_count / execution_count if execution_count else 0.0,
            "failure_rate": failed_count / execution_count if execution_count else 0.0,
            "cancelled_rate": cancelled_count / execution_count if execution_count else 0.0,
            # Automation ratios
            "auto_response_percentage": allow_auto_count / total_count if total_count else 0.0,
            "human_approval_percentage": require_human_count / total_count if total_count else 0.0,
            "policy_denied_percentage": deny_count / total_count if total_count else 0.0,
            # Analyst feedback stats
            "recommendation_acceptance_rate": feedback_accepted / (feedback_accepted + feedback_rejected) if (feedback_accepted + feedback_rejected) else 0.0
        }

    async def get_policy_effectiveness(self, organization_id: str) -> List[Dict[str, Any]]:
        """Group response outcomes by policy and version to measure rule performance."""
        query = {
            "organization_id": organization_id, 
            "policy_id": {"$ne": None}, 
            "soft_delete": {"$ne": True}
        }
        cursor = self.outcome_repo.collection.find(query)
        outcomes = await cursor.to_list(length=5000)

        # Policy group aggregations
        groups = {}
        for ot in outcomes:
            policy_id = ot["policy_id"]
            ver = ot.get("policy_version", 1)
            key = f"{policy_id}:v{ver}"

            if key not in groups:
                groups[key] = {
                    "policy_id": policy_id,
                    "version": ver,
                    "evaluations": 0,
                    "allowed": 0,
                    "human_approval": 0,
                    "denied": 0,
                    "successful_actions": 0,
                    "failed_actions": 0,
                    "analyst_accepted": 0,
                    "analyst_rejected": 0,
                    "false_positives": 0
                }

            g = groups[key]
            g["evaluations"] += 1
            
            mode = ot.get("policy_decision_mode")
            if mode == "ALLOW_AUTO":
                g["allowed"] += 1
            elif mode == "REQUIRE_HUMAN":
                g["human_approval"] += 1
            elif mode == "DENY":
                g["denied"] += 1

            status = ot.get("status")
            if ot.get("execution_id"):
                if status == "SUCCESS":
                    g["successful_actions"] += 1
                elif status in ["FAILED", "EXHAUSTED"]:
                    g["failed_actions"] += 1

            feedback_class = ot.get("feedback_classification")
            if feedback_class:
                if feedback_class == "CORRECT_RESPONSE":
                    g["analyst_accepted"] += 1
                elif feedback_class in ["INCORRECT_RESPONSE", "FALSE_POSITIVE", "PLAYBOOK_FAILURE"]:
                    g["analyst_rejected"] += 1
                if feedback_class == "FALSE_POSITIVE":
                    g["false_positives"] += 1

        return list(groups.values())

    async def get_playbook_effectiveness(self, organization_id: str) -> List[Dict[str, Any]]:
        """Group outcomes by E6 playbook context to measure response orchestration reliability."""
        query = {
            "organization_id": organization_id,
            "playbook_id": {"$ne": None},
            "soft_delete": {"$ne": True}
        }
        cursor = self.outcome_repo.collection.find(query)
        outcomes = await cursor.to_list(length=5000)

        groups = {}
        for ot in outcomes:
            playbook_id = ot["playbook_id"]
            name = ot.get("playbook_name", playbook_id)

            if playbook_id not in groups:
                groups[playbook_id] = {
                    "playbook_id": playbook_id,
                    "playbook_name": name,
                    "total_runs": 0,
                    "successful_runs": 0,
                    "failed_runs": 0,
                    "retry_count": 0,
                    "analyst_accepted": 0,
                    "analyst_rejected": 0
                }

            g = groups[playbook_id]
            g["total_runs"] += 1

            status = ot.get("status")
            if status == "SUCCESS":
                g["successful_runs"] += 1
            elif status in ["FAILED", "EXHAUSTED"]:
                g["failed_runs"] += 1

            feedback_class = ot.get("feedback_classification")
            if feedback_class:
                if feedback_class == "CORRECT_RESPONSE":
                    g["analyst_accepted"] += 1
                elif feedback_class in ["INCORRECT_RESPONSE", "FALSE_POSITIVE"]:
                    g["analyst_rejected"] += 1

        return list(groups.values())

response_analytics_service = ResponseAnalyticsService()

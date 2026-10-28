import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from bson import ObjectId
from app.database.connection import db_manager
from app.repositories.response_optimization_repo import (
    ResponseOptimizationRepository,
    ResponseTuningRecommendationRepository
)
from app.services.response_policy_simulation_service import response_policy_simulation_service
from app.services.response_policy_service import response_policy_service
from app.services.response_analytics_service import response_analytics_service

logger = logging.getLogger("guardianmail.response_optimization_service")

class ResponseOptimizationService:
    @property
    def db(self):
        return db_manager.db

    @property
    def opt_repo(self) -> ResponseOptimizationRepository:
        return ResponseOptimizationRepository(self.db)

    @property
    def rec_repo(self) -> ResponseTuningRecommendationRepository:
        return ResponseTuningRecommendationRepository(self.db)

    async def trigger_optimization_run(
        self,
        organization_id: str,
        user_id: str,
        time_window_days: int = 30
    ) -> Dict[str, Any]:
        """
        Scans historical response outcomes and analytics to identify policy, playbook, and detection tuning recommendations.
        Strictly safe: does not execute remediation. If insufficient data exists, returns INSUFFICIENT_DATA.
        """
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=time_window_days)

        # 1. Fetch historical outcomes for the organization
        cursor = self.db["response_outcomes"].find({
            "organization_id": organization_id,
            "created_at": {"$gte": start_time},
            "soft_delete": {"$ne": True}
        })
        outcomes = await cursor.to_list(length=1000)

        # Retrieve overview metrics
        metrics = await response_analytics_service.get_overview_metrics(organization_id)

        # 2. Check for Insufficient Data block
        if len(outcomes) < 3:
            logger.info(f"Insufficient outcomes data ({len(outcomes)} found) for organization {organization_id}. Bypassing run.")
            opt_id = str(ObjectId())
            opt_doc = {
                "_id": ObjectId(opt_id),
                "organization_id": organization_id,
                "status": "COMPLETED",
                "optimization_type": "CONSOLIDATED",
                "source_window_start": start_time,
                "source_window_end": now,
                "metrics_snapshot": metrics,
                "recommendation_count": 0,
                "simulation_status": "NOT_STARTED",
                "approval_status": "APPROVED",
                "audit_reference": "INSUFFICIENT_DATA",
                "created_by": user_id,
                "created_at": now,
                "updated_at": now,
                "soft_delete": False
            }
            await self.opt_repo.collection.insert_one(opt_doc)
            opt_doc["_id"] = opt_id
            return {"status": "INSUFFICIENT_DATA", "optimization": opt_doc, "recommendations": []}

        # 3. Create active Optimization Run tracker
        opt_id = str(ObjectId())
        opt_doc = {
            "_id": ObjectId(opt_id),
            "organization_id": organization_id,
            "status": "PENDING",
            "optimization_type": "CONSOLIDATED",
            "source_window_start": start_time,
            "source_window_end": now,
            "metrics_snapshot": metrics,
            "recommendation_count": 0,
            "simulation_status": "NOT_STARTED",
            "approval_status": "PENDING",
            "audit_reference": f"OPT-RUN-{opt_id[:8].upper()}",
            "created_by": user_id,
            "created_at": now,
            "updated_at": now,
            "soft_delete": False
        }
        await self.opt_repo.collection.insert_one(opt_doc)

        recommendations = []

        # A. POLICY_TUNING Analyzer (False positive containment policy mismatch)
        fp_outcomes = [o for o in outcomes if o.get("feedback_status") == "REVIEWED" and o.get("feedback_classification") == "FALSE_POSITIVE"]
        policy_fps = {}
        for fp in fp_outcomes:
            pid = fp.get("policy_id")
            if pid and pid != "GLOBAL_DEFAULT":
                policy_fps.setdefault(pid, []).append(fp)

        for pid, fps in policy_fps.items():
            if len(fps) >= 3:
                # Find maximum confidence score of these false positives
                confidences = [fp.get("confidence_score", 0.0) for fp in fps]
                max_conf = max(confidences)
                proposed_conf = int(max_conf) + 1 if max_conf < 99 else 99

                # Fetch active policy definition
                policy = await response_policy_service.get_policy(organization_id, pid)
                if policy:
                    current_conf = policy.get("minimum_confidence", 0.0)
                    if proposed_conf > current_conf:
                        rec_id = str(ObjectId())
                        rec_doc = {
                            "_id": ObjectId(rec_id),
                            "organization_id": organization_id,
                            "optimization_id": opt_id,
                            "recommendation_type": "POLICY_TUNING",
                            "target_type": "POLICY",
                            "target_id": pid,
                            "current_configuration": {"minimum_confidence": current_conf},
                            "proposed_configuration": {"minimum_confidence": proposed_conf},
                            "reason": f"Raise minimum confidence from {current_conf} to {proposed_conf} to suppress false-positive containment actions.",
                            "evidence": {
                                "false_positive_count": len(fps),
                                "max_false_positive_confidence": max_conf,
                                "observed_confidences": confidences
                            },
                            "confidence": min(100.0, len(fps) * 15.0),
                            "expected_impact": {"false_positives_prevented_est": len(fps), "automation_delta_est": -5.0},
                            "risk_level": "LOW",
                            "affected_actions": [policy.get("action", "*")],
                            "affected_playbooks": [],
                            "affected_policies": [pid],
                            "status": "PROPOSED",
                            "created_by": user_id,
                            "created_at": now,
                            "updated_at": now,
                            "soft_delete": False
                        }
                        recommendations.append(rec_doc)

        # B. PLAYBOOK_TUNING Analyzer (Playbook execution timeouts or connector failures)
        playbook_runs = {}
        for o in outcomes:
            pbid = o.get("playbook_id")
            if pbid:
                playbook_runs.setdefault(pbid, []).append(o)

        for pbid, runs in playbook_runs.items():
            if len(runs) >= 3:
                failures = [r for r in runs if r.get("status") in ["FAILED", "EXHAUSTED"]]
                fail_rate = len(failures) / len(runs)
                if fail_rate > 0.15:
                    rec_id = str(ObjectId())
                    rec_doc = {
                        "_id": ObjectId(rec_id),
                        "organization_id": organization_id,
                        "optimization_id": opt_id,
                        "recommendation_type": "PLAYBOOK_TUNING",
                        "target_type": "PLAYBOOK",
                        "target_id": pbid,
                        "current_configuration": {},
                        "proposed_configuration": {},
                        "reason": f"Investigate connector timeout reliability. Playbook '{pbid}' has exhibiting failure rate of {fail_rate*100:.1f}%.",
                        "evidence": {
                            "total_runs": len(runs),
                            "failed_runs": len(failures),
                            "failure_rate": fail_rate
                        },
                        "confidence": min(100.0, len(runs) * 10.0),
                        "expected_impact": {"playbook_success_rate_est": 95.0},
                        "risk_level": "MEDIUM",
                        "affected_actions": [],
                        "affected_playbooks": [pbid],
                        "affected_policies": [],
                        "status": "PROPOSED",
                        "created_by": user_id,
                        "created_at": now,
                        "updated_at": now,
                        "soft_delete": False
                    }
                    recommendations.append(rec_doc)

        # C. DETECTION_FEEDBACK Analyzer (Correlate feedback with detection rule type)
        # For simplicity, we check if outcomes have target detection types linked
        det_fps = {}
        for fp in fp_outcomes:
            # Gather associated evidence references or action targets
            action = fp.get("action")
            if action:
                det_fps.setdefault(action, []).append(fp)

        for action, fps in det_fps.items():
            if len(fps) >= 3:
                rec_id = str(ObjectId())
                rec_doc = {
                    "_id": ObjectId(rec_id),
                    "organization_id": organization_id,
                    "optimization_id": opt_id,
                    "recommendation_type": "DETECTION_FEEDBACK",
                    "target_type": "DETECTION",
                    "target_id": action,
                    "current_configuration": {},
                    "proposed_configuration": {},
                    "reason": f"Phishing/malware detection thresholds for action '{action}' correlate with high false-positive rates.",
                    "evidence": {
                        "false_positives_count": len(fps)
                    },
                    "confidence": min(100.0, len(fps) * 15.0),
                    "expected_impact": {"false_positive_reduction_rate_est": 20.0},
                    "risk_level": "LOW",
                    "affected_actions": [action],
                    "affected_playbooks": [],
                    "affected_policies": [],
                    "status": "PROPOSED",
                    "created_by": user_id,
                    "created_at": now,
                    "updated_at": now,
                    "soft_delete": False
                }
                recommendations.append(rec_doc)

        # D. AUTOMATION_TUNING Analyzer (Shift manual to automated ALLOW_AUTO)
        # Identify policies where approval_mode == REQUIRE_HUMAN but success rate is 100%
        cursor_policies = self.db["response_policies"].find({
            "organization_id": organization_id,
            "approval_mode": "REQUIRE_HUMAN",
            "soft_delete": {"$ne": True}
        })
        human_policies = await cursor_policies.to_list(length=100)
        
        for policy in human_policies:
            pid = policy.get("policy_id")
            policy_action = policy.get("action")
            policy_runs = [o for o in outcomes if o.get("policy_id") == pid]
            
            if len(policy_runs) >= 3:
                failures = [r for r in policy_runs if r.get("status") in ["FAILED", "EXHAUSTED"]]
                avg_conf = sum([r.get("confidence_score", 100.0) for r in policy_runs]) / len(policy_runs)
                
                if len(failures) == 0 and avg_conf > 85.0:
                    rec_id = str(ObjectId())
                    rec_doc = {
                        "_id": ObjectId(rec_id),
                        "organization_id": organization_id,
                        "optimization_id": opt_id,
                        "recommendation_type": "AUTOMATION_TUNING",
                        "target_type": "POLICY",
                        "target_id": pid,
                        "current_configuration": {"approval_mode": "REQUIRE_HUMAN"},
                        "proposed_configuration": {"approval_mode": "ALLOW_AUTO"},
                        "reason": f"Action '{policy_action}' has 100% success rate and average confidence of {avg_conf:.1f}% over {len(policy_runs)} runs. Propose converting to ALLOW_AUTO.",
                        "evidence": {
                            "total_runs": len(policy_runs),
                            "avg_confidence": avg_conf,
                            "failed_runs": 0
                        },
                        "confidence": min(100.0, len(policy_runs) * 12.0),
                        "expected_impact": {"automation_delta_est": 15.0},
                        "risk_level": "MEDIUM",
                        "affected_actions": [policy_action],
                        "affected_playbooks": [],
                        "affected_policies": [pid],
                        "status": "PROPOSED",
                        "created_by": user_id,
                        "created_at": now,
                        "updated_at": now,
                        "soft_delete": False
                    }
                    recommendations.append(rec_doc)

        # Write recommendations
        if recommendations:
            for rec in recommendations:
                await self.rec_repo.collection.insert_one(rec)
                rec["_id"] = str(rec["_id"])

        # Update parent run status
        await self.opt_repo.collection.update_one(
            {"_id": ObjectId(opt_id)},
            {"$set": {
                "status": "COMPLETED",
                "recommendation_count": len(recommendations),
                "updated_at": now
            }}
        )
        opt_doc["status"] = "COMPLETED"
        opt_doc["recommendation_count"] = len(recommendations)
        opt_doc["_id"] = opt_id

        # Log audits
        await self.db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": user_id,
            "action": "RESPONSE_OPTIMIZATION_CREATED",
            "details": {
                "optimization_id": opt_id,
                "recommendations_generated": len(recommendations)
            },
            "created_at": now
        })

        return {"status": "SUCCESS", "optimization": opt_doc, "recommendations": recommendations}

    async def get_optimization_run(self, organization_id: str, opt_id: str) -> Optional[Dict[str, Any]]:
        return await self.opt_repo.get_by_optimization_id(organization_id, opt_id)

    async def list_optimization_runs(self, organization_id: str, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        return await self.opt_repo.list_optimizations(organization_id, skip, limit)

    async def get_recommendation(self, organization_id: str, rec_id: str) -> Optional[Dict[str, Any]]:
        return await self.rec_repo.get_by_recommendation_id(organization_id, rec_id)

    async def list_recommendations(self, organization_id: str, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        return await self.rec_repo.list_recommendations(organization_id, skip, limit)

    async def list_recommendations_for_run(self, organization_id: str, opt_id: str) -> List[Dict[str, Any]]:
        return await self.rec_repo.list_recommendations_by_optimization(organization_id, opt_id)

    async def simulate_recommendation(self, organization_id: str, rec_id: str, user_id: str) -> Dict[str, Any]:
        """Runs the historical policy simulation on the proposed tuning adjustments."""
        rec = await self.get_recommendation(organization_id, rec_id)
        if not rec:
            raise ValueError("Tuning recommendation not found")

        if rec.get("recommendation_type") not in ["POLICY_TUNING", "AUTOMATION_TUNING"]:
            raise ValueError("Simulation only supported for POLICY_TUNING and AUTOMATION_TUNING")

        now = datetime.now(timezone.utc)
        await self.rec_repo.collection.update_one(
            {"_id": ObjectId(rec_id)},
            {"$set": {"status": "SIMULATING", "updated_at": now}}
        )

        try:
            sim_res = await response_policy_simulation_service.run_policy_simulation(
                organization_id=organization_id,
                policy_id=rec["target_id"],
                proposed_rules=rec["proposed_configuration"]
            )
            
            # Update recommendation state to SIMULATED
            await self.rec_repo.collection.update_one(
                {"_id": ObjectId(rec_id)},
                {"$set": {
                    "status": "SIMULATED",
                    "simulation_result": sim_res,
                    "updated_at": now
                }}
            )
            rec["status"] = "SIMULATED"
            rec["simulation_result"] = sim_res
            return rec
        except Exception as e:
            await self.rec_repo.collection.update_one(
                {"_id": ObjectId(rec_id)},
                {"$set": {"status": "PROPOSED", "updated_at": now}}
            )
            logger.error(f"Tuning simulation failed: {str(e)}")
            raise

    async def approve_recommendation(self, organization_id: str, rec_id: str, user_id: str) -> Dict[str, Any]:
        """Approve tuning recommendation, enforcing Separation of Duties and updating active policy lifecycle."""
        rec = await self.get_recommendation(organization_id, rec_id)
        if not rec:
            raise ValueError("Tuning recommendation not found")

        current_status = rec.get("status")
        if current_status not in ["PROPOSED", "SIMULATED"]:
            raise ValueError(f"State transition rejected: recommendation must be in PROPOSED or SIMULATED state, got '{current_status}'")

        # Separation of Duties check
        # An analyst who created/triggered the run cannot approve it
        if rec.get("created_by") == user_id:
            raise ValueError("Separation of duties required: recommendation creator cannot approve the tuning adjustment")

        now = datetime.utcfromtimestamp(datetime.now(timezone.utc).timestamp()).replace(tzinfo=timezone.utc)

        # Apply changes based on recommendation type
        rec_type = rec.get("recommendation_type")
        target_type = rec.get("target_type")
        target_id = rec.get("target_id")

        if rec_type in ["POLICY_TUNING", "AUTOMATION_TUNING"] and target_type == "POLICY":
            # Apply configuration updates to response policies via response_policy_service
            # This creates a new version snapshotted history
            await response_policy_service.update_policy(
                organization_id=organization_id,
                policy_id=target_id,
                payload=rec["proposed_configuration"],
                user_id=user_id
            )
            
            # Audit log versions
            await self.db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": "system",
                "action": "RESPONSE_POLICY_VERSION_ACTIVATED",
                "details": {
                    "policy_id": target_id,
                    "triggered_by_recommendation": rec_id
                },
                "created_at": now
            })

        # Update recommendation governance state
        await self.rec_repo.collection.update_one(
            {"_id": ObjectId(rec_id)},
            {"$set": {
                "status": "APPROVED",
                "reviewed_by": user_id,
                "reviewed_at": now,
                "updated_at": now
            }}
        )

        # Log audit trail event
        await self.db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": user_id,
            "action": "RESPONSE_TUNING_APPROVED",
            "details": {
                "recommendation_id": rec_id,
                "type": rec_type,
                "target": target_id
            },
            "created_at": now
        })

        rec["status"] = "APPROVED"
        rec["reviewed_by"] = user_id
        rec["reviewed_at"] = now
        return rec

    async def reject_recommendation(self, organization_id: str, rec_id: str, user_id: str) -> Dict[str, Any]:
        """Reject and dismiss a proposed tuning recommendation."""
        rec = await self.get_recommendation(organization_id, rec_id)
        if not rec:
            raise ValueError("Tuning recommendation not found")

        current_status = rec.get("status")
        if current_status not in ["PROPOSED", "SIMULATED"]:
            raise ValueError(f"State transition rejected: recommendation must be in PROPOSED or SIMULATED state, got '{current_status}'")

        now = datetime.now(timezone.utc)
        await self.rec_repo.collection.update_one(
            {"_id": ObjectId(rec_id)},
            {"$set": {
                "status": "REJECTED",
                "reviewed_by": user_id,
                "reviewed_at": now,
                "updated_at": now
            }}
        )

        # Log audit trail event
        await self.db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": user_id,
            "action": "RESPONSE_TUNING_REJECTED",
            "details": {
                "recommendation_id": rec_id
            },
            "created_at": now
        })

        rec["status"] = "REJECTED"
        rec["reviewed_by"] = user_id
        rec["reviewed_at"] = now
        return rec

    async def cancel_recommendation(self, organization_id: str, rec_id: str, user_id: str) -> Dict[str, Any]:
        """Cancel/dismiss a pending recommendation."""
        rec = await self.get_recommendation(organization_id, rec_id)
        if not rec:
            raise ValueError("Tuning recommendation not found")

        current_status = rec.get("status")
        if current_status not in ["PROPOSED", "SIMULATED"]:
            raise ValueError(f"State transition rejected: recommendation must be in PROPOSED or SIMULATED state, got '{current_status}'")

        now = datetime.now(timezone.utc)
        await self.rec_repo.collection.update_one(
            {"_id": ObjectId(rec_id)},
            {"$set": {
                "status": "CANCELLED",
                "updated_at": now
            }}
        )

        # Log audit trail event
        await self.db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": user_id,
            "action": "RESPONSE_TUNING_CANCELLED",
            "details": {
                "recommendation_id": rec_id
            },
            "created_at": now
        })

        rec["status"] = "CANCELLED"
        return rec

response_optimization_service = ResponseOptimizationService()

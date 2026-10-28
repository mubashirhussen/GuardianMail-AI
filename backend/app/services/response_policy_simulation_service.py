import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from bson import ObjectId
from app.database.connection import db_manager
from app.services.response_policy_service import response_policy_service

logger = logging.getLogger("guardianmail.response_policy_simulation_service")

class ResponsePolicySimulationService:
    @property
    def db(self):
        return db_manager.db

    async def run_policy_simulation(
        self,
        organization_id: str,
        policy_id: str,
        proposed_rules: Dict[str, Any],
        time_window_days: int = 30
    ) -> Dict[str, Any]:
        """
        Runs a historical policy simulation. Compares current active policies against a proposed
        policy config over historical response decisions. Strictly read-only; does not call SOAR/Celery.
        """
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=time_window_days)

        # 1. Fetch historical response decisions in time window
        cursor = self.db["response_decisions"].find({
            "organization_id": organization_id,
            "created_at": {"$gte": start_time},
            "soft_delete": {"$ne": True}
        })
        decisions = await cursor.to_list(length=1000)

        # 2. Fetch all other current active policies for the organization
        current_policies = await response_policy_service.policy_repo.get_active_policies_by_org_and_action(organization_id, "*")
        # Fetch active policies for specific actions as well
        # We can just load all policies for the org
        cursor_all = self.db["response_policies"].find({
            "organization_id": organization_id,
            "soft_delete": {"$ne": True}
        })
        all_org_policies = await cursor_all.to_list(length=200)

        # 3. Build current vs proposed policy lists
        # Propose replacing target policy_id with proposed_rules
        proposed_policies = []
        target_found = False
        for p in all_org_policies:
            if p.get("policy_id") == policy_id:
                proposed_policy = {**p, **proposed_rules, "policy_id": policy_id, "organization_id": organization_id}
                proposed_policies.append(proposed_policy)
                target_found = True
            else:
                proposed_policies.append(p)
        
        if not target_found:
            # It's a new policy
            new_policy = {**proposed_rules, "policy_id": policy_id, "organization_id": organization_id, "enabled": True}
            proposed_policies.append(new_policy)

        # Sort lists by priority descending
        all_org_policies.sort(key=lambda x: x.get("priority", 1), reverse=True)
        proposed_policies.sort(key=lambda x: x.get("priority", 1), reverse=True)

        total_simulated = len(decisions)
        verdict_changes = {
            "ALLOW_AUTO_TO_REQUIRE_HUMAN": 0,
            "ALLOW_AUTO_TO_DENY": 0,
            "REQUIRE_HUMAN_TO_ALLOW_AUTO": 0,
            "REQUIRE_HUMAN_TO_DENY": 0,
            "DENY_TO_ALLOW_AUTO": 0,
            "DENY_TO_REQUIRE_HUMAN": 0,
            "NO_CHANGE": 0
        }
        affected_decision_ids = []
        current_auto_count = 0
        proposed_auto_count = 0

        # Fetch outcomes to identify false positive details
        cursor_outcomes = self.db["response_outcomes"].find({
            "organization_id": organization_id,
            "soft_delete": {"$ne": True}
        })
        outcomes = await cursor_outcomes.to_list(length=1000)
        outcomes_map = {o["decision_id"]: o for o in outcomes if "decision_id" in o}

        false_positives_prevented = 0

        for dec in decisions:
            dec_id = str(dec["_id"])
            action = dec.get("recommended_action", "NO_ACTION")
            
            # Retrieve or evaluate current verdict
            curr_verdict = dec.get("policy_decision") or dec.get("status")
            if curr_verdict not in ["ALLOW_AUTO", "REQUIRE_HUMAN", "DENY"]:
                # Evaluate against current policies
                curr_eval = await self._evaluate_with_policies(organization_id, dec, all_org_policies)
                curr_verdict = curr_eval["decision"]

            # Evaluate against proposed policies
            prop_eval = await self._evaluate_with_policies(organization_id, dec, proposed_policies)
            prop_verdict = prop_eval["decision"]

            if curr_verdict == "ALLOW_AUTO":
                current_auto_count += 1
            if prop_verdict == "ALLOW_AUTO":
                proposed_auto_count += 1

            if curr_verdict != prop_verdict:
                change_key = f"{curr_verdict}_TO_{prop_verdict}"
                if change_key in verdict_changes:
                    verdict_changes[change_key] += 1
                affected_decision_ids.append(dec_id)

                # If proposed is DENY and historical decision was false positive, we prevented a false positive!
                if prop_verdict == "DENY" and dec_id in outcomes_map:
                    outcome = outcomes_map[dec_id]
                    if outcome.get("feedback_status") == "REVIEWED" and outcome.get("feedback_classification") == "FALSE_POSITIVE":
                        false_positives_prevented += 1
            else:
                verdict_changes["NO_CHANGE"] += 1

        # Calculate estimated delta
        current_auto_rate = (current_auto_count / total_simulated * 100) if total_simulated > 0 else 0.0
        proposed_auto_rate = (proposed_auto_count / total_simulated * 100) if total_simulated > 0 else 0.0
        estimated_automation_delta = proposed_auto_rate - current_auto_rate

        simulation_id = str(ObjectId())
        simulation_doc = {
            "_id": ObjectId(simulation_id),
            "organization_id": organization_id,
            "policy_id": policy_id,
            "proposed_rules": proposed_rules,
            "time_window_days": time_window_days,
            "status": "COMPLETED",
            "total_simulated": total_simulated,
            "verdict_changes": verdict_changes,
            "estimated_automation_delta": estimated_automation_delta,
            "estimated_false_positive_reduction": false_positives_prevented,
            "affected_decision_ids": affected_decision_ids,
            "created_at": now,
            "soft_delete": False
        }

        # Save simulation result
        await self.db["response_policy_simulations"].insert_one(simulation_doc)

        # Log audit trail event
        await self.db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": "system",
            "action": "RESPONSE_TUNING_SIMULATION_COMPLETED",
            "details": {
                "simulation_id": simulation_id,
                "policy_id": policy_id,
                "total_simulated": total_simulated,
                "estimated_automation_delta": estimated_automation_delta
            },
            "created_at": now
        })

        simulation_doc["_id"] = simulation_id
        return simulation_doc

    async def _evaluate_with_policies(self, organization_id: str, decision: Dict[str, Any], policies_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Helper to match a decision against a specific policy list (isolated from global state)."""
        action = decision.get("recommended_action", "NO_ACTION")
        risk_score = decision.get("risk_score", 0.0)
        confidence = decision.get("confidence_score", 100.0)
        severity = decision.get("severity", "LOW")
        
        evidence_refs = decision.get("evidence_refs", [])
        evidence_types = {ref.get("source_type") for ref in evidence_refs if isinstance(ref, dict)}

        matched_policy = None
        for policy in policies_list:
            if not policy.get("enabled", True):
                continue

            policy_action = policy.get("action")
            if policy_action != "*" and policy_action != action:
                continue

            allowed_severity = policy.get("allowed_severity", [])
            if allowed_severity and severity not in allowed_severity:
                continue

            if confidence < policy.get("minimum_confidence", 0.0):
                continue

            required_evidence = policy.get("required_evidence", [])
            evidence_satisfied = True
            for req in required_evidence:
                if req not in evidence_types:
                    evidence_satisfied = False
                    break
            if not evidence_satisfied:
                continue

            matched_policy = policy
            break

        if matched_policy:
            verdict = matched_policy.get("approval_mode", "REQUIRE_HUMAN")
            return {
                "decision": verdict,
                "policy_id": matched_policy.get("policy_id")
            }

        # Fallback global defaults
        low_risk_actions = ["NO_ACTION", "MONITOR", "NOTIFY_ANALYST", "EXPORT_GRC_EVIDENCE"]
        global_verdict = "ALLOW_AUTO" if action in low_risk_actions else "REQUIRE_HUMAN"
        if risk_score >= 80 or confidence < 40:
            global_verdict = "REQUIRE_HUMAN"

        return {
            "decision": global_verdict,
            "policy_id": "GLOBAL_DEFAULT"
        }

response_policy_simulation_service = ResponsePolicySimulationService()

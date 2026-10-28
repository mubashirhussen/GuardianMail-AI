import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from bson import ObjectId

from app.database.connection import db_manager
from app.repositories.response_policy_repo import (
    ResponsePolicyRepository,
    ResponsePolicyVersionRepository,
    ResponsePolicySimulationRepository,
    ResponsePolicyAuditRepository
)

logger = logging.getLogger("guardianmail.response_policy_service")

class ResponsePolicyService:
    def __init__(self):
        pass

    @property
    def db(self):
        return db_manager.db

    @property
    def policy_repo(self) -> ResponsePolicyRepository:
        return ResponsePolicyRepository(self.db)

    @property
    def version_repo(self) -> ResponsePolicyVersionRepository:
        return ResponsePolicyVersionRepository(self.db)

    @property
    def simulation_repo(self) -> ResponsePolicySimulationRepository:
        return ResponsePolicySimulationRepository(self.db)

    @property
    def audit_repo(self) -> ResponsePolicyAuditRepository:
        return ResponsePolicyAuditRepository(self.db)

    async def get_emergency_disable_reason(self, organization_id: str, action: str, playbook_id: Optional[str] = None, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Check dynamic enable/disable settings (kill switches) at Global, Tenant, Action, Playbook, and User levels.
        Returns a dictionary explaining the block if disabled, otherwise None.
        """
        # 1. GLOBAL_DISABLE
        global_cfg = await self.db["sys_config"].find_one({"config_key": "soar_execution_enabled"})
        if global_cfg and global_cfg.get("config_value") is False:
            return {
                "decision": "DENY",
                "reason_code": "GLOBAL_DISABLE",
                "explanation": ["SOAR execution is globally disabled via configurations."]
            }

        # 2. TENANT_DISABLE
        tenant_cfg = await self.db["sys_config"].find_one({"config_key": f"soar_execution_enabled:{organization_id}"})
        if tenant_cfg and tenant_cfg.get("config_value") is False:
            return {
                "decision": "DENY",
                "reason_code": "TENANT_DISABLE",
                "explanation": ["SOAR execution is disabled for this organization via configuration rules."]
            }

        # 3. ACTION_DISABLE
        action_cfg = await self.db["sys_config"].find_one({"config_key": f"soar_execution_enabled:action:{action}"})
        if action_cfg and action_cfg.get("config_value") is False:
            return {
                "decision": "DENY",
                "reason_code": "ACTION_DISABLE",
                "explanation": [f"SOAR action '{action}' is disabled globally."]
            }

        tenant_action_cfg = await self.db["sys_config"].find_one({"config_key": f"soar_execution_enabled:{organization_id}:action:{action}"})
        if tenant_action_cfg and tenant_action_cfg.get("config_value") is False:
            return {
                "decision": "DENY",
                "reason_code": "ACTION_DISABLE",
                "explanation": [f"SOAR action '{action}' is disabled for this organization."]
            }

        # 4. PLAYBOOK_DISABLE
        if playbook_id:
            playbook_cfg = await self.db["sys_config"].find_one({"config_key": f"soar_execution_enabled:playbook:{playbook_id}"})
            if playbook_cfg and playbook_cfg.get("config_value") is False:
                return {
                    "decision": "DENY",
                    "reason_code": "PLAYBOOK_DISABLE",
                    "explanation": [f"SOAR playbook '{playbook_id}' is disabled globally."]
                }

            tenant_playbook_cfg = await self.db["sys_config"].find_one({"config_key": f"soar_execution_enabled:{organization_id}:playbook:{playbook_id}"})
            if tenant_playbook_cfg and tenant_playbook_cfg.get("config_value") is False:
                return {
                    "decision": "DENY",
                    "reason_code": "PLAYBOOK_DISABLE",
                    "explanation": [f"SOAR playbook '{playbook_id}' is disabled for this organization."]
                }

        # 5. USER_SCOPE_DISABLE
        if user_id:
            user_cfg = await self.db["sys_config"].find_one({"config_key": f"soar_execution_enabled:user:{user_id}"})
            if user_cfg and user_cfg.get("config_value") is False:
                return {
                    "decision": "DENY",
                    "reason_code": "USER_SCOPE_DISABLE",
                    "explanation": [f"SOAR execution privileges are disabled for user '{user_id}'."]
                }

        return None

    async def evaluate_decision(self, organization_id: str, decision: Dict[str, Any], user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Evaluate a response decision against tenant policies and emergency controls.
        Sitting between recommendation/approval and execution.
        """
        action = decision.get("recommended_action", "NO_ACTION")
        playbook_id = decision.get("recommended_playbook_id")
        
        # 1. Evaluate emergency controls (Kill switches)
        emergency_block = await self.get_emergency_disable_reason(
            organization_id=organization_id,
            action=action,
            playbook_id=playbook_id,
            user_id=user_id or decision.get("requested_by")
        )
        if emergency_block:
            # Audit block
            await self.audit_repo.collection.insert_one({
                "organization_id": organization_id,
                "actor_id": user_id or "system",
                "policy_id": "EMERGENCY_OVERRIDE",
                "action": "POLICY_EVALUATION_DENIED",
                "details": {
                    "decision_id": str(decision.get("_id", decision.get("decision_id"))),
                    "reason_code": emergency_block["reason_code"],
                    "action_type": action
                },
                "timestamp": datetime.now(timezone.utc)
            })
            emergency_block["explainability"] = {
                "kill_switches_checked": "FAILED",
                "reason": emergency_block["explanation"][0]
            }
            return emergency_block

        # Extract context variables for rules evaluation
        risk_score = decision.get("risk_score", 0.0)
        confidence = decision.get("confidence_score", 100.0)
        severity = decision.get("severity", "LOW")
        
        # Evidence sufficiency
        evidence_refs = decision.get("evidence_refs", [])
        evidence_types = {ref.get("source_type") for ref in evidence_refs if isinstance(ref, dict)}
        
        # Signal summaries
        signal_summary = decision.get("signal_summary", {})
        campaign_status = signal_summary.get("campaign_status", "inactive")
        threat_reputation = signal_summary.get("threat_reputation", "clean")
        ueba_risk = signal_summary.get("ueba_risk", 0.0)

        # 2. Fetch tenant policies matching this action
        policies = await self.policy_repo.get_active_policies_by_org_and_action(organization_id, action)
        policies.sort(key=lambda x: x.get("priority", 1), reverse=True)
        
        matched_policy = None
        reasons = []

        for policy in policies:
            if not policy.get("enabled", True):
                continue

            # Verify severity allowed list (e.g. ['HIGH', 'CRITICAL'])
            allowed_severity = policy.get("allowed_severity", [])
            if allowed_severity and severity not in allowed_severity:
                continue

            # Verify minimum confidence score
            if confidence < policy.get("minimum_confidence", 0.0):
                continue

            # Verify required evidence types
            required_evidence = policy.get("required_evidence", [])
            evidence_satisfied = True
            for req in required_evidence:
                if req not in evidence_types:
                    evidence_satisfied = False
                    break
            if not evidence_satisfied:
                continue

            # Highest priority active match wins
            matched_policy = policy
            break

        # 3. Construct explainability payload
        explainability = {
            "detection_severity": severity,
            "threat_reputation": threat_reputation,
            "ueba_risk": ueba_risk,
            "campaign_confidence": confidence,
            "evidence_sufficient": "YES" if len(evidence_types) > 0 else "NO"
        }

        if matched_policy:
            verdict = matched_policy.get("approval_mode", "REQUIRE_HUMAN")
            explainability["tenant_policy_applied"] = matched_policy.get("policy_id")
            
            # Log audit trail evaluation match
            await self.db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": "system",
                "action": "RESPONSE_POLICY_MATCHED",
                "details": {
                    "decision_id": str(decision.get("_id", decision.get("decision_id"))),
                    "policy_id": matched_policy["policy_id"],
                    "policy_version": matched_policy.get("version", 1),
                    "verdict": verdict
                },
                "created_at": datetime.now(timezone.utc)
            })

            reasons.append(f"Detection severity: {severity}")
            reasons.append(f"Threat reputation: {threat_reputation}")
            reasons.append(f"UEBA risk: {ueba_risk}")
            reasons.append(f"Campaign confidence: {confidence}")
            reasons.append(f"Evidence sufficient: {explainability['evidence_sufficient']}")
            reasons.append(f"Tenant policy: {verdict}")
            reasons.append(f"Action: {action}")

            return {
                "decision": verdict,
                "reason_code": "TENANT_POLICY_MATCH" if verdict != "DENY" else "TENANT_POLICY_BLOCK",
                "policy_id": matched_policy["policy_id"],
                "policy_version": matched_policy.get("version", 1),
                "action": action,
                "max_attempts": matched_policy.get("max_attempts", 3),
                "rate_limit": matched_policy.get("rate_limit", 10),
                "cooldown_seconds": matched_policy.get("cooldown_seconds", 60),
                "explanation": reasons,
                "explainability": explainability
            }

        # 4. Fall back to Global Default Policy checks
        low_risk_actions = ["NO_ACTION", "MONITOR", "NOTIFY_ANALYST", "EXPORT_GRC_EVIDENCE"]
        global_verdict = "ALLOW_AUTO" if action in low_risk_actions else "REQUIRE_HUMAN"
        
        # Override to REQUIRE_HUMAN on extreme risk
        if risk_score >= 80 or confidence < 40:
            global_verdict = "REQUIRE_HUMAN"

        explainability["tenant_policy_applied"] = "GLOBAL_DEFAULT"

        reasons.append(f"Detection severity: {severity}")
        reasons.append(f"Threat reputation: {threat_reputation}")
        reasons.append(f"UEBA risk: {ueba_risk}")
        reasons.append(f"Campaign confidence: {confidence}")
        reasons.append(f"Evidence sufficient: {explainability['evidence_sufficient']}")
        reasons.append(f"Tenant policy: GLOBAL_DEFAULT")
        reasons.append(f"Action: {action}")

        return {
            "decision": global_verdict,
            "reason_code": "GLOBAL_DEFAULT_FALLBACK",
            "action": action,
            "max_attempts": 3,
            "rate_limit": 10,
            "cooldown_seconds": 60,
            "explanation": reasons,
            "explainability": explainability
        }

    # CRUD + Versioning & Simulations Operations

    async def list_policies(self, organization_id: str) -> List[Dict[str, Any]]:
        return await self.policy_repo.get_active_policies_by_org(organization_id)

    async def get_policy(self, organization_id: str, policy_id: str) -> Optional[Dict[str, Any]]:
        return await self.policy_repo.get_by_policy_id(organization_id, policy_id)

    async def create_policy(self, organization_id: str, payload: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Create a new active response policy and record the audit log trail."""
        policy_id = payload.get("policy_id")
        if not policy_id:
            raise ValueError("policy_id attribute is required")

        existing = await self.get_policy(organization_id, policy_id)
        if existing:
            raise ValueError(f"Policy ID '{policy_id}' already exists for this organization.")

        now = datetime.now(timezone.utc)
        doc = {
            "organization_id": organization_id,
            "policy_id": policy_id,
            "name": payload.get("name", "Unnamed Policy"),
            "version": 1,
            "status": payload.get("status", "active"),
            "priority": payload.get("priority", 1),
            "action": payload.get("action", "*"),
            "minimum_confidence": payload.get("minimum_confidence", 0.0),
            "required_evidence": payload.get("required_evidence", []),
            "allowed_severity": payload.get("allowed_severity", []),
            "approval_mode": payload.get("approval_mode", "REQUIRE_HUMAN"),
            "max_attempts": payload.get("max_attempts", 3),
            "rate_limit": payload.get("rate_limit", 10),
            "cooldown_seconds": payload.get("cooldown_seconds", 60),
            "enabled": payload.get("enabled", True),
            "created_by": user_id,
            "updated_by": user_id,
            "created_at": now,
            "updated_at": now,
            "soft_delete": False
        }

        result = await self.policy_repo.collection.insert_one(doc)
        doc["_id"] = str(result.inserted_id)

        # Audit CREATE event
        await self.audit_repo.collection.insert_one({
            "organization_id": organization_id,
            "actor_id": user_id,
            "policy_id": policy_id,
            "action": "CREATE",
            "details": {"name": doc["name"], "action_type": doc["action"], "approval_mode": doc["approval_mode"]},
            "timestamp": now
        })

        return doc

    async def update_policy(self, organization_id: str, policy_id: str, payload: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Update an active response policy, incrementing version and snapshotted history."""
        policy = await self.get_policy(organization_id, policy_id)
        if not policy:
            raise ValueError("Policy not found")

        db = self.db
        now = datetime.now(timezone.utc)
        
        # 1. Save historical version snapshot
        await self.version_repo.collection.insert_one({
            "organization_id": organization_id,
            "policy_id": policy_id,
            "version": policy["version"],
            "name": policy["name"],
            "rules": {
                "action": policy["action"],
                "minimum_confidence": policy["minimum_confidence"],
                "required_evidence": policy["required_evidence"],
                "allowed_severity": policy["allowed_severity"],
                "approval_mode": policy["approval_mode"],
                "max_attempts": policy["max_attempts"],
                "rate_limit": policy["rate_limit"],
                "cooldown_seconds": policy["cooldown_seconds"]
            },
            "status": policy["status"],
            "created_by": policy["updated_by"],
            "created_at": policy["updated_at"]
        })

        # 2. Update active policy parameters
        next_ver = policy["version"] + 1
        update_fields = {
            "name": payload.get("name", policy["name"]),
            "version": next_ver,
            "status": payload.get("status", policy["status"]),
            "priority": payload.get("priority", policy["priority"]),
            "action": payload.get("action", policy["action"]),
            "minimum_confidence": payload.get("minimum_confidence", policy["minimum_confidence"]),
            "required_evidence": payload.get("required_evidence", policy["required_evidence"]),
            "allowed_severity": payload.get("allowed_severity", policy["allowed_severity"]),
            "approval_mode": payload.get("approval_mode", policy["approval_mode"]),
            "max_attempts": payload.get("max_attempts", policy["max_attempts"]),
            "rate_limit": payload.get("rate_limit", policy["rate_limit"]),
            "cooldown_seconds": payload.get("cooldown_seconds", policy["cooldown_seconds"]),
            "enabled": payload.get("enabled", policy.get("enabled", True)),
            "updated_by": user_id,
            "updated_at": now
        }

        await db["response_policies"].update_one(
            {"organization_id": organization_id, "policy_id": policy_id},
            {"$set": update_fields}
        )

        # Audit UPDATE event
        await self.audit_repo.collection.insert_one({
            "organization_id": organization_id,
            "actor_id": user_id,
            "policy_id": policy_id,
            "action": "UPDATE",
            "details": {"version_before": policy["version"], "version_after": next_ver},
            "timestamp": now
        })

        policy.update(update_fields)
        return policy

    async def delete_policy(self, organization_id: str, policy_id: str, user_id: str) -> bool:
        """Soft delete a response policy."""
        policy = await self.get_policy(organization_id, policy_id)
        if not policy:
            raise ValueError("Policy not found")

        db = self.db
        now = datetime.now(timezone.utc)
        await db["response_policies"].update_one(
            {"organization_id": organization_id, "policy_id": policy_id},
            {"$set": {"soft_delete": True, "updated_at": now}}
        )

        # Audit DELETE event
        await self.audit_repo.collection.insert_one({
            "organization_id": organization_id,
            "actor_id": user_id,
            "policy_id": policy_id,
            "action": "DELETE",
            "details": {"deleted_at": now},
            "timestamp": now
        })
        return True

    async def simulate_policy(self, organization_id: str, decision_payload: Dict[str, Any], policy_payload: Optional[Dict[str, Any]] = None, user_id: str = "system") -> Dict[str, Any]:
        """
        Simulate policy execution on a mock/actual decision context.
        If a temporary policy_payload is supplied, evaluate with that policy injected as highest priority override.
        """
        # Load active policies
        policies = await self.policy_repo.get_active_policies_by_org(organization_id)
        
        # Inject temporary proposed policy payload if provided
        if policy_payload:
            temp_policy = dict(policy_payload)
            temp_policy["organization_id"] = organization_id
            temp_policy["policy_id"] = temp_policy.get("policy_id", "SIM-PROPOSED-POL")
            temp_policy["version"] = 9999
            temp_policy["enabled"] = True
            temp_policy["priority"] = 99999  # Put at highest priority for simulation override
            policies.insert(0, temp_policy)

        # Apply priority sort safeguard
        policies.sort(key=lambda x: x.get("priority", 1), reverse=True)

        # Build mock decision from payload
        mock_decision = {
            "recommended_action": decision_payload.get("recommended_action", "NO_ACTION"),
            "severity": decision_payload.get("severity", "LOW"),
            "confidence_score": decision_payload.get("confidence_score", 100.0),
            "risk_score": decision_payload.get("risk_score", 0.0),
            "evidence_refs": decision_payload.get("evidence_refs", []),
            "signal_summary": decision_payload.get("signal_summary", {})
        }

        # Evaluate against the (potentially overridden) list of policies
        action = mock_decision["recommended_action"]
        severity = mock_decision["severity"]
        confidence = mock_decision["confidence_score"]
        evidence_types = {ref.get("source_type") for ref in mock_decision["evidence_refs"] if isinstance(ref, dict)}
        
        # Run matches
        matched_policy = None
        reasons = []
        for policy in policies:
            if not policy.get("enabled", True):
                continue
            if policy.get("action") not in [action, "*"]:
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

        explainability = {
            "detection_severity": severity,
            "threat_reputation": mock_decision["signal_summary"].get("threat_reputation", "clean"),
            "ueba_risk": mock_decision["signal_summary"].get("ueba_risk", 0.0),
            "campaign_confidence": confidence,
            "evidence_sufficient": "YES" if len(evidence_types) > 0 else "NO"
        }

        if matched_policy:
            verdict = matched_policy.get("approval_mode", "REQUIRE_HUMAN")
            explainability["tenant_policy_applied"] = matched_policy["policy_id"]
            
            reasons.append(f"Detection severity: {severity}")
            reasons.append(f"Threat reputation: {explainability['threat_reputation']}")
            reasons.append(f"UEBA risk: {explainability['ueba_risk']}")
            reasons.append(f"Campaign confidence: {confidence}")
            reasons.append(f"Evidence sufficient: {explainability['evidence_sufficient']}")
            reasons.append(f"Tenant policy: {verdict}")
            reasons.append(f"Action: {action}")

            res = {
                "decision": verdict,
                "reason_code": "TENANT_POLICY_MATCH" if verdict != "DENY" else "TENANT_POLICY_BLOCK",
                "policy_id": matched_policy["policy_id"],
                "policy_version": matched_policy.get("version", 1),
                "action": action,
                "explanation": reasons,
                "explainability": explainability
            }
        else:
            low_risk_actions = ["NO_ACTION", "MONITOR", "NOTIFY_ANALYST", "EXPORT_GRC_EVIDENCE"]
            global_verdict = "ALLOW_AUTO" if action in low_risk_actions else "REQUIRE_HUMAN"
            if mock_decision["risk_score"] >= 80 or confidence < 40:
                global_verdict = "REQUIRE_HUMAN"

            explainability["tenant_policy_applied"] = "GLOBAL_DEFAULT"
            reasons.append(f"Detection severity: {severity}")
            reasons.append(f"Threat reputation: {explainability['threat_reputation']}")
            reasons.append(f"UEBA risk: {explainability['ueba_risk']}")
            reasons.append(f"Campaign confidence: {confidence}")
            reasons.append(f"Evidence sufficient: {explainability['evidence_sufficient']}")
            reasons.append(f"Tenant policy: GLOBAL_DEFAULT")
            reasons.append(f"Action: {action}")

            res = {
                "decision": global_verdict,
                "reason_code": "GLOBAL_DEFAULT_FALLBACK",
                "action": action,
                "explanation": reasons,
                "explainability": explainability
            }

        # Save simulation result
        await self.simulation_repo.collection.insert_one({
            "organization_id": organization_id,
            "simulated_by": user_id,
            "policy_id": matched_policy["policy_id"] if matched_policy else None,
            "decision_id": decision_payload.get("decision_id", "simulated-id"),
            "decision": res["decision"],
            "reason_code": res["reason_code"],
            "explanation": res["explanation"],
            "explainability": res["explainability"],
            "simulated_at": datetime.now(timezone.utc)
        })

        return res

response_policy_service = ResponsePolicyService()

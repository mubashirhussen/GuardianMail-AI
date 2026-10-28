import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from bson import ObjectId

from app.database.connection import db_manager
from app.repositories.response_intelligence_repo import ResponseDecisionRepository
from app.services.response_risk_engine import ResponseRiskEngine
from app.services.response_playbook_service import playbook_resolver, evidence_evaluator

logger = logging.getLogger("guardianmail.response_intelligence")

class ResponseDecisionService:
    def __init__(self):
        # Initialized lazily via get_repo dependency or constructor
        self._repo: Optional[ResponseDecisionRepository] = None

    @property
    def repo(self) -> ResponseDecisionRepository:
        if self._repo is None:
            self._repo = ResponseDecisionRepository(db_manager.db)
        return self._repo

    async def create_response_decision(
        self,
        organization_id: str,
        recommended_action: str,
        incident_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        created_by: str = "system"
    ) -> Dict[str, Any]:
        """Consolidate telemetry signals, enforce idempotency checks, build evidence reference list and persist decision."""
        # 1. Enforce Idempotency check
        if incident_id:
            existing = await self.repo.find_duplicate_recommendation(organization_id, incident_id, recommended_action)
            if existing:
                logger.info(f"Duplicate recommendation detected for incident {incident_id} and action {recommended_action}. Returning existing.")
                return existing

        db = db_manager.db

        # 2. Gather context signals (E11.3 Detections / Findings)
        detection_signals = []
        if incident_id:
            cursor = db["detection_findings"].find({
                "organization_id": organization_id,
                "$or": [{"event_id": incident_id}, {"email_id": incident_id}],
                "soft_delete": False
            })
            detection_signals = await cursor.to_list(length=20)

        # Gather GRC context or Campaign (E11.6)
        campaign_signals = []
        if campaign_id:
            camp = await db["campaigns"].find_one({
                "_id": ObjectId(campaign_id) if isinstance(campaign_id, str) and ObjectId.is_valid(campaign_id) else campaign_id,
                "organization_id": organization_id,
                "soft_delete": False
            })
            if camp:
                campaign_signals.append(camp)

        # Gather UEBA signals (E9)
        ueba_signals = []
        if incident_id:
            email = await db["emails"].find_one({"_id": ObjectId(incident_id) if ObjectId.is_valid(incident_id) else incident_id})
            if email:
                user_id = email.get("user_id")
                if user_id:
                    cursor = db["ml_features"].find({
                        "organization_id": organization_id,
                        "entity_id": user_id,
                        "soft_delete": False
                    })
                    ueba_signals = await cursor.to_list(length=10)

        # 3. Build signal summary context
        signal_summary = {
            "detections_count": len(detection_signals),
            "campaigns_count": len(campaign_signals),
            "ueba_anomalies_count": len(ueba_signals),
            "retrieved_at": datetime.now(timezone.utc).isoformat()
        }

        # 4. Construct Evidence References list
        evidence_refs = []
        for det in detection_signals:
            evidence_refs.append({
                "source_type": "FINDING",
                "source_id": str(det.get("_id")),
                "organization_id": organization_id,
                "relevance": "HIGH"
            })
        for camp in campaign_signals:
            evidence_refs.append({
                "source_type": "CAMPAIGN",
                "source_id": str(camp.get("_id")),
                "organization_id": organization_id,
                "relevance": "CRITICAL"
            })
        for ueba in ueba_signals:
            evidence_refs.append({
                "source_type": "UEBA_SIGNAL",
                "source_id": str(ueba.get("_id")),
                "organization_id": organization_id,
                "relevance": "MEDIUM"
            })

        # 5. Dynamic score calculation via ResponseRiskEngine
        signals = {
            "detection": {
                "score": 75.0 if len(detection_signals) > 0 else 0.0,
                "confidence": 80.0 if len(detection_signals) > 0 else 0.0,
                "organization_id": organization_id
            },
            "threat_intel": {
                "score": 85.0 if len(ueba_signals) > 0 else 0.0,
                "confidence": 85.0 if len(ueba_signals) > 0 else 0.0,
                "organization_id": organization_id
            },
            "campaign": {
                "score": 90.0 if len(campaign_signals) > 0 else 0.0,
                "confidence": 90.0 if len(campaign_signals) > 0 else 0.0,
                "organization_id": organization_id
            },
            "ueba": {
                "score": 80.0 if len(ueba_signals) > 0 else 0.0,
                "confidence": 75.0 if len(ueba_signals) > 0 else 0.0,
                "organization_id": organization_id
            },
            "investigation": {
                "score": 50.0 if investigation_id else 0.0,
                "confidence": 60.0 if investigation_id else 0.0,
                "organization_id": organization_id
            }
        }

        calc = ResponseRiskEngine.calculate_decision(organization_id, signals)

        # Enforce approval requirement and status based on the selected recommended_action parameter
        low_risk_actions = ["NO_ACTION", "MONITOR", "NOTIFY_ANALYST", "EXPORT_GRC_EVIDENCE"]
        approval_required = recommended_action not in low_risk_actions
        status = "PENDING_APPROVAL" if approval_required else "RECOMMENDED"

        # 6. Create decision payload
        decision_doc = {
            "organization_id": organization_id,
            "incident_id": incident_id,
            "campaign_id": campaign_id,
            "investigation_id": investigation_id,
            "status": status,
            "recommended_action": recommended_action,
            "severity": calc["severity"],
            "approval_required": approval_required,
            "risk_score": calc["risk_score"],
            "confidence_score": calc["confidence_score"],
            "decision_reason": f"System formulated recommendation for action {recommended_action} based on {len(evidence_refs)} evidence indicators.",
            "evidence_refs": evidence_refs,
            "signal_summary": signal_summary,
            "decision_trace": calc["decision_trace"],
            "created_by": created_by,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "soft_delete": False
        }

        # 7. Persist
        res = await self.repo.create(decision_doc)
        res["_id"] = str(res["_id"])
        return res

    async def get_decision(self, organization_id: str, id_str: str) -> Optional[Dict[str, Any]]:
        return await self.repo.get_by_org_and_id(organization_id, id_str)

    async def list_decisions(self, organization_id: str) -> List[Dict[str, Any]]:
        return await self.repo.get_by_org(organization_id)

    async def update_decision_status(
        self,
        organization_id: str,
        id_str: str,
        new_status: str,
        user_id: str
    ) -> Dict[str, Any]:
        """Transition decision status and log standard compliance audits."""
        decision = await self.get_decision(organization_id, id_str)
        if not decision:
            raise ValueError("Decision context not found")

        current_status = decision.get("status")
        valid_statuses = ["DRAFT", "RECOMMENDED", "PENDING_APPROVAL", "APPROVED", "REJECTED", "EXPIRED"]
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid target status state '{new_status}'")

        # State transition rules validation
        if current_status == "PENDING_APPROVAL":
            if new_status not in ["APPROVED", "REJECTED"]:
                raise ValueError(f"Invalid state transition from PENDING_APPROVAL to {new_status}")
        elif current_status in ["APPROVED", "REJECTED", "EXPIRED"]:
            raise ValueError(f"Terminal state '{current_status}' cannot transition to '{new_status}'")
        elif current_status == "RECOMMENDED":
            if new_status not in ["APPROVED", "REJECTED", "EXPIRED"]:
                raise ValueError(f"Invalid state transition from RECOMMENDED to {new_status}")
        elif current_status == "DRAFT":
            if new_status not in ["RECOMMENDED", "PENDING_APPROVAL"]:
                raise ValueError(f"Invalid state transition from DRAFT to {new_status}")

        # Update document
        db = db_manager.db
        now = datetime.now(timezone.utc)
        await db["response_decisions"].update_one(
            {"_id": ObjectId(id_str)},
            {"$set": {"status": new_status, "updated_at": now}}
        )

        # Log audit trail event
        audit_action = "RESPONSE_APPROVED" if new_status == "APPROVED" else "RESPONSE_REJECTED"
        await db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": user_id,
            "action": audit_action,
            "details": {
                "decision_id": id_str,
                "recommended_action": decision.get("recommended_action"),
                "status_before": current_status,
                "status_after": new_status
            },
            "created_at": now
        })

        decision["status"] = new_status
        decision["updated_at"] = now
        
        # Track response outcomes (E11.8.8)
        from app.services.response_analytics_service import response_analytics_service
        await response_analytics_service.upsert_outcome_from_decision(decision)

        return decision

    async def evaluate_and_update_decision(self, organization_id: str, id_str: str) -> Dict[str, Any]:
        """Reload fresh signals, recalculate risk/confidence using ResponseRiskEngine, and save updates (E11.8.2)."""
        decision = await self.get_decision(organization_id, id_str)
        if not decision:
            raise ValueError("Decision context not found")

        # Refuse to recalculate terminal states
        if decision.get("status") in ["APPROVED", "REJECTED", "EXPIRED"]:
            raise ValueError(f"Recalculation blocked. Decision is in terminal state '{decision.get('status')}'")

        db = db_manager.db
        incident_id = decision.get("incident_id")
        campaign_id = decision.get("campaign_id")
        investigation_id = decision.get("investigation_id")

        # Reload detection findings
        detection_signals = []
        if incident_id:
            cursor = db["detection_findings"].find({
                "organization_id": organization_id,
                "$or": [{"event_id": incident_id}, {"email_id": incident_id}],
                "soft_delete": False
            })
            detection_signals = await cursor.to_list(length=20)

        # Reload campaign signals
        campaign_signals = []
        if campaign_id:
            camp = await db["campaigns"].find_one({
                "_id": ObjectId(campaign_id) if isinstance(campaign_id, str) and ObjectId.is_valid(campaign_id) else campaign_id,
                "organization_id": organization_id,
                "soft_delete": False
            })
            if camp:
                campaign_signals.append(camp)

        # Reload UEBA
        ueba_signals = []
        if incident_id:
            email = await db["emails"].find_one({"_id": ObjectId(incident_id) if ObjectId.is_valid(incident_id) else incident_id})
            if email:
                user_id = email.get("user_id")
                if user_id:
                    cursor = db["ml_features"].find({
                        "organization_id": organization_id,
                        "entity_id": user_id,
                        "soft_delete": False
                    })
                    ueba_signals = await cursor.to_list(length=10)

        # Build signals for calculation
        signals = {
            "detection": {
                "score": 75.0 if len(detection_signals) > 0 else 0.0,
                "confidence": 80.0 if len(detection_signals) > 0 else 0.0,
                "organization_id": organization_id
            },
            "threat_intel": {
                "score": 85.0 if len(ueba_signals) > 0 else 0.0,
                "confidence": 85.0 if len(ueba_signals) > 0 else 0.0,
                "organization_id": organization_id
            },
            "campaign": {
                "score": 90.0 if len(campaign_signals) > 0 else 0.0,
                "confidence": 90.0 if len(campaign_signals) > 0 else 0.0,
                "organization_id": organization_id
            },
            "ueba": {
                "score": 80.0 if len(ueba_signals) > 0 else 0.0,
                "confidence": 75.0 if len(ueba_signals) > 0 else 0.0,
                "organization_id": organization_id
            },
            "investigation": {
                "score": 50.0 if investigation_id else 0.0,
                "confidence": 60.0 if investigation_id else 0.0,
                "organization_id": organization_id
            }
        }

        # Build signal summary
        signal_summary = {
            "detections_count": len(detection_signals),
            "campaigns_count": len(campaign_signals),
            "ueba_anomalies_count": len(ueba_signals),
            "retrieved_at": datetime.now(timezone.utc).isoformat()
        }

        # Calculate using engine
        calc = ResponseRiskEngine.calculate_decision(organization_id, signals)

        # Build evidence references
        evidence_refs = []
        for det in detection_signals:
            evidence_refs.append({
                "source_type": "FINDING",
                "source_id": str(det.get("_id")),
                "organization_id": organization_id,
                "relevance": "HIGH"
            })
        for camp in campaign_signals:
            evidence_refs.append({
                "source_type": "CAMPAIGN",
                "source_id": str(camp.get("_id")),
                "organization_id": organization_id,
                "relevance": "CRITICAL"
            })
        for ueba in ueba_signals:
            evidence_refs.append({
                "source_type": "UEBA_SIGNAL",
                "source_id": str(ueba.get("_id")),
                "organization_id": organization_id,
                "relevance": "MEDIUM"
            })

        # Update document
        now = datetime.now(timezone.utc)
        update_doc = {
            "risk_score": calc["risk_score"],
            "confidence_score": calc["confidence_score"],
            "severity": calc["severity"],
            "recommended_action": calc["recommended_action"],
            "approval_required": calc["approval_required"],
            "decision_trace": calc["decision_trace"],
            "signal_summary": signal_summary,
            "evidence_refs": evidence_refs,
            "updated_at": now
        }

        # State transition corrections
        if decision.get("status") == "PENDING_APPROVAL" and not calc["approval_required"]:
            update_doc["status"] = "RECOMMENDED"
        elif decision.get("status") == "RECOMMENDED" and calc["approval_required"]:
            update_doc["status"] = "PENDING_APPROVAL"

        await db["response_decisions"].update_one(
            {"_id": ObjectId(id_str)},
            {"$set": update_doc}
        )

        # Log audit trail event
        await db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": "system",
            "action": "RESPONSE_SCORE_RECALCULATED",
            "details": {
                "decision_id": id_str,
                "risk_score": calc["risk_score"],
                "confidence_score": calc["confidence_score"],
                "recommended_action": calc["recommended_action"]
            },
            "created_at": now
        })

        decision.update(update_doc)
        decision["_id"] = str(decision["_id"])
        return decision

    async def generate_playbook_recommendation(self, organization_id: str, id_str: str) -> Dict[str, Any]:
        """Verify evidence sufficiency, resolve matching E6 playbook configurations, and stage recommendation (E11.8.3)."""
        decision = await self.get_decision(organization_id, id_str)
        if not decision:
            raise ValueError("Decision context not found")

        db = db_manager.db
        action = decision.get("recommended_action", "NO_ACTION")
        evidence_refs = decision.get("evidence_refs", [])
        safety_constraints = ["No execution performed by E11.8", "E6 remains execution owner"]

        # 1. Enforce Evidence Sufficiency check
        evaluation = evidence_evaluator.evaluate_evidence_sufficiency(action, evidence_refs)
        if not evaluation["sufficient"]:
            logger.warning(f"Insufficient evidence for action {action}. Missing types: {evaluation['missing_types']}. Downgrading action to NOTIFY_ANALYST.")
            action = "NOTIFY_ANALYST"
            safety_constraints.append(f"Evidence insufficient: missing required signals {evaluation['missing_types']}")
            
            # Log downgrade audit event
            await db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": "system",
                "action": "RESPONSE_RECOMMENDATION_DOWNGRADED",
                "details": {
                    "decision_id": id_str,
                    "original_action": decision.get("recommended_action"),
                    "downgraded_action": action,
                    "reason": "INSUFFICIENT_EVIDENCE"
                },
                "created_at": datetime.now(timezone.utc)
            })

        # 2. Confidence Gate check (confidence < 40 downgrades destructive actions)
        confidence = decision.get("confidence_score", 100)
        if confidence < 40 and action in ["ISOLATE_HOST", "RESET_CREDENTIAL", "REVOKE_SESSION"]:
            logger.warning(f"Confidence score {confidence} is below safety threshold (40). Downgrading action {action} to NOTIFY_ANALYST.")
            action = "NOTIFY_ANALYST"
            safety_constraints.append(f"Confidence score {confidence} below safety threshold (40)")

            # Log confidence downgrade audit event
            await db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": "system",
                "action": "RESPONSE_RECOMMENDATION_DOWNGRADED",
                "details": {
                    "decision_id": id_str,
                    "original_action": decision.get("recommended_action"),
                    "downgraded_action": action,
                    "reason": "LOW_CONFIDENCE"
                },
                "created_at": datetime.now(timezone.utc)
            })

        # 3. Resolve active playbook from E6 soar_playbooks collection
        playbook = await playbook_resolver.resolve_playbook(organization_id, action)
        if not playbook:
            logger.warning(f"No E6 playbook resolved for action {action}. Falling back to safe analyst notification.")
            
            # Log unavailable audit event
            await db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": "system",
                "action": "RESPONSE_PLAYBOOK_UNAVAILABLE",
                "details": {
                    "decision_id": id_str,
                    "action_type": action
                },
                "created_at": datetime.now(timezone.utc)
            })

            action = "NOTIFY_ANALYST"
            playbook = await playbook_resolver.resolve_playbook(organization_id, action)
            safety_constraints.append("E6 playbook unavailable for original action")

        playbook_id = playbook.get("playbook_id") if playbook else None
        playbook_name = playbook.get("playbook_name") if playbook else None

        # 4. Priority classification mapped directly from severity
        priority = decision.get("severity", "MEDIUM")

        # 5. Evaluate response policies (E11.8.7)
        from app.services.response_policy_service import response_policy_service
        eval_payload = {
            "recommended_action": action,
            "recommended_playbook_id": playbook_id,
            "severity": priority,
            "confidence_score": confidence,
            "risk_score": decision.get("risk_score", 0.0),
            "evidence_refs": evidence_refs,
            "signal_summary": decision.get("signal_summary", {})
        }
        policy_res = await response_policy_service.evaluate_decision(organization_id, eval_payload)
        
        verdict = policy_res["decision"]
        if verdict == "ALLOW_AUTO":
            approval_required = False
            status = "RECOMMENDED"
        elif verdict == "DENY":
            approval_required = True
            status = "REJECTED"
            safety_constraints.append(f"Blocked by policy engine: {policy_res.get('reason_code')} ({policy_res.get('policy_id') or 'DEFAULT'})")
        else:  # REQUIRE_HUMAN / REQUIRE_APPROVAL
            approval_required = True
            status = "PENDING_APPROVAL"

        # Update document
        now = datetime.now(timezone.utc)
        update_doc = {
            "recommended_action": action,
            "recommended_playbook_id": playbook_id,
            "recommended_playbook_name": playbook_name,
            "priority": priority,
            "required_evidence": evaluation["required_types"],
            "safety_constraints": safety_constraints,
            "status": status,
            "approval_required": approval_required,
            "policy_decision_mode": verdict,
            "policy_decision_reason": policy_res.get("reason_code"),
            "policy_decision_id": policy_res.get("policy_id"),
            "policy_decision_version": policy_res.get("policy_version"),
            "policy_decision_timestamp": now,
            "policy_decision_explainability": policy_res.get("explainability"),
            "updated_at": now
        }

        await db["response_decisions"].update_one(
            {"_id": ObjectId(id_str)},
            {"$set": update_doc}
        )

        # Log recommendation created audit event
        await db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": "system",
            "action": "RESPONSE_RECOMMENDATION_CREATED",
            "details": {
                "decision_id": id_str,
                "playbook_id": playbook_id,
                "recommended_action": action,
                "priority": priority
            },
            "created_at": now
        })

        decision.update(update_doc)
        decision["_id"] = str(decision["_id"])
        
        # Track response outcomes (E11.8.8)
        from app.services.response_analytics_service import response_analytics_service
        await response_analytics_service.upsert_outcome_from_decision(decision)

        return decision

response_decision_service = ResponseDecisionService()

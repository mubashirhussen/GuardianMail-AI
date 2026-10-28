import logging
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from bson import ObjectId

from app.database.connection import db_manager
from app.repositories.soar_execution_repo import SOARExecutionRepository
from app.services.response_approval_service import response_approval_service

logger = logging.getLogger("guardianmail.soar_execution_service")

class SOARExecutionService:
    @property
    def db(self):
        return db_manager.db

    @property
    def execution_repo(self):
        return SOARExecutionRepository(self.db)

    async def check_kill_switches(self, organization_id: str) -> None:
        """Verify dynamic global and tenant-scoped operational enable/disable configs."""
        from app.services.response_policy_service import response_policy_service
        emergency = await response_policy_service.get_emergency_disable_reason(organization_id, action="*", playbook_id=None, user_id=None)
        if emergency:
            await self.db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": "system",
                "action": "SOAR_EXECUTION_BLOCKED",
                "details": {"reason": emergency["reason_code"]},
                "created_at": datetime.now(timezone.utc)
            })
            raise ValueError(emergency["explanation"][0])

    async def check_rate_limits(self, organization_id: str) -> None:
        """Enforce tenant-scoped execution count limits (maximum 10 per minute)."""
        now = datetime.now(timezone.utc)
        one_minute_ago = now - timedelta(minutes=1)
        
        count = await self.db["soar_execution_requests"].count_documents({
            "organization_id": organization_id,
            "created_at": {"$gt": one_minute_ago},
            "soft_delete": {"$ne": True}
        })
        
        if count >= 10:
            await self.db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": "system",
                "action": "SOAR_EXECUTION_RATE_LIMITED",
                "details": {
                    "count_last_minute": count,
                    "limit": 10
                },
                "created_at": now
            })
            raise ValueError("Tenant execution rate limit exceeded (maximum 10 per minute).")

    async def create_execution_request(
        self,
        organization_id: str,
        decision_id: str,
        token_id: str,
        token_secret: str,
        user_id: str
    ) -> Dict[str, Any]:
        """Validate approval tokens, rate limits, kill switches, and atomically queue SOAR execution."""
        # 1. Kill switches check
        await self.check_kill_switches(organization_id)

        # 2. Rate limiting check
        await self.check_rate_limits(organization_id)

        # 3. Retrieve response decision
        decision = await response_approval_service.get_decision(organization_id, decision_id)
        if not decision:
            raise ValueError("Response decision not found")

        # 3b. Evaluate Emergency policy controls (E11.8.7)
        from app.services.response_policy_service import response_policy_service
        emergency_block = await response_policy_service.get_emergency_disable_reason(
            organization_id=organization_id,
            action=decision.get("recommended_action"),
            playbook_id=decision.get("recommended_playbook_id"),
            user_id=user_id
        )
        if emergency_block:
            await self.db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": user_id,
                "action": "SOAR_EXECUTION_BLOCKED",
                "details": {
                    "reason": emergency_block["reason_code"],
                    "explanation": emergency_block["explanation"][0]
                },
                "created_at": datetime.now(timezone.utc)
            })
            raise ValueError(f"SOAR execution blocked by policy override: {emergency_block['explanation'][0]}")

        # 4. Idempotency Check (Check before token validation to bypass consumption replay check)
        playbook_id = decision.get("recommended_playbook_id") or "PLAYBOOK-FALLBACK"
        action = decision.get("recommended_action")
        
        raw_key = f"{organization_id}:{decision_id}:{token_id}:{playbook_id}:{action}"
        idempotency_key = hashlib.sha256(raw_key.encode()).hexdigest()

        existing = await self.execution_repo.get_by_idempotency_key(organization_id, idempotency_key)
        if existing:
            await self.db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": user_id,
                "action": "SOAR_EXECUTION_DUPLICATE",
                "details": {
                    "decision_id": decision_id,
                    "idempotency_key": idempotency_key,
                    "existing_execution_id": existing["execution_id"]
                },
                "created_at": datetime.now(timezone.utc)
            })
            return existing

        # 5. Token validation check
        validation = await response_approval_service.validate_token(
            organization_id=organization_id,
            decision_id=decision_id,
            recommendation_version=decision.get("recommendation_version", 1),
            recommended_action=action,
            playbook_id=decision.get("recommended_playbook_id"),
            token_id=token_id,
            token_secret=token_secret
        )

        if not validation["valid"]:
            await self.db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": user_id,
                "action": "SOAR_EXECUTION_REJECTED",
                "details": {
                    "decision_id": decision_id,
                    "reason": validation["reason"]
                },
                "created_at": datetime.now(timezone.utc)
            })
            raise ValueError(f"Authorization validation failed: {validation['reason']}")

        # 6. Connector Safety Check (Reject if no active connectors for organization)
        active_connectors = await self.db["integrations"].count_documents({
            "organization_id": organization_id,
            "status": "ACTIVE",
            "soft_delete": {"$ne": True}
        })
        if active_connectors == 0:
            await self.db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": user_id,
                "action": "SOAR_EXECUTION_BLOCKED",
                "details": {
                    "decision_id": decision_id,
                    "reason": "MISSING_CONNECTOR"
                },
                "created_at": datetime.now(timezone.utc)
            })
            raise ValueError("Missing connector configuration reference for tenant: no active integrations configured.")

        # 7. Atomic Token Consumption
        await response_approval_service.consume_token(
            organization_id=organization_id,
            decision_id=decision_id,
            recommendation_version=decision.get("recommendation_version", 1),
            recommended_action=action,
            playbook_id=decision.get("recommended_playbook_id"),
            token_id=token_id,
            token_secret=token_secret
        )

        # 8. Create Execution request document
        now = datetime.now(timezone.utc)
        exec_uuid = str(uuid.uuid4())
        
        exec_doc = {
            "organization_id": organization_id,
            "execution_id": exec_uuid,
            "response_decision_id": decision_id,
            "incident_id": decision.get("incident_id"),
            "approval_request_id": token_id,
            "authorization_reference": token_id,
            "playbook_id": playbook_id,
            "recommended_action": action,
            "requested_by": decision.get("requested_by"),
            "approved_by": decision.get("approved_by"),
            "evidence_reference": [ref.get("source_id") for ref in decision.get("evidence_refs", []) if isinstance(ref, dict)] or [decision_id],
            "risk_score": decision.get("risk_score", 0.0),
            "confidence_score": decision.get("confidence_score", 0.0),
            "priority": decision.get("priority", "MEDIUM"),
            "status": "QUEUED",
            "idempotency_key": idempotency_key,
            "created_at": now,
            "updated_at": now,
            "approved_at": decision.get("approved_at"),
            "queued_at": now,
            "soft_delete": False
        }

        result = await self.db["soar_execution_requests"].insert_one(exec_doc)
        exec_doc["_id"] = str(result.inserted_id)

        # 9. Audit event trail logging
        await self.db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": user_id,
            "action": "SOAR_EXECUTION_REQUESTED",
            "details": {"execution_id": exec_uuid, "decision_id": decision_id},
            "created_at": now
        })
        await self.db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": "system",
            "action": "SOAR_EXECUTION_QUEUED",
            "details": {"execution_id": exec_uuid, "celery_name": "tasks.soar_execution_task"},
            "created_at": now
        })

        # 10. Queue asynchronous Celery task worker
        from app.workers.tasks import soar_execution_task
        soar_execution_task.delay(exec_uuid)

        # Track response outcomes (E11.8.8)
        from app.services.response_analytics_service import response_analytics_service
        await response_analytics_service.upsert_outcome_from_execution(exec_doc)

        return exec_doc

    async def get_execution(self, organization_id: str, execution_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve scoped execution record."""
        return await self.db["soar_execution_requests"].find_one({
            "execution_id": execution_id,
            "organization_id": organization_id,
            "soft_delete": {"$ne": True}
        })

    async def transition_status(
        self,
        organization_id: str,
        execution_id: str,
        to_status: str,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
        duration_ms: Optional[int] = None,
        connector_reference: Optional[str] = None,
        result_reference: Optional[str] = None,
        is_retryable: bool = False,
        user_id: str = "system",
        retry_reason: Optional[str] = None,
        next_retry_at: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Atomically transition execution status checking valid state machine routes."""
        db = self.db
        exec_doc = await db["soar_execution_requests"].find_one({
            "execution_id": execution_id,
            "organization_id": organization_id,
            "soft_delete": {"$ne": True}
        })
        if not exec_doc:
            raise ValueError("Execution request not found")

        from_status = exec_doc.get("status", "QUEUED")
        
        # Valid state transitions
        valid_transitions = {
            "QUEUED": ["VALIDATING", "CANCELLED", "FAILED"],
            "VALIDATING": ["RUNNING", "FAILED", "CANCELLED"],
            "RUNNING": ["SUCCESS", "PARTIAL_SUCCESS", "FAILED"],
            "FAILED": ["RETRYING", "EXHAUSTED"],
            "RETRYING": ["VALIDATING", "RUNNING", "EXHAUSTED", "FAILED"],
            "SUCCESS": [],
            "PARTIAL_SUCCESS": [],
            "EXHAUSTED": [],
            "CANCELLED": []
        }

        # Check if transition is valid
        allowed = valid_transitions.get(from_status, [])
        if to_status not in allowed:
            # Audit status rejection
            now = datetime.now(timezone.utc)
            await db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": user_id,
                "action": "EXECUTION_STATUS_CHANGE_REJECTED",
                "details": {
                    "execution_id": execution_id,
                    "from_status": from_status,
                    "to_status": to_status
                },
                "created_at": now
            })
            raise ValueError(f"State transition from {from_status} to {to_status} is invalid.")

        now = datetime.now(timezone.utc)
        update_fields = {
            "status": to_status,
            "updated_at": now
        }

        # Lifecycle timestamps mapping
        if to_status == "VALIDATING":
            pass
        elif to_status == "RUNNING":
            update_fields["started_at"] = now
        elif to_status in ["SUCCESS", "PARTIAL_SUCCESS", "FAILED", "EXHAUSTED", "CANCELLED"]:
            update_fields["completed_at"] = now

        if duration_ms is not None:
            update_fields["duration_ms"] = duration_ms
        if connector_reference is not None:
            update_fields["connector_reference"] = connector_reference
        if result_reference is not None:
            update_fields["result_reference"] = result_reference
        if error_code is not None:
            update_fields["error_code"] = error_code
        if error_message is not None:
            update_fields["error_message"] = error_message
            update_fields["failure_reason"] = error_message
            update_fields["last_error"] = error_message
        
        update_fields["retryable"] = is_retryable
        if retry_reason is not None:
            update_fields["retry_reason"] = retry_reason
        if next_retry_at is not None:
            update_fields["next_retry_at"] = next_retry_at

        # Atomic Compare-and-Swap status transition
        result = await db["soar_execution_requests"].update_one(
            {"execution_id": execution_id, "organization_id": organization_id, "status": from_status},
            {"$set": update_fields}
        )
        if result.modified_count == 0:
            raise ValueError("Concurrent status modification detected, transition failed.")

        # Log audits
        audit_action_map = {
            "QUEUED": "EXECUTION_QUEUED",
            "VALIDATING": "EXECUTION_VALIDATION_STARTED",
            "RUNNING": "EXECUTION_STARTED",
            "SUCCESS": "EXECUTION_SUCCEEDED",
            "PARTIAL_SUCCESS": "EXECUTION_PARTIAL_SUCCESS",
            "FAILED": "EXECUTION_FAILED",
            "RETRYING": "EXECUTION_RETRY_SCHEDULED",
            "EXHAUSTED": "EXECUTION_EXHAUSTED",
            "CANCELLED": "EXECUTION_CANCELLED"
        }
        
        audit_action = audit_action_map.get(to_status, "EXECUTION_STATUS_CHANGED")
        await db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": user_id,
            "action": audit_action,
            "details": {
                "execution_id": execution_id,
                "from_status": from_status,
                "to_status": to_status,
                "error_code": error_code
            },
            "created_at": now
        })

        # Back-propagate final status to ResponseDecision & Incident
        if to_status in ["SUCCESS", "PARTIAL_SUCCESS", "EXHAUSTED", "FAILED", "CANCELLED"]:
            decision_id = exec_doc.get("response_decision_id")
            # Update response decisions
            try:
                from bson import ObjectId
                await db["response_decisions"].update_one(
                    {"_id": ObjectId(decision_id)},
                    {"$set": {
                        "execution_id": execution_id,
                        "execution_status": to_status,
                        "executed_at": now,
                        "execution_result_reference": result_reference or error_message or "Execution Terminal State"
                    }}
                )
            except Exception:
                pass

            incident_id = exec_doc.get("incident_id")
            if incident_id:
                execution_link = {
                    "execution_id": execution_id,
                    "status": to_status,
                    "timestamp": now
                }
                try:
                    await db["incidents"].update_one(
                        {"_id": ObjectId(incident_id)},
                        {"$push": {"soar_executions": execution_link}}
                    )
                except Exception:
                    try:
                        await db["incidents"].update_one(
                            {"_id": incident_id},
                            {"$push": {"soar_executions": execution_link}}
                        )
                    except Exception:
                        pass

        # Return updated document
        updated_doc = {**exec_doc, **update_fields}
        updated_doc["_id"] = str(updated_doc["_id"])

        # Track response outcomes (E11.8.8)
        from app.services.response_analytics_service import response_analytics_service
        await response_analytics_service.upsert_outcome_from_execution(updated_doc)

        return updated_doc

    async def cancel_execution(self, organization_id: str, execution_id: str, user_id: str) -> Dict[str, Any]:
        """Cancel execution request before it runs."""
        db = self.db
        exec_doc = await db["soar_execution_requests"].find_one({
            "execution_id": execution_id,
            "organization_id": organization_id,
            "soft_delete": {"$ne": True}
        })
        if not exec_doc:
            raise ValueError("Execution request not found")

        current_status = exec_doc.get("status")
        if current_status not in ["PENDING", "QUEUED", "VALIDATING"]:
            raise ValueError(f"Execution request is in state {current_status} and cannot be cancelled.")

        return await self.transition_status(
            organization_id=organization_id,
            execution_id=execution_id,
            to_status="CANCELLED",
            error_message="User requested cancellation",
            error_code="CANCELLED",
            user_id=user_id
        )

    async def retry_execution(self, organization_id: str, execution_id: str, user_id: str) -> Dict[str, Any]:
        """Manually trigger retry of a failed or exhausted execution request."""
        db = self.db
        
        # 1. Kill switches check
        await self.check_kill_switches(organization_id)

        # 2. Rate limiting check
        await self.check_rate_limits(organization_id)

        exec_doc = await db["soar_execution_requests"].find_one({
            "execution_id": execution_id,
            "organization_id": organization_id,
            "soft_delete": {"$ne": True}
        })
        if not exec_doc:
            raise ValueError("Execution request not found")

        current_status = exec_doc.get("status")
        if current_status not in ["FAILED", "EXHAUSTED"]:
            raise ValueError(f"Manual retry is only allowed for FAILED or EXHAUSTED executions, got '{current_status}'")

        # Increment attempt count, reset state to QUEUED
        now = datetime.now(timezone.utc)
        result = await db["soar_execution_requests"].update_one(
            {"execution_id": execution_id, "organization_id": organization_id, "status": current_status},
            {"$set": {
                "status": "QUEUED",
                "attempt_count": 0, # Reset attempt count for next retry cycle
                "retry_reason": "MANUAL_RETRY",
                "updated_at": now
            }}
        )
        if result.modified_count == 0:
            raise ValueError("Concurrent state change occurred, retry failed")

        # Log audits
        await db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": user_id,
            "action": "SOAR_EXECUTION_REQUESTED",
            "details": {"execution_id": execution_id, "retry": "manual"},
            "created_at": now
        })
        await db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": "system",
            "action": "SOAR_EXECUTION_QUEUED",
            "details": {"execution_id": execution_id, "celery_name": "tasks.soar_execution_task"},
            "created_at": now
        })

        # Queue Celery task
        from app.workers.tasks import soar_execution_task
        soar_execution_task.delay(execution_id)

        exec_doc["status"] = "QUEUED"
        exec_doc["attempt_count"] = 0
        exec_doc["_id"] = str(exec_doc["_id"])
        return exec_doc

    async def get_timeline(self, organization_id: str, execution_id: str) -> List[Dict[str, Any]]:
        """Construct evidence-grounded chronological execution timeline from audit trails, decisions, and GRC evidence."""
        db = self.db
        exec_doc = await db["soar_execution_requests"].find_one({
            "execution_id": execution_id,
            "organization_id": organization_id,
            "soft_delete": {"$ne": True}
        })
        if not exec_doc:
            raise ValueError("Execution request not found")

        decision_id = exec_doc.get("response_decision_id")
        decision = await db["response_decisions"].find_one({
            "_id": ObjectId(decision_id),
            "organization_id": organization_id,
            "soft_delete": {"$ne": True}
        })

        timeline = []

        # 1. Finding / Detection Event
        if decision:
            finding_id = decision.get("incident_id") or "Finding Created"
            timeline.append({
                "stage": "DETECTION",
                "timestamp": decision.get("created_at") or exec_doc.get("created_at"),
                "title": "Threat Detection Signal Grounded",
                "details": f"Detection finding referenced as indicator: {finding_id}",
                "reference_id": finding_id,
                "reference_type": "finding"
            })

            # 2. Risk Evaluation Event
            timeline.append({
                "stage": "RISK_EVALUATION",
                "timestamp": decision.get("created_at") or exec_doc.get("created_at"),
                "title": "Risk & Confidence Scored",
                "details": f"Computed Risk Score: {decision.get('risk_score', 0.0)}, Confidence: {decision.get('confidence_score', 0.0)}",
                "reference_id": decision_id,
                "reference_type": "decision"
            })

            # 3. Playbook Recommendation Event
            if decision.get("recommended_playbook_id"):
                timeline.append({
                    "stage": "PLAYBOOK_RECOMMENDATION",
                    "timestamp": decision.get("updated_at") or exec_doc.get("created_at"),
                    "title": "E6 Playbook Recommendation Classified",
                    "details": f"Recommended playbook '{decision.get('recommended_playbook_name')}' ({decision.get('recommended_playbook_id')})",
                    "reference_id": decision.get("recommended_playbook_id"),
                    "reference_type": "playbook"
                })

        # 4. Pull audit logs related to approval, authorization, and execution
        cursor = db["audit_logs"].find({
            "organization_id": organization_id
        }).sort("created_at", 1)
        all_audit_logs = await cursor.to_list(length=1000)

        audit_logs = []
        for audit in all_audit_logs:
            details = audit.get("details")
            if isinstance(details, dict) and (details.get("execution_id") == execution_id or details.get("decision_id") == decision_id):
                audit_logs.append(audit)

        for audit in audit_logs:
            action = audit.get("action")
            timestamp = audit.get("created_at")
            details = audit.get("details", {})
            user_id = audit.get("user_id")

            if action == "RESPONSE_APPROVAL_REQUESTED":
                timeline.append({
                    "stage": "APPROVAL_REQUESTED",
                    "timestamp": timestamp,
                    "title": "Human Approval Requested",
                    "details": f"Analyst review requested by {user_id}",
                    "reference_id": decision_id,
                    "reference_type": "decision"
                })
            elif action == "RESPONSE_APPROVED":
                timeline.append({
                    "stage": "APPROVED",
                    "timestamp": timestamp,
                    "title": "Human Approval Granted",
                    "details": f"Four-Eyes approval authorized by analyst: {user_id}",
                    "reference_id": decision_id,
                    "reference_type": "decision"
                })
            elif action == "RESPONSE_AUTHORIZATION_ISSUED":
                timeline.append({
                    "stage": "AUTHORIZATION_ISSUED",
                    "timestamp": timestamp,
                    "title": "Authorization Token Minted",
                    "details": f"Secure authorization token UUID: {details.get('authorization_id') or details.get('token_id')}",
                    "reference_id": details.get("authorization_id") or details.get("token_id"),
                    "reference_type": "token"
                })
            elif action == "SOAR_EXECUTION_QUEUED" or action == "EXECUTION_QUEUED":
                timeline.append({
                    "stage": "EXECUTION_QUEUED",
                    "timestamp": timestamp,
                    "title": "Execution Request Queued",
                    "details": "Integration safety validations initialized. Background Celery task dispatched.",
                    "reference_id": execution_id,
                    "reference_type": "execution"
                })
            elif action == "EXECUTION_VALIDATION_STARTED":
                timeline.append({
                    "stage": "EXECUTION_VALIDATING",
                    "timestamp": timestamp,
                    "title": "Execution Validating",
                    "details": "Safety validations successfully processed (Kill switches, rate-limits, active connectors validated).",
                    "reference_id": execution_id,
                    "reference_type": "execution"
                })
            elif action == "EXECUTION_STARTED" or action == "SOAR_EXECUTION_STARTED":
                timeline.append({
                    "stage": "EXECUTION_RUNNING",
                    "timestamp": timestamp,
                    "title": "E6 Playbook Execution Started",
                    "details": "Dispatching simulated containment payload to active connector endpoint.",
                    "reference_id": execution_id,
                    "reference_type": "execution"
                })
            elif action in ["EXECUTION_SUCCEEDED", "EXECUTION_FAILED", "EXECUTION_EXHAUSTED", "EXECUTION_CANCELLED", "EXECUTION_PARTIAL_SUCCESS"]:
                timeline.append({
                    "stage": "EXECUTION_RESULT",
                    "timestamp": timestamp,
                    "title": f"SOAR Execution Status: {action.replace('EXECUTION_', '')}",
                    "details": f"Status updated to {action.replace('EXECUTION_', '')}.",
                    "reference_id": execution_id,
                    "reference_type": "execution"
                })

        # 5. GRC Compliance Evidence event
        cursor_grc = db["grc_evidence"].find({
            "organization_id": organization_id
        }).sort("assessed_at", 1)
        all_grc = await cursor_grc.to_list(length=100)
        grc_evidence = []
        for grc in all_grc:
            details = grc.get("details")
            if isinstance(details, dict) and details.get("execution_id") == execution_id:
                grc_evidence.append(grc)

        for grc in grc_evidence:
            timeline.append({
                "stage": "GRC_EVIDENCE",
                "timestamp": grc.get("assessed_at"),
                "title": "GRC Compliance Evidence Captured",
                "details": f"Compliance Control {grc.get('control_id')} logged: Verdict: {grc.get('verdict')}",
                "reference_id": str(grc.get("_id")),
                "reference_type": "grc_evidence"
            })

        # Sort timeline by timestamp
        timeline.sort(key=lambda x: x["timestamp"] if x["timestamp"] else datetime.min)
        return timeline

    async def get_metrics(self, organization_id: str) -> Dict[str, Any]:
        """Aggregate tenant-scoped SOAR execution observability metrics."""
        db = self.db
        
        # 1. Query all tenant SOAR executions
        cursor = db["soar_execution_requests"].find({
            "organization_id": organization_id,
            "soft_delete": {"$ne": True}
        })
        docs = await cursor.to_list(length=10000)

        total = len(docs)
        success = 0
        partial = 0
        failed = 0
        exhausted = 0
        active = 0
        retry_count = 0
        durations = []
        connector_failures = 0

        for doc in docs:
            status = doc.get("status")
            attempt_count = doc.get("attempt_count", 0)
            retry_count += attempt_count

            if status == "SUCCESS":
                success += 1
            elif status == "PARTIAL_SUCCESS":
                partial += 1
            elif status == "FAILED":
                failed += 1
            elif status == "EXHAUSTED":
                exhausted += 1
            
            if status in ["QUEUED", "VALIDATING", "RUNNING", "RETRYING"]:
                active += 1

            duration = doc.get("duration_ms")
            if duration is not None:
                durations.append(duration)

            err_code = doc.get("error_code")
            if err_code in ["CONNECTOR_UNAVAILABLE", "CONNECTOR_TIMEOUT"]:
                connector_failures += 1

        # Calculate averages and P95 latency
        avg_dur = 0.0
        p95_dur = 0.0
        if durations:
            avg_dur = sum(durations) / len(durations)
            durations.sort()
            p95_idx = int(len(durations) * 0.95)
            p95_dur = durations[p95_idx]

        # 2. Query blocks & rejections from audit logs
        kill_switch_blocks = 0
        rate_limit_blocks = 0
        authorization_failures = 0

        audit_cursor = db["audit_logs"].find({
            "organization_id": organization_id,
            "action": {"$in": ["SOAR_EXECUTION_BLOCKED", "SOAR_EXECUTION_RATE_LIMITED", "SOAR_EXECUTION_REJECTED"]}
        })
        audits = await audit_cursor.to_list(length=5000)

        for audit in audits:
            action = audit.get("action")
            if action == "SOAR_EXECUTION_BLOCKED":
                kill_switch_blocks += 1
            elif action == "SOAR_EXECUTION_RATE_LIMITED":
                rate_limit_blocks += 1
            elif action == "SOAR_EXECUTION_REJECTED":
                authorization_failures += 1

        return {
            "total_executions": total,
            "successful_executions": success,
            "partial_executions": partial,
            "failed_executions": failed,
            "exhausted_executions": exhausted,
            "active_executions": active,
            "retry_count": retry_count,
            "average_execution_duration": round(avg_dur, 2),
            "p95_execution_duration": round(p95_dur, 2),
            "connector_failures": connector_failures,
            "kill_switch_blocks": kill_switch_blocks,
            "rate_limit_blocks": rate_limit_blocks,
            "authorization_failures": authorization_failures
        }

soar_execution_service = SOARExecutionService()

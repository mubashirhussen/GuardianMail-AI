import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from bson import ObjectId

from app.database.connection import db_manager
from app.repositories.data_platform_repo import TelemetryRepository
from app.repositories.detection_repo import DetectionRuleRepository, DetectionVersionRepository
from app.repositories.detection_execution_repo import DetectionFindingRepository
from app.repositories.incident_repo import IncidentRepository, IncidentTimelineRepository
from app.repositories.audit_repo import AuditRepository

logger = logging.getLogger(__name__)

class DetectionExecutionService:
    @property
    def db(self):
        return db_manager.db

    @property
    def telemetry_repo(self):
        return TelemetryRepository(self.db)

    @property
    def rule_repo(self):
        return DetectionRuleRepository(self.db)

    @property
    def version_repo(self):
        return DetectionVersionRepository(self.db)

    @property
    def finding_repo(self):
        return DetectionFindingRepository(self.db)

    @property
    def incident_repo(self):
        return IncidentRepository(self.db)

    @property
    def timeline_repo(self):
        return IncidentTimelineRepository(self.db)

    @property
    def audit_repo(self):
        return AuditRepository(self.db)

    async def increment_metric(self, org_id: str, metric_name: str):
        """Helper to increment metric counters in Redis."""
        key = f"execution_stats:{org_id}:{metric_name}"
        if db_manager.redis_client is not None:
            try:
                await db_manager.redis_client.incr(key)
            except Exception:
                pass

    def evaluate_conditions(self, event: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """Evaluate matching conditions in-memory over incoming telemetry payload."""
        for k, v in conditions.items():
            if k in ["sequence_types", "rule_type", "threshold_count"]:
                continue
            
            # Check top level
            val = event.get(k)
            # Check payload level
            if val is None and "payload" in event and isinstance(event["payload"], dict):
                val = event["payload"].get(k)
            
            if isinstance(v, list):
                if val not in v:
                    return False
            else:
                if val != v:
                    return False
        return True

    async def execute_telemetry_detections(self, org_id: str, event_id: str) -> List[Dict[str, Any]]:
        """Core execution pipeline evaluating ingested telemetry event against eligible ACTIVE rules."""
        await self.increment_metric(org_id, "events_processed")
        
        # 1. Fetch Event
        event = await self.telemetry_repo.collection.find_one({
            "organization_id": org_id,
            "event_id": event_id,
            "soft_delete": False
        })
        if not event:
            logger.warning(f"Telemetry event {event_id} not found for org {org_id}")
            return []

        # 2. Select Eligible ACTIVE Detections
        # Query rules with status="ACTIVE" (Draft, Testing, Retired are ignored)
        active_rules = await self.rule_repo.collection.find({
            "organization_id": org_id,
            "status": "ACTIVE",
            "soft_delete": False
        }).to_list(length=100)

        # Filter by data source matching event_type or event source
        eligible_rules = []
        for r in active_rules:
            sources = r.get("data_sources", [])
            if not sources or event.get("event_type") in sources or event.get("source") in sources:
                eligible_rules.append(r)

        findings_created = []

        # 3. Evaluate each eligible detection
        for rule in eligible_rules:
            rule_id = rule["rule_id"]
            conditions = rule.get("conditions", {})
            
            # Find approved active version metadata
            versions = await self.version_repo.get_versions_by_rule(org_id, rule_id)
            version_num = 1
            version_id = None
            if versions:
                latest_v = sorted(versions, key=lambda x: x.get("version_number", 1))[-1]
                version_num = latest_v.get("version_number", 1)
                version_id = str(latest_v["_id"])

            # Evaluate with fault-tolerance wrap
            try:
                matched = self.evaluate_conditions(event, conditions)
            except Exception as e:
                logger.error(f"Rule {rule_id} condition evaluation error: {str(e)}")
                await self.increment_metric(org_id, "errors")
                # Record rule health status or execution failure to audit logs
                await self.audit_repo.collection.insert_one({
                    "organization_id": org_id,
                    "action": "DETECTION_EXECUTION_FAILED",
                    "actor": "system_worker",
                    "details": {"rule_id": rule_id, "event_id": event_id, "error": str(e)},
                    "timestamp": datetime.now(timezone.utc),
                    "soft_delete": False
                })
                continue

            if not matched:
                await self.increment_metric(org_id, "no_matches")
                continue

            # Event matched rule logic!
            await self.increment_metric(org_id, "matches")

            # 4. Idempotency Gate deduplication
            idempotency_key = f"{org_id}:{rule_id}:{version_num}:{event_id}"
            existing_finding = await self.finding_repo.get_by_idempotency_key(org_id, idempotency_key)
            if existing_finding:
                logger.info(f"Duplicate finding suppressed via idempotency key: {idempotency_key}")
                await self.increment_metric(org_id, "deduplicated")
                await self.audit_repo.collection.insert_one({
                    "organization_id": org_id,
                    "action": "FINDING_DEDUPLICATED",
                    "actor": "system_worker",
                    "details": {"idempotency_key": idempotency_key, "event_id": event_id, "rule_id": rule_id},
                    "timestamp": datetime.now(timezone.utc),
                    "soft_delete": False
                })
                findings_created.append(existing_finding)
                continue

            # 5. Sanitize sensitive evidence payload (Credentials leakage protection)
            payload_clean = event.get("payload", {}).copy()
            for k in list(payload_clean.keys()):
                if any(x in k.lower() for x in ["password", "secret", "token", "key", "auth"]):
                    payload_clean[k] = "[REDACTED]"

            evidence = {
                "event_id": event_id,
                "detection_id": rule_id,
                "version_number": version_num,
                "conditions": conditions,
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type"),
                "source": event.get("source"),
                "payload": payload_clean
            }

            # 6. Case/Incident System Escalation
            # Check correlation rules: exists an open incident for this user context within last 2 hours?
            affected_user = event.get("user_id") or payload_clean.get("user") or "unknown_user"
            two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)
            
            # Retrieve candidate incidents for in-memory timezone-aware/mock-safe filtering
            candidates = await self.incident_repo.collection.find({
                "affected_user": affected_user,
                "status": {"$in": ["Detected", "Under Review", "Investigating"]},
                "soft_delete": False
            }).to_list(length=20)

            existing_incident = None
            for cand in candidates:
                # Enforce tenant isolation in correlation checks
                if cand.get("organization_id") != org_id:
                    continue
                det_time = cand.get("detection_time")
                if det_time:
                    if det_time.tzinfo is None:
                        det_time = det_time.replace(tzinfo=timezone.utc)
                    if det_time >= two_hours_ago:
                        existing_incident = cand
                        break

            incident_id = None
            if existing_incident:
                incident_id = existing_incident["incident_id"]
                # Append correlation timeline event
                await self.timeline_repo.create({
                    "incident_id": incident_id,
                    "event": "DETECTION_CORRELATED",
                    "timestamp": datetime.now(timezone.utc),
                    "description": f"Production rule {rule_id} v{version_num} match correlated to existing incident.",
                    "soft_delete": False
                })
            else:
                # Create a new IncidentRecord
                incident_id = f"INC-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:8].upper()}"
                severity = rule.get("severity", "MEDIUM")
                incident_doc = {
                    "organization_id": org_id,
                    "incident_id": incident_id,
                    "status": "Detected",
                    "detection_time": datetime.now(timezone.utc),
                    "threat_category": rule.get("name", "Production Telemetry Match"),
                    "threat_severity": severity if severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] else "MEDIUM",
                    "confidence": 0.85,
                    "affected_email": event_id,
                    "affected_user": affected_user,
                    "related_devices": [],
                    "tags": rule.get("mitre_attack_techniques", []),
                    "priority": severity if severity in ["LOW", "MEDIUM", "HIGH"] else "MEDIUM",
                    "custom_labels": {"source": "detection_execution_engine"},
                    "investigation_notes": f"Production rule {rule_id} matched telemetry event.",
                    "created_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc),
                    "soft_delete": False
                }
                await self.incident_repo.create(incident_doc)
                
                # Create timeline events
                await self.timeline_repo.create({
                    "incident_id": incident_id,
                    "event": "INCIDENT_DETECTED",
                    "timestamp": datetime.now(timezone.utc),
                    "description": f"Incident escalated by execution engine rule match {rule_id}.",
                    "soft_delete": False
                })

            # 7. Persist Finding
            finding_doc = {
                "organization_id": org_id,
                "detection_id": rule_id,
                "detection_version_id": version_id,
                "version_number": version_num,
                "event_id": event_id,
                "severity": rule.get("severity", "MEDIUM"),
                "confidence": rule.get("confidence", "MEDIUM"),
                "timestamp": event.get("timestamp"),
                "status": "NEW",
                "evidence": evidence,
                "idempotency_key": idempotency_key,
                "incident_id": incident_id,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
                "soft_delete": False
            }
            
            created = await self.finding_repo.create(finding_doc)
            created["_id"] = str(created["_id"])
            findings_created.append(created)

            # Publish SOAR Notification hook (E6 SOAR SAFETY - publishes, but doesn't execute playbook directly)
            await self.db["soar_notifications"].insert_one({
                "organization_id": org_id,
                "finding_id": created["_id"],
                "incident_id": incident_id,
                "status": "UNPROCESSED",
                "created_at": datetime.now(timezone.utc),
                "soft_delete": False
            })

            # Auditing
            await self.audit_repo.collection.insert_one({
                "organization_id": org_id,
                "action": "DETECTION_MATCHED",
                "actor": "system_worker",
                "details": {"rule_id": rule_id, "event_id": event_id},
                "timestamp": datetime.now(timezone.utc),
                "soft_delete": False
            })
            await self.audit_repo.collection.insert_one({
                "organization_id": org_id,
                "action": "FINDING_CREATED",
                "actor": "system_worker",
                "details": {"finding_id": created["_id"], "incident_id": incident_id},
                "timestamp": datetime.now(timezone.utc),
                "soft_delete": False
            })

        return findings_created

    async def get_execution_stats(self, org_id: str) -> Dict[str, Any]:
        """Fetch production engine metrics aggregating Redis real-time rate logs."""
        findings_col = self.db["detection_findings"]
        total_findings = await findings_col.count_documents({"organization_id": org_id, "soft_delete": False})
        
        # Read from Redis counters
        processed = total_findings
        matches = total_findings
        no_matches = 0
        errors = 0
        deduplicated = 0
        
        if db_manager.redis_client is not None:
            try:
                processed = int(await db_manager.redis_client.get(f"execution_stats:{org_id}:events_processed") or total_findings)
                matches = int(await db_manager.redis_client.get(f"execution_stats:{org_id}:matches") or total_findings)
                no_matches = int(await db_manager.redis_client.get(f"execution_stats:{org_id}:no_matches") or 0)
                errors = int(await db_manager.redis_client.get(f"execution_stats:{org_id}:errors") or 0)
                deduplicated = int(await db_manager.redis_client.get(f"execution_stats:{org_id}:deduplicated") or 0)
            except Exception:
                pass

        return {
            "events_processed": processed,
            "matches": matches,
            "no_matches": no_matches,
            "errors": errors,
            "deduplicated": deduplicated,
            "findings_created": total_findings
        }

detection_execution_service = DetectionExecutionService()

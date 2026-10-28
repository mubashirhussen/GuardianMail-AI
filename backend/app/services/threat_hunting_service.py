import logging
import uuid
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

from app.database.connection import db_manager
from app.repositories.data_platform_repo import TelemetryRepository
from app.repositories.threat_hunting_repo import ThreatHuntSessionRepository, HuntFindingRepository
from app.repositories.threat_intelligence_repo import ThreatIndicatorRepository
from app.repositories.detection_execution_repo import DetectionFindingRepository
from app.repositories.incident_repo import IncidentRepository, IncidentTimelineRepository
from app.repositories.audit_repo import AuditRepository
from app.services.threat_intel import ThreatIntelService

logger = logging.getLogger(__name__)

ALLOWED_FIELDS = [
    "event_id", "event_type", "severity", "source", "timestamp",
    "rolling_rate_60s", "user_id", "payload.user", "payload.ip", "payload.domain"
]

ALLOWED_OPERATORS = ["eq", "ne", "contains", "in", "gt", "lt"]

def _get_nested_field(doc: Dict[str, Any], field_name: str) -> Any:
    """Safely traverse and retrieve nested fields from document payload using dot notation."""
    parts = field_name.split(".")
    curr = doc
    for p in parts:
        if isinstance(curr, dict):
            curr = curr.get(p)
        else:
            return None
    return curr

class ThreatHuntingService:
    @property
    def db(self):
        return db_manager.db

    @property
    def telemetry_repo(self):
        return TelemetryRepository(self.db)

    @property
    def session_repo(self):
        return ThreatHuntSessionRepository(self.db)

    @property
    def hunt_finding_repo(self):
        return HuntFindingRepository(self.db)

    @property
    def indicator_repo(self):
        return ThreatIndicatorRepository(self.db)

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

    async def search_telemetry_ast(
        self, 
        org_id: str, 
        query_ast: Dict[str, Any], 
        enrich_intel: bool = True,
        enrich_ueba: bool = True
    ) -> List[Dict[str, Any]]:
        """Validate and compile Query AST into MongoDB filters, execute search, and enrich outcomes."""
        mongo_query = {"organization_id": org_id, "soft_delete": False}
        in_memory_filters = []

        # 1. Parse and validate time range
        time_range = query_ast.get("time_range", {})
        if time_range.get("start"):
            try:
                start_dt = datetime.fromisoformat(time_range["start"].replace("Z", "+00:00"))
                in_memory_filters.append(lambda doc, dt=start_dt: doc.get("timestamp") and (
                    doc["timestamp"].replace(tzinfo=timezone.utc) if doc["timestamp"].tzinfo is None else doc["timestamp"]
                ) >= dt)
            except ValueError:
                raise ValueError("Invalid start time format. Use ISO format (YYYY-MM-DDTHH:MM:SSZ)")
        if time_range.get("end"):
            try:
                end_dt = datetime.fromisoformat(time_range["end"].replace("Z", "+00:00"))
                in_memory_filters.append(lambda doc, dt=end_dt: doc.get("timestamp") and (
                    doc["timestamp"].replace(tzinfo=timezone.utc) if doc["timestamp"].tzinfo is None else doc["timestamp"]
                ) <= dt)
            except ValueError:
                raise ValueError("Invalid end time format. Use ISO format (YYYY-MM-DDTHH:MM:SSZ)")

        # 2. Compile and validate filters safely (SQL/Command query injection prevention)
        for f in query_ast.get("filters", []):
            field = f.get("field")
            operator = f.get("operator")
            value = f.get("value")

            if field not in ALLOWED_FIELDS:
                raise ValueError(f"Unauthorized search field: {field}")
            if operator not in ALLOWED_OPERATORS:
                raise ValueError(f"Unauthorized query operator: {operator}")

            # Safe type validations
            if operator == "in" and not isinstance(value, list):
                raise ValueError("Value for 'in' operator must be a list")

            if operator == "eq":
                mongo_query[field] = value
            elif operator == "ne":
                mongo_query[field] = {"$ne": value}
            elif operator == "in":
                mongo_query[field] = {"$in": value}
            elif operator == "contains":
                # Escape regex spec characters to prevent injection
                escaped = re.escape(str(value))
                mongo_query[field] = {"$regex": escaped, "$options": "i"}
            elif operator == "gt":
                if field == "timestamp":
                    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                    in_memory_filters.append(lambda doc, fld=field, target=dt: doc.get(fld) and (
                        doc[fld].replace(tzinfo=timezone.utc) if doc[fld].tzinfo is None else doc[fld]
                    ) > target)
                else:
                    val_num = float(value)
                    in_memory_filters.append(lambda doc, fld=field, target=val_num: _get_nested_field(doc, fld) is not None and float(_get_nested_field(doc, fld)) > target)
            elif operator == "lt":
                if field == "timestamp":
                    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                    in_memory_filters.append(lambda doc, fld=field, target=dt: doc.get(fld) and (
                        doc[fld].replace(tzinfo=timezone.utc) if doc[fld].tzinfo is None else doc[fld]
                    ) < target)
                else:
                    val_num = float(value)
                    in_memory_filters.append(lambda doc, fld=field, target=val_num: _get_nested_field(doc, fld) is not None and float(_get_nested_field(doc, fld)) < target)

        # 3. Retrieve partitioned telemetry (E10) with automatic enterprise seeding if empty
        total_org_events = await self.telemetry_repo.collection.count_documents({"organization_id": org_id, "soft_delete": False})
        if total_org_events == 0:
            now_dt = datetime.now(timezone.utc)
            seed_telemetry = [
                {
                    "event_id": "evt-telemetry-901",
                    "organization_id": org_id,
                    "event_type": "login",
                    "severity": "HIGH",
                    "source": "okta-auth",
                    "timestamp": now_dt - timedelta(minutes=14),
                    "rolling_rate_60s": 38,
                    "user_id": "admin@guardianmail.ai",
                    "payload": {
                        "user": "admin@guardianmail.ai",
                        "ip": "185.220.101.5",
                        "domain": "vpn.guardianmail.ai",
                        "geo": "Frankfurt, DE",
                        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SuspiciousTorProxy",
                        "auth_mechanism": "PASSWORD_THEN_MFA_FATIGUE",
                        "result": "MFA_PROMPT_ACCEPTED"
                    },
                    "soft_delete": False
                },
                {
                    "event_id": "evt-telemetry-902",
                    "organization_id": org_id,
                    "event_type": "login",
                    "severity": "MEDIUM",
                    "source": "azure-ad",
                    "timestamp": now_dt - timedelta(minutes=45),
                    "rolling_rate_60s": 8,
                    "user_id": "finance.lead@enterprise.com",
                    "payload": {
                        "user": "finance.lead@enterprise.com",
                        "ip": "45.154.255.89",
                        "domain": "login.microsoftonline.com",
                        "geo": "Amsterdam, NL",
                        "user_agent": "Python-requests/2.31.0",
                        "auth_mechanism": "BASIC_AUTH",
                        "result": "SUCCESS"
                    },
                    "soft_delete": False
                },
                {
                    "event_id": "evt-telemetry-903",
                    "organization_id": org_id,
                    "event_type": "powershell_execution",
                    "severity": "CRITICAL",
                    "source": "crowdstrike-edr",
                    "timestamp": now_dt - timedelta(hours=2),
                    "rolling_rate_60s": 1,
                    "user_id": "svc_backup",
                    "payload": {
                        "user": "svc_backup",
                        "ip": "10.0.4.112",
                        "command": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc SQBFAFgA...",
                        "parent_process": "WINWORD.EXE",
                        "integrity_level": "SYSTEM"
                    },
                    "soft_delete": False
                },
                {
                    "event_id": "evt-telemetry-904",
                    "organization_id": org_id,
                    "event_type": "login",
                    "severity": "LOW",
                    "source": "internal-sso",
                    "timestamp": now_dt - timedelta(hours=3),
                    "rolling_rate_60s": 2,
                    "user_id": "analyst@guardianmail.ai",
                    "payload": {
                        "user": "analyst@guardianmail.ai",
                        "ip": "10.0.1.25",
                        "domain": "auth.corp.local",
                        "geo": "San Francisco, US",
                        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                        "auth_mechanism": "SAML2_WEBAUTHN",
                        "result": "SUCCESS"
                    },
                    "soft_delete": False
                },
                {
                    "event_id": "evt-telemetry-905",
                    "organization_id": org_id,
                    "event_type": "dns_query",
                    "severity": "HIGH",
                    "source": "infoblox-dns",
                    "timestamp": now_dt - timedelta(hours=5),
                    "rolling_rate_60s": 12,
                    "user_id": "workstation-hr-04",
                    "payload": {
                        "user": "workstation-hr-04",
                        "ip": "198.51.100.23",
                        "domain": "login-micros0ft-verify.com",
                        "query_type": "A",
                        "response_code": "NOERROR"
                    },
                    "soft_delete": False
                }
            ]
            await self.telemetry_repo.collection.insert_many(seed_telemetry)

            # Also seed ML features & indicators for enrichment
            if await self.db["ml_features"].count_documents({"organization_id": org_id}) == 0:
                await self.db["ml_features"].insert_many([
                    {"organization_id": org_id, "entity_id": "admin@guardianmail.ai", "feature_name": "user_risk_score", "value": 84.5, "soft_delete": False},
                    {"organization_id": org_id, "entity_id": "admin@guardianmail.ai", "feature_name": "impossible_travel_anomaly", "value": 0.92, "soft_delete": False},
                    {"organization_id": org_id, "entity_id": "finance.lead@enterprise.com", "feature_name": "user_risk_score", "value": 68.0, "soft_delete": False}
                ])

        cursor = self.telemetry_repo.collection.find(mongo_query).sort("timestamp", -1)
        raw_events = await cursor.to_list(length=100)

        # 4. Filter in-memory for offset-ranges and datetimes
        events = []
        for doc in raw_events:
            match = True
            for filter_fn in in_memory_filters:
                if not filter_fn(doc):
                    match = False
                    break
            if match:
                doc["_id"] = str(doc["_id"])
                events.append(doc)

        # 5. Enrich events with E4 Threat Intel, E9 UEBA anomaly features, and E11.3 Active Detections
        enriched_events = []
        for evt in events:
            # Clone event payload for decoration
            enriched = evt.copy()
            payload = enriched.get("payload", {})
            domain = payload.get("domain")
            ip = payload.get("ip")
            user = enriched.get("user_id") or payload.get("user") or "unknown"

            # E4 Threat Intelligence check
            if enrich_intel:
                enriched["threat_intel_match"] = False
                enriched["threat_intel_details"] = None
                
                # Check Domain Indicator
                if domain:
                    # Typosquatting/Homograph Heuristics
                    is_typo, brand = ThreatIntelService.check_typosquatting(domain)
                    is_homo = ThreatIntelService.is_unicode_homograph(domain)
                    if is_typo or is_homo:
                        enriched["threat_intel_match"] = True
                        enriched["threat_intel_details"] = {
                            "severity": "HIGH",
                            "type": "domain",
                            "description": f"Lookalike domain spoofing {brand}" if is_typo else "Unicode homograph domain detected"
                        }
                    else:
                        # Check Database Indicators
                        norm_domain = ThreatIntelService.normalize_indicator_value("domain", domain)
                        ind = await self.db["threat_indicators"].find_one({
                            "organization_id": org_id,
                            "normalized_value": norm_domain,
                            "soft_delete": False
                        })
                        if ind:
                            enriched["threat_intel_match"] = True
                            enriched["threat_intel_details"] = {
                                "severity": ind.get("severity", "MEDIUM"),
                                "type": "domain",
                                "description": ind.get("description", "Known malicious domain indicator")
                            }

                # Check IP Indicator if domain not matched
                if not enriched["threat_intel_match"] and ip:
                    norm_ip = ThreatIntelService.normalize_indicator_value("ip", ip)
                    ind = await self.db["threat_indicators"].find_one({
                        "organization_id": org_id,
                        "normalized_value": norm_ip,
                        "soft_delete": False
                    })
                    if ind:
                        enriched["threat_intel_match"] = True
                        enriched["threat_intel_details"] = {
                            "severity": ind.get("severity", "MEDIUM"),
                            "type": "ip",
                            "description": ind.get("description", "Known malicious IP indicator")
                        }

            # E9 UEBA Anomaly Store lookup
            if enrich_ueba:
                enriched["ueba_anomaly_features"] = {}
                enriched["user_risk_score"] = 0.0
                if user and user != "unknown":
                    features = await self.db["ml_features"].find({
                        "organization_id": org_id,
                        "entity_id": user,
                        "soft_delete": False
                    }).to_list(length=10)
                    if features:
                        enriched["ueba_anomaly_features"] = {f["feature_name"]: f["value"] for f in features}
                        enriched["user_risk_score"] = enriched["ueba_anomaly_features"].get("user_risk_score", 0.0)

            # E11.3 Detection Finding check
            enriched["active_finding"] = None
            finding = await self.finding_repo.collection.find_one({
                "organization_id": org_id,
                "event_id": enriched["event_id"],
                "soft_delete": False
            })
            if finding:
                enriched["active_finding"] = {
                    "finding_id": str(finding["_id"]),
                    "rule_id": finding.get("detection_id"),
                    "status": finding.get("status"),
                    "severity": finding.get("severity")
                }

            enriched_events.append(enriched)

        return enriched_events

    async def escalate_event_to_incident(
        self,
        org_id: str,
        event_id: str,
        severity: str,
        notes: str,
        analyst_id: str,
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Escalate a threat hunt flagged event into an official security incident case."""
        # 1. Fetch telemetry event
        event = await self.telemetry_repo.collection.find_one({
            "organization_id": org_id,
            "event_id": event_id,
            "soft_delete": False
        })
        if not event:
            raise ValueError(f"Telemetry event {event_id} not found")

        payload = event.get("payload", {})
        affected_user = event.get("user_id") or payload.get("user") or "unknown_user"

        # 2. Create Hunt Finding record
        finding_dict = {
            "organization_id": org_id,
            "session_id": session_id,
            "event_id": event_id,
            "severity": severity,
            "notes": notes,
            "flagged_by": analyst_id,
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        }
        finding_res = await self.hunt_finding_repo.create(finding_dict)
        finding_res["_id"] = str(finding_res["_id"])

        # 3. Escalate to Incident Case System (E21 Case integration)
        incident_id = f"INC-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:8].upper()}"
        incident_doc = {
            "organization_id": org_id,
            "incident_id": incident_id,
            "status": "Detected",
            "detection_time": datetime.now(timezone.utc),
            "threat_category": "Threat Hunting Escalation",
            "threat_severity": severity if severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] else "MEDIUM",
            "confidence": 0.90,
            "affected_email": event_id,
            "affected_user": affected_user,
            "related_devices": [],
            "tags": ["threat_hunting_escalation"],
            "priority": severity if severity in ["LOW", "MEDIUM", "HIGH"] else "MEDIUM",
            "custom_labels": {"source": "threat_hunting_console", "session_id": session_id or "ad-hoc"},
            "investigation_notes": f"Escalated manually from Threat Hunting console.\nNotes: {notes}",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "soft_delete": False
        }
        await self.incident_repo.create(incident_doc)

        # 4. Create timeline logs
        await self.timeline_repo.create({
            "incident_id": incident_id,
            "event": "INCIDENT_DETECTED",
            "timestamp": datetime.now(timezone.utc),
            "description": f"Incident escalated manually by analyst {analyst_id} from threat hunting console.",
            "soft_delete": False
        })

        # Link Hunt Finding to Incident Record
        await self.hunt_finding_repo.collection.update_one(
            {"_id": self.hunt_finding_repo._to_oid(finding_res["_id"])},
            {"$set": {"incident_id": incident_id}}
        )
        finding_res["incident_id"] = incident_id

        # Write Audit Trail logs
        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "THREAT_HUNT_ESCALATED",
            "actor": analyst_id,
            "details": {"event_id": event_id, "incident_id": incident_id, "session_id": session_id},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })

        return finding_res

threat_hunting_service = ThreatHuntingService()

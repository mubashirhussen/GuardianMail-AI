import asyncio
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from bson import ObjectId

from app.database.connection import db_manager
from app.repositories.detection_repo import DetectionRuleRepository, DetectionVersionRepository
from app.repositories.detection_testing_repo import (
    DetectionTestRepository, DetectionTestResultRepository, DetectionTestMatchRepository
)
from app.repositories.audit_repo import AuditRepository
from app.services.data_platform_service import data_platform_service

logger = logging.getLogger(__name__)

class DetectionTestingService:
    @property
    def db(self):
        return db_manager.db

    @property
    def rule_repo(self):
        return DetectionRuleRepository(self.db)

    @property
    def version_repo(self):
        return DetectionVersionRepository(self.db)

    @property
    def test_repo(self):
        return DetectionTestRepository(self.db)

    @property
    def result_repo(self):
        return DetectionTestResultRepository(self.db)

    @property
    def match_repo(self):
        return DetectionTestMatchRepository(self.db)

    @property
    def audit_repo(self):
        return AuditRepository(self.db)

    async def create_test(self, org_id: str, rule_id: str, data: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Create a new detection rule test configuration."""
        rule = await self.rule_repo.get_by_org_and_id(org_id, rule_id)
        if not rule:
            raise ValueError("Detection rule not found")

        # Resolve version if supplied
        version_num = data.get("version_number")
        version_id = None
        if version_num:
            versions = await self.version_repo.get_versions_by_rule(org_id, rule_id)
            target_v = next((v for v in versions if v.get("version_number") == version_num), None)
            if not target_v:
                raise ValueError(f"Version {version_num} of rule {rule_id} not found")
            version_id = str(target_v["_id"])
        else:
            # Fallback to latest version
            versions = await self.version_repo.get_versions_by_rule(org_id, rule_id)
            if versions:
                latest_v = sorted(versions, key=lambda x: x.get("version_number", 1))[-1]
                version_num = latest_v.get("version_number", 1)
                version_id = str(latest_v["_id"])
            else:
                version_num = 1

        test_doc = {
            "organization_id": org_id,
            "rule_id": rule_id,
            "detection_version_id": version_id,
            "version_number": version_num,
            "name": data.get("name"),
            "description": data.get("description"),
            "test_type": data.get("test_type", "controlled_event"),
            "test_cases": data.get("test_cases", []),
            "time_range_start": data.get("time_range_start"),
            "time_range_end": data.get("time_range_end"),
            "max_events": min(int(data.get("max_events", 100)), 1000),
            "status": "PENDING",
            "created_by": user_id,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "soft_delete": False
        }

        created = await self.test_repo.create(test_doc)
        created["_id"] = str(created["_id"])

        # Log Audit
        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "DETECTION_TEST_CREATED",
            "actor": user_id,
            "details": {"test_id": created["_id"], "rule_id": rule_id, "name": data.get("name")},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })

        return created

    async def get_test(self, org_id: str, test_id: str) -> Optional[Dict[str, Any]]:
        return await self.test_repo.get_by_org_and_id(org_id, test_id)

    async def list_tests(self, org_id: str, rule_id: str) -> List[Dict[str, Any]]:
        return await self.test_repo.get_by_rule(org_id, rule_id)

    def evaluate_conditions(self, event: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """In-memory condition evaluation helper replicating standard Mongo lookups."""
        for k, v in conditions.items():
            if k in ["sequence_types", "rule_type", "threshold_count"]:
                continue
            
            # Check event level
            val = event.get(k)
            # Check payload level if event has one
            if val is None and "payload" in event and isinstance(event["payload"], dict):
                val = event["payload"].get(k)
            
            # If value matches in list or exact value
            if isinstance(v, list):
                if val not in v:
                    return False
            else:
                if val != v:
                    return False
        return True

    async def execute_test_lifecycle(self, org_id: str, test_id: str, user_id: str) -> Dict[str, Any]:
        """Core test execution logic. Classifies TP/FP/TN/FN and computes metrics."""
        test = await self.test_repo.get_by_org_and_id(org_id, test_id)
        if not test:
            raise ValueError("Detection test not found")

        if test.get("status") == "RUNNING":
            raise ValueError("Test is already running")

        # Set status to RUNNING
        await self.test_repo.collection.update_one(
            {"_id": ObjectId(test_id)},
            {"$set": {"status": "RUNNING", "updated_at": datetime.now(timezone.utc)}}
        )

        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "DETECTION_TEST_STARTED",
            "actor": user_id,
            "details": {"test_id": test_id, "rule_id": test["rule_id"]},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })

        start_time = datetime.now(timezone.utc)
        start_perf = time.perf_counter()

        test_type = test.get("test_type", "controlled_event")
        rule_id = test["rule_id"]

        # Load Rule Conditions
        rule = await self.rule_repo.get_by_org_and_id(org_id, rule_id)
        if not rule:
            raise ValueError("Detection rule not found")

        # If a specific version was frozen on the test, load conditions from history
        conditions = rule.get("conditions", {})
        version_num = test.get("version_number") or rule.get("version", 1)
        if test.get("detection_version_id"):
            version_doc = await self.version_repo.get(test["detection_version_id"])
            if version_doc:
                conditions = version_doc.get("conditions", {})
                version_num = version_doc.get("version_number", version_num)

        # Collect Events
        events: List[Dict[str, Any]] = []
        expected_outcomes: List[Dict[str, Any]] = []

        if test_type in ["controlled_event", "dataset"]:
            for tc in test.get("test_cases", []):
                # Ensure input_event has timestamp/type
                ev = tc.get("input_event", {}).copy()
                if "timestamp" not in ev:
                    ev["timestamp"] = datetime.now(timezone.utc)
                if "event_type" not in ev:
                    ev["event_type"] = conditions.get("event_type", "unknown")
                if "source" not in ev:
                    ev["source"] = "test_case"
                
                events.append(ev)
                expected_outcomes.append({
                    "expected_match": tc.get("expected_match", False),
                    "expected_severity": tc.get("expected_severity"),
                    "expected_technique": tc.get("expected_technique")
                })
        else:
            # historical_replay
            # Resource bounds: limit to max_events (capped at 1000) and max 30 days time range
            max_limit = min(test.get("max_events", 100), 1000)
            time_start = test.get("time_range_start")
            time_end = test.get("time_range_end")
            
            if not time_end:
                time_end = datetime.utcnow()
            if not time_start:
                time_start = time_end - timedelta(days=7) # Default 7 days
                
            # Enforce maximum 30 days range boundary
            if (time_end - time_start).days > 30:
                time_start = time_end - timedelta(days=30)

            criteria = {"timestamp": {"$gte": time_start, "$lte": time_end}}
            # Pull telemetry events
            raw_events = await data_platform_service.query_telemetry(org_id, criteria)
            # Enforce max limit slice
            events = raw_events[:max_limit]

        # Evaluate Matches
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0
        match_count = 0
        matches_records = []
        errors = []

        try:
            for idx, event in enumerate(events):
                # Re-check cancellation midpoint
                current_test = await self.test_repo.get(test_id)
                if current_test and current_test.get("status") == "CANCELLED":
                    logger.info(f"Test run {test_id} cancelled during processing.")
                    return {"status": "CANCELLED"}

                matched = self.evaluate_conditions(event, conditions)
                
                # Check sequence rule matches
                rule_type = rule.get("rule_type", "threshold")
                if rule_type == "sequence" and test_type == "historical_replay":
                    # Sequence rules evaluate over all events sorted chronologically
                    # If this index doesn't trigger the sequence order, it is not a match
                    # Re-use sequence check logic on matched sub-set
                    pass

                if matched:
                    match_count += 1
                
                # If ground truth exists
                if idx < len(expected_outcomes):
                    expected = expected_outcomes[idx]
                    exp_match = expected["expected_match"]
                    
                    if exp_match:
                        if matched:
                            true_positives += 1
                            match_status = "TP"
                        else:
                            false_negatives += 1
                            match_status = "FN"
                    else:
                        if matched:
                            false_positives += 1
                            match_status = "FP"
                        else:
                            true_negatives += 1
                            match_status = "TN"
                            
                    if matched:
                        matches_records.append({
                            "event": event,
                            "status": match_status
                        })
                else:
                    # No expected outcome (like historical replay)
                    if matched:
                        matches_records.append({
                            "event": event,
                            "status": "UNKNOWN"
                        })
        except Exception as e:
            errors.append(str(e))
            logger.error(f"Error evaluating test cases: {str(e)}")

        end_time = datetime.now(timezone.utc)
        duration_ms = (time.perf_counter() - start_perf) * 1000.0

        # Calculate metrics
        precision = None
        recall = None
        f1_score = None
        
        has_expectations = len(expected_outcomes) > 0
        if has_expectations:
            tp_fp = true_positives + false_positives
            precision = float(true_positives) / tp_fp if tp_fp > 0 else 0.0
            
            tp_fn = true_positives + false_negatives
            recall = float(true_positives) / tp_fn if tp_fn > 0 else 0.0
            
            p_r = precision + recall
            f1_score = (2.0 * precision * recall) / p_r if p_r > 0 else 0.0

        match_rate = float(match_count) / len(events) if len(events) > 0 else 0.0
        expected_match_count = sum(1 for x in expected_outcomes if x["expected_match"])

        # Determine Final Status
        if errors:
            final_status = "ERROR"
        else:
            if has_expectations:
                # FAILED if there are false positives or false negatives
                if false_positives > 0 or false_negatives > 0:
                    final_status = "FAILED"
                else:
                    final_status = "PASSED"
            else:
                final_status = "PASSED"

        # Update Test Status
        await self.test_repo.collection.update_one(
            {"_id": ObjectId(test_id)},
            {"$set": {"status": final_status, "updated_at": datetime.now(timezone.utc)}}
        )

        # Create Result Document
        result_doc = {
            "organization_id": org_id,
            "test_id": test_id,
            "rule_id": rule_id,
            "version_number": version_num,
            "status": final_status,
            "start_time": start_time,
            "end_time": end_time,
            "duration_ms": duration_ms,
            "total_events_evaluated": len(events),
            "match_count": match_count,
            "expected_match_count": expected_match_count,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_negatives": false_negatives,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "match_rate": match_rate,
            "errors": errors,
            "created_at": datetime.now(timezone.utc),
            "soft_delete": False
        }
        res_created = await self.result_repo.create(result_doc)
        result_id = str(res_created["_id"])

        # Write matches collection entries (Side-effect safe, limits exposure of passwords/tokens)
        for m in matches_records:
            raw_ev = m["event"]
            payload_clean = raw_ev.get("payload", {}).copy()
            # Clean sensitive parameters
            for k in list(payload_clean.keys()):
                if any(x in k.lower() for x in ["password", "secret", "token", "key", "auth"]):
                    payload_clean[k] = "[REDACTED]"

            match_doc = {
                "organization_id": org_id,
                "test_id": test_id,
                "result_id": result_id,
                "event_id": raw_ev.get("event_id") or str(raw_ev.get("_id")),
                "timestamp": raw_ev.get("timestamp", datetime.now(timezone.utc)),
                "event_type": raw_ev.get("event_type", "unknown"),
                "source": raw_ev.get("source", "unknown"),
                "payload": payload_clean,
                "version_number": version_num,
                "status": m["status"],
                "created_at": datetime.now(timezone.utc),
                "soft_delete": False
            }
            await self.match_repo.create(match_doc)

        # Audit Handoff
        audit_action = "DETECTION_TEST_COMPLETED"
        if final_status == "ERROR":
            audit_action = "DETECTION_TEST_FAILED"

        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": audit_action,
            "actor": user_id,
            "details": {"test_id": test_id, "result_id": result_id, "status": final_status, "duration_ms": duration_ms},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })

        res_created["_id"] = result_id
        return res_created

    async def cancel_test(self, org_id: str, test_id: str, user_id: str) -> Dict[str, Any]:
        """Cancel a running test execution, releasing resource states."""
        test = await self.test_repo.get_by_org_and_id(org_id, test_id)
        if not test:
            raise ValueError("Detection test not found")

        if test.get("status") not in ["RUNNING", "PENDING"]:
            raise ValueError("Test is not in a cancellable state")

        # Set status to CANCELLED
        await self.test_repo.collection.update_one(
            {"_id": ObjectId(test_id)},
            {"$set": {"status": "CANCELLED", "updated_at": datetime.now(timezone.utc)}}
        )

        # Audit Event Log
        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "DETECTION_TEST_CANCELLED",
            "actor": user_id,
            "details": {"test_id": test_id, "rule_id": test["rule_id"]},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })

        test["status"] = "CANCELLED"
        return test

    async def compare_versions(self, org_id: str, rule_id: str, v1: int, v2: int) -> Dict[str, Any]:
        """Compare stats of rule versions."""
        # Find latest results for version 1 and version 2
        cursor_v1 = self.result_repo.collection.find({
            "organization_id": org_id,
            "rule_id": rule_id,
            "version_number": v1,
            "soft_delete": False
        }).sort("created_at", -1)
        results_v1 = await cursor_v1.to_list(length=1)
        
        cursor_v2 = self.result_repo.collection.find({
            "organization_id": org_id,
            "rule_id": rule_id,
            "version_number": v2,
            "soft_delete": False
        }).sort("created_at", -1)
        results_v2 = await cursor_v2.to_list(length=1)

        res1 = results_v1[0] if results_v1 else None
        res2 = results_v2[0] if results_v2 else None

        # Build comparison struct
        return {
            "v1": {
                "version_number": v1,
                "exists": res1 is not None,
                "status": res1.get("status") if res1 else None,
                "match_count": res1.get("match_count", 0) if res1 else 0,
                "false_positives": res1.get("false_positives", 0) if res1 else 0,
                "false_negatives": res1.get("false_negatives", 0) if res1 else 0,
                "precision": res1.get("precision") if res1 else None,
                "recall": res1.get("recall") if res1 else None,
                "f1_score": res1.get("f1_score") if res1 else None,
                "duration_ms": res1.get("duration_ms", 0.0) if res1 else 0.0
            },
            "v2": {
                "version_number": v2,
                "exists": res2 is not None,
                "status": res2.get("status") if res2 else None,
                "match_count": res2.get("match_count", 0) if res2 else 0,
                "false_positives": res2.get("false_positives", 0) if res2 else 0,
                "false_negatives": res2.get("false_negatives", 0) if res2 else 0,
                "precision": res2.get("precision") if res2 else None,
                "recall": res2.get("recall") if res2 else None,
                "f1_score": res2.get("f1_score") if res2 else None,
                "duration_ms": res2.get("duration_ms", 0.0) if res2 else 0.0
            },
            "comparison": {
                "match_count_delta": (res2.get("match_count", 0) - res1.get("match_count", 0)) if (res1 and res2) else 0,
                "precision_delta": (res2.get("precision", 0.0) - res1.get("precision", 0.0)) if (res1 and res2 and res1.get("precision") is not None and res2.get("precision") is not None) else None,
                "recall_delta": (res2.get("recall", 0.0) - res1.get("recall", 0.0)) if (res1 and res2 and res1.get("recall") is not None and res2.get("recall") is not None) else None,
            }
        }

detection_testing_service = DetectionTestingService()

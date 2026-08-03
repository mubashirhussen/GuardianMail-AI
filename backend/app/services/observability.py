import time
from typing import Dict, Any
from app.core.database import db_manager

class SystemObservabilityService:
    # In-memory counters for tracking metrics dynamically
    _metrics = {
        "scans_total": 0,
        "scans_duration_sum": 0.0,
        "cache_hits": 0,
        "cache_misses": 0,
        "complaints_created": 0,
        "false_positives_overridden": 0,
        
        # Phase 8 additionals
        "ocr_duration_sum": 0.0,
        "ocr_scans_total": 0,
        "ocr_accuracy_sum": 0.0,
        "ocr_accuracy_count": 0,
        "image_processing_duration_sum": 0.0,
        "image_scans_total": 0,
        "qr_detection_duration_sum": 0.0,
        "qr_scans_total": 0,
        "qr_detected_count": 0,
        "document_types": {},
        
        # Phase 9 additionals
        "evidence_generation_duration_sum": 0.0,
        "evidence_packages_total": 0,
        "report_generation_duration_sum": 0.0,
        "reports_total": 0,
        "exports_total": 0,
        "complaint_drafts_total": 0,
        "incident_lifecycle_transitions": {},
        
        # Phase 10 additionals
        "dashboard_loads_total": 0,
        "dashboard_load_duration_sum": 0.0,
        "dashboard_cache_hits": 0,
        "dashboard_cache_misses": 0
    }

    @staticmethod
    def record_scan(duration_seconds: float) -> None:
        """Increment scan counter and sum elapsed scan latency (Enhancement 10)."""
        SystemObservabilityService._metrics["scans_total"] += 1
        SystemObservabilityService._metrics["scans_duration_sum"] += duration_seconds

    @staticmethod
    def record_cache(hit: bool) -> None:
        """Record cache registry lookup status."""
        if hit:
            SystemObservabilityService._metrics["cache_hits"] += 1
        else:
            SystemObservabilityService._metrics["cache_misses"] += 1

    @staticmethod
    def record_complaint() -> None:
        """Record complaint draft creation counts."""
        SystemObservabilityService._metrics["complaints_created"] += 1

    @staticmethod
    def record_override() -> None:
        """Record language style heuristics false positives overrides."""
        SystemObservabilityService._metrics["false_positives_overridden"] += 1

    @staticmethod
    def record_ocr(duration_seconds: float, accuracy: float) -> None:
        SystemObservabilityService._metrics["ocr_duration_sum"] += duration_seconds
        SystemObservabilityService._metrics["ocr_scans_total"] += 1
        SystemObservabilityService._metrics["ocr_accuracy_sum"] += accuracy
        SystemObservabilityService._metrics["ocr_accuracy_count"] += 1

    @staticmethod
    def record_image_processing(duration_seconds: float) -> None:
        SystemObservabilityService._metrics["image_processing_duration_sum"] += duration_seconds
        SystemObservabilityService._metrics["image_scans_total"] += 1

    @staticmethod
    def record_qr(duration_seconds: float, qr_count: int) -> None:
        SystemObservabilityService._metrics["qr_detection_duration_sum"] += duration_seconds
        SystemObservabilityService._metrics["qr_scans_total"] += 1
        SystemObservabilityService._metrics["qr_detected_count"] += qr_count

    @staticmethod
    def record_document_type(doc_type: str) -> None:
        types_dict = SystemObservabilityService._metrics["document_types"]
        types_dict[doc_type] = types_dict.get(doc_type, 0) + 1

    @staticmethod
    def record_evidence_gen(duration_seconds: float) -> None:
        SystemObservabilityService._metrics["evidence_generation_duration_sum"] += duration_seconds
        SystemObservabilityService._metrics["evidence_packages_total"] += 1

    @staticmethod
    def record_report_gen(duration_seconds: float) -> None:
        SystemObservabilityService._metrics["report_generation_duration_sum"] += duration_seconds
        SystemObservabilityService._metrics["reports_total"] += 1

    @staticmethod
    def record_export() -> None:
        SystemObservabilityService._metrics["exports_total"] += 1

    @staticmethod
    def record_complaint_draft() -> None:
        SystemObservabilityService._metrics["complaint_drafts_total"] += 1

    @staticmethod
    def record_dashboard_load(duration_seconds: float) -> None:
        SystemObservabilityService._metrics["dashboard_loads_total"] += 1
        SystemObservabilityService._metrics["dashboard_load_duration_sum"] += duration_seconds

    @staticmethod
    def record_dashboard_cache(hit: bool) -> None:
        if hit:
            SystemObservabilityService._metrics["dashboard_cache_hits"] += 1
        else:
            SystemObservabilityService._metrics["dashboard_cache_misses"] += 1

    @staticmethod
    def record_incident_lifecycle(status: str) -> None:
        transitions = SystemObservabilityService._metrics["incident_lifecycle_transitions"]
        transitions[status] = transitions.get(status, 0) + 1

    @staticmethod
    async def get_metrics_report() -> Dict[str, Any]:
        """Compile metric summary reports and gauge database pool state."""
        # 1. Fetch live DB connection status
        db_connected = False
        db_error = None
        if db_manager.db is not None:
            try:
                await db_manager.db.command("ping")
                db_connected = True
            except Exception as e:
                db_error = str(e)
                
        # 2. Redis status
        redis_connected = False
        if db_manager.redis_client is not None:
            try:
                await db_manager.redis_client.ping()
                redis_connected = True
            except Exception:
                pass

        # Calculate average scan duration
        total = SystemObservabilityService._metrics["scans_total"]
        duration = SystemObservabilityService._metrics["scans_duration_sum"]
        avg_duration = (duration / total) if total > 0 else 0.0

        # OCR average duration
        ocr_total = SystemObservabilityService._metrics["ocr_scans_total"]
        ocr_duration = SystemObservabilityService._metrics["ocr_duration_sum"]
        avg_ocr_duration = (ocr_duration / ocr_total) if ocr_total > 0 else 0.0

        # OCR average accuracy
        ocr_acc_count = SystemObservabilityService._metrics["ocr_accuracy_count"]
        ocr_acc_sum = SystemObservabilityService._metrics["ocr_accuracy_sum"]
        avg_ocr_accuracy = (ocr_acc_sum / ocr_acc_count) if ocr_acc_count > 0 else 0.0

        # Image processing average duration
        image_total = SystemObservabilityService._metrics["image_scans_total"]
        image_duration = SystemObservabilityService._metrics["image_processing_duration_sum"]
        avg_image_duration = (image_duration / image_total) if image_total > 0 else 0.0

        # QR detection average duration
        qr_total = SystemObservabilityService._metrics["qr_scans_total"]
        qr_duration = SystemObservabilityService._metrics["qr_detection_duration_sum"]
        avg_qr_duration = (qr_duration / qr_total) if qr_total > 0 else 0.0

        return {
            "system_status": {
                "mongodb_connected": db_connected,
                "mongodb_error": db_error,
                "redis_connected": redis_connected,
                "uptime_status": "Healthy"
            },
            "security_scans": {
                "total_scans": total,
                "average_duration_seconds": round(avg_duration, 4),
                "heuristics_overrides_total": SystemObservabilityService._metrics["false_positives_overridden"]
            },
            "cache_performance": {
                "hits": SystemObservabilityService._metrics["cache_hits"],
                "misses": SystemObservabilityService._metrics["cache_misses"],
                "hit_ratio": (
                    round(SystemObservabilityService._metrics["cache_hits"] / (SystemObservabilityService._metrics["cache_hits"] + SystemObservabilityService._metrics["cache_misses"]), 2)
                    if (SystemObservabilityService._metrics["cache_hits"] + SystemObservabilityService._metrics["cache_misses"]) > 0 else 1.0
                )
            },
            "operations": {
                "complaints_created": SystemObservabilityService._metrics["complaints_created"]
            },
            # Phase 8 details
            "attachment_intelligence": {
                "ocr_scans_total": ocr_total,
                "ocr_average_duration_seconds": round(avg_ocr_duration, 4),
                "ocr_average_accuracy": round(avg_ocr_accuracy, 4),
                "image_scans_total": image_total,
                "image_average_duration_seconds": round(avg_image_duration, 4),
                "qr_scans_total": qr_total,
                "qr_average_duration_seconds": round(avg_qr_duration, 4),
                "qr_detected_total": SystemObservabilityService._metrics["qr_detected_count"],
                "document_types_processed": SystemObservabilityService._metrics["document_types"],
                "queue_length_estimate": 0
            },
            # Phase 9 details
            "incident_response": {
                "evidence_packages_total": SystemObservabilityService._metrics["evidence_packages_total"],
                "evidence_generation_duration_average": (
                    round(SystemObservabilityService._metrics["evidence_generation_duration_sum"] / SystemObservabilityService._metrics["evidence_packages_total"], 4)
                    if SystemObservabilityService._metrics["evidence_packages_total"] > 0 else 0.0
                ),
                "reports_total": SystemObservabilityService._metrics["reports_total"],
                "report_generation_duration_average": (
                    round(SystemObservabilityService._metrics["report_generation_duration_sum"] / SystemObservabilityService._metrics["reports_total"], 4)
                    if SystemObservabilityService._metrics["reports_total"] > 0 else 0.0
                ),
                "exports_total": SystemObservabilityService._metrics["exports_total"],
                "complaint_drafts_total": SystemObservabilityService._metrics["complaint_drafts_total"],
                "lifecycle_transitions": SystemObservabilityService._metrics["incident_lifecycle_transitions"]
            },
            # Phase 10 details
            "dashboard_performance": {
                "total_loads": SystemObservabilityService._metrics["dashboard_loads_total"],
                "average_load_seconds": (
                    round(SystemObservabilityService._metrics["dashboard_load_duration_sum"] / SystemObservabilityService._metrics["dashboard_loads_total"], 4)
                    if SystemObservabilityService._metrics["dashboard_loads_total"] > 0 else 0.0
                ),
                "cache_hits": SystemObservabilityService._metrics["dashboard_cache_hits"],
                "cache_misses": SystemObservabilityService._metrics["dashboard_cache_misses"]
            }
        }

    @staticmethod
    async def get_prometheus_metrics() -> str:
        """Expose Prometheus formatted counter text."""
        report = await SystemObservabilityService.get_metrics_report()
        sys = report["system_status"]
        scans = report["security_scans"]
        cache = report["cache_performance"]
        ops = report["operations"]
        ai = report["attachment_intelligence"]
        
        lines = [
            "# HELP guardianmail_scans_total Total email security scans conducted.",
            "# TYPE guardianmail_scans_total counter",
            f"guardianmail_scans_total {scans['total_scans']}",
            "",
            "# HELP guardianmail_scan_duration_average_seconds Average processing duration of scanner.",
            "# TYPE guardianmail_scan_duration_average_seconds gauge",
            f"guardianmail_scan_duration_average_seconds {scans['average_duration_seconds']}",
            "",
            "# HELP guardianmail_heuristics_overrides_total Heuristics language style false positive overrides.",
            "# TYPE guardianmail_heuristics_overrides_total counter",
            f"guardianmail_heuristics_overrides_total {scans['heuristics_overrides_total']}",
            "",
            "# HELP guardianmail_cache_hits_total Total Redis cache key lookups successfully hit.",
            "# TYPE guardianmail_cache_hits_total counter",
            f"guardianmail_cache_hits_total {cache['hits']}",
            "",
            "# HELP guardianmail_cache_misses_total Total Redis cache key lookups missed.",
            "# TYPE guardianmail_cache_misses_total counter",
            f"guardianmail_cache_misses_total {cache['misses']}",
            "",
            "# HELP guardianmail_complaints_drafts_total Total abuse reports draft formats created.",
            "# TYPE guardianmail_complaints_drafts_total counter",
            f"guardianmail_complaints_drafts_total {ops['complaints_created']}",
            "",
            "# HELP guardianmail_database_healthy Status of MongoDB connectivity.",
            "# TYPE guardianmail_database_healthy gauge",
            f"guardianmail_database_healthy {1 if sys['mongodb_connected'] else 0}",
            "",
            "# HELP guardianmail_redis_healthy Status of Redis cache connection.",
            "# TYPE guardianmail_redis_healthy gauge",
            f"guardianmail_redis_healthy {1 if sys['redis_connected'] else 0}",
            "",
            "# HELP guardianmail_ocr_scans_total Total OCR scans conducted.",
            "# TYPE guardianmail_ocr_scans_total counter",
            f"guardianmail_ocr_scans_total {ai['ocr_scans_total']}",
            "",
            "# HELP guardianmail_ocr_duration_average_seconds Average processing duration of OCR scanner.",
            "# TYPE guardianmail_ocr_duration_average_seconds gauge",
            f"guardianmail_ocr_duration_average_seconds {ai['ocr_average_duration_seconds']}",
            "",
            "# HELP guardianmail_ocr_accuracy_average Average OCR accuracy ratio.",
            "# TYPE guardianmail_ocr_accuracy_average gauge",
            f"guardianmail_ocr_accuracy_average {ai['ocr_average_accuracy']}",
            "",
            "# HELP guardianmail_image_scans_total Total image security scans conducted.",
            "# TYPE guardianmail_image_scans_total counter",
            f"guardianmail_image_scans_total {ai['image_scans_total']}",
            "",
            "# HELP guardianmail_image_duration_average_seconds Average processing duration of image scanner.",
            "# TYPE guardianmail_image_duration_average_seconds gauge",
            f"guardianmail_image_duration_average_seconds {ai['image_average_duration_seconds']}",
            "",
            "# HELP guardianmail_qr_scans_total Total QR code security scans conducted.",
            "# TYPE guardianmail_qr_scans_total counter",
            f"guardianmail_qr_scans_total {ai['qr_scans_total']}",
            "",
            "# HELP guardianmail_qr_duration_average_seconds Average processing duration of QR scanner.",
            "# TYPE guardianmail_qr_duration_average_seconds gauge",
            f"guardianmail_qr_duration_average_seconds {ai['qr_average_duration_seconds']}",
            "",
            "# HELP guardianmail_qr_detected_total Total QR codes detected.",
            "# TYPE guardianmail_qr_detected_total counter",
            f"guardianmail_qr_detected_total {ai['qr_detected_total']}"
        ]
        
        ir = report["incident_response"]
        lines.extend([
            "",
            "# HELP guardianmail_evidence_packages_total Total evidence packages generated.",
            "# TYPE guardianmail_evidence_packages_total counter",
            f"guardianmail_evidence_packages_total {ir['evidence_packages_total']}",
            "",
            "# HELP guardianmail_evidence_generation_duration_average_seconds Average time to generate evidence package.",
            "# TYPE guardianmail_evidence_generation_duration_average_seconds gauge",
            f"guardianmail_evidence_generation_duration_average_seconds {ir['evidence_generation_duration_average']}",
            "",
            "# HELP guardianmail_reports_total Total PDF security reports generated.",
            "# TYPE guardianmail_reports_total counter",
            f"guardianmail_reports_total {ir['reports_total']}",
            "",
            "# HELP guardianmail_report_generation_duration_average_seconds Average time to generate PDF report.",
            "# TYPE guardianmail_report_generation_duration_average_seconds gauge",
            f"guardianmail_report_generation_duration_average_seconds {ir['report_generation_duration_average']}",
            "",
            "# HELP guardianmail_forensic_exports_total Total ZIP forensic packages downloaded/exported.",
            "# TYPE guardianmail_forensic_exports_total counter",
            f"guardianmail_forensic_exports_total {ir['exports_total']}",
            "",
            "# HELP guardianmail_complaint_drafts_total Total complaint drafts prepared.",
            "# TYPE guardianmail_complaint_drafts_total counter",
            f"guardianmail_complaint_drafts_total {ir['complaint_drafts_total']}"
        ])
        
        dp = report["dashboard_performance"]
        lines.extend([
            "",
            "# HELP guardianmail_dashboard_loads_total Total dashboard overview/analytics requests.",
            "# TYPE guardianmail_dashboard_loads_total counter",
            f"guardianmail_dashboard_loads_total {dp['total_loads']}",
            "",
            "# HELP guardianmail_dashboard_load_duration_average_seconds Average latency of dashboard loads.",
            "# TYPE guardianmail_dashboard_load_duration_average_seconds gauge",
            f"guardianmail_dashboard_load_duration_average_seconds {dp['average_load_seconds']}",
            "",
            "# HELP guardianmail_dashboard_cache_hits_total Total Redis dashboard cache lookups successfully hit.",
            "# TYPE guardianmail_dashboard_cache_hits_total counter",
            f"guardianmail_dashboard_cache_hits_total {dp['cache_hits']}",
            "",
            "# HELP guardianmail_dashboard_cache_misses_total Total Redis dashboard cache lookups missed.",
            "# TYPE guardianmail_dashboard_cache_misses_total counter",
            f"guardianmail_dashboard_cache_misses_total {dp['cache_misses']}"
        ])
        
        return "\n".join(lines)

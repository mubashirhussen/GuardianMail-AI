import csv
import json
import io
from typing import Dict, Any, List

class ReportGeneratorService:
    @staticmethod
    def export_json(email_record: Dict[str, Any]) -> str:
        """Compile a complete JSON evidence pack (Module 14)."""
        # Ensure clean serialization of ObjectIds and datetimes
        serializable = {}
        for k, v in email_record.items():
            if k == "_id":
                serializable["email_id"] = str(v)
            elif k == "date" or k == "sync_time":
                serializable[k] = v.isoformat() if hasattr(v, "isoformat") else str(v)
            elif k == "analysis" and "analysis_time" in v:
                serializable["analysis"] = v.copy()
                serializable["analysis"]["analysis_time"] = v["analysis_time"].isoformat() if hasattr(v["analysis_time"], "isoformat") else str(v["analysis_time"])
            else:
                serializable[k] = v
                
        return json.dumps(serializable, indent=2)

    @staticmethod
    def export_csv(email_records: List[Dict[str, Any]]) -> str:
        """Compile records into a CSV format representing threat metadata overview (Module 14)."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            "Email ID", "Subject", "Sender", "Date Mapped", "Risk Score", "Verdict", 
            "Authentication Failures count", "URL Count", "Attachment Count"
        ])
        
        for r in email_records:
            analysis = r.get("analysis", {})
            verdict = analysis.get("verdict", "UNANALYZED")
            score = int(analysis.get("risk_score", 0) * 100)
            
            # Auth failures count
            indicators = analysis.get("indicators", [])
            auth_failures = sum(1 for ind in indicators if "auth" in ind.get("indicator", "").lower() or "spf" in ind.get("indicator", "").lower())
            
            writer.writerow([
                str(r.get("_id", r.get("id"))),
                r.get("subject", "No Subject"),
                r.get("from_address", ""),
                r.get("date").isoformat() if hasattr(r.get("date"), "isoformat") else str(r.get("date")),
                score,
                verdict,
                auth_failures,
                len(r.get("urls", [])),
                len(r.get("attachments", []))
            ])
            
        return output.getvalue()

    @staticmethod
    def export_threat_report_text(email_record: Dict[str, Any]) -> str:
        """Compile a human-readable text threat report summary (Module 14)."""
        analysis = email_record.get("analysis", {})
        recs = email_record.get("recommendations", {})
        
        report = []
        report.append("=" * 70)
        report.append("         GUARDIANMAIL AI - INCIDENT EVIDENCE REPORT")
        report.append("=" * 70)
        report.append(f"Incident ID   : {str(email_record.get('_id'))}")
        report.append(f"Subject       : {email_record.get('subject')}")
        report.append(f"From Sender   : {email_record.get('from_address')}")
        report.append(f"Verdict       : {analysis.get('verdict')} ({int(analysis.get('risk_score', 0) * 100)}/100)")
        report.append("-" * 70)
        
        report.append("\n[AUTHENTICATION SIGNATURES]")
        auth = analysis.get("auth_status", {})
        report.append(f"  SPF: {auth.get('spf', 'N/A')} | DKIM: {auth.get('dkim', 'N/A')} | DMARC: {auth.get('dmarc', 'N/A')}")
        report.append(f"  Sender Alignment: {'Aligned' if auth.get('sender_alignment', True) else 'Mismatched'}")
        
        report.append("\n[IDENTIFIED RISK INDICATORS]")
        indicators = analysis.get("indicators", [])
        if indicators:
            for ind in indicators:
                report.append(f"  - [{ind.get('severity')}] {ind.get('indicator')}: {ind.get('detail')}")
        else:
            report.append("  No security warnings compiled.")
            
        report.append("\n[REMEDIATION SUGGESTIONS]")
        for sugg in recs.get("suggestions", []):
            report.append(f"  * {sugg}")
            
        report.append("\n[INCIDENT INVESTIGATION TIMELINE]")
        timeline = analysis.get("timeline", [])
        if timeline:
            for idx, event in enumerate(timeline):
                if hasattr(event, "timestamp"):
                    ts = event.timestamp
                    evt_name = event.event
                    evt_desc = event.description
                elif isinstance(event, dict):
                    ts = event.get("timestamp")
                    evt_name = event.get("event")
                    evt_desc = event.get("description")
                else:
                    continue
                    
                if hasattr(ts, "isoformat"):
                    ts_str = ts.isoformat()[:19]
                else:
                    ts_str = str(ts)[:19]
                report.append(f"  [{idx + 1}] {ts_str} - {evt_name}: {evt_desc}")
        else:
            report.append("  No timeline events compiled.")
            
        report.append("\n[EXPLAINABLE THREAT INTELLIGENCE EVIDENCE]")
        pos = analysis.get("positive_evidence", [])
        neg = analysis.get("negative_evidence", [])
        if pos:
            report.append("  Positive Evidence (Threat indicators):")
            for p in pos:
                report.append(f"    + {p}")
        if neg:
            report.append("  Negative Evidence (Safe indicators):")
            for n in neg:
                report.append(f"    - {n}")
        sources = analysis.get("detector_sources", [])
        if sources:
            report.append(f"  Triggered Detectors: {', '.join(sources)}")
            
        report.append("\n[SECURITY EXPLANATION]")
        report.append(recs.get("explanation", "No further explanation provided."))
        report.append("\n" + "=" * 70)
        
        return "\n".join(report)

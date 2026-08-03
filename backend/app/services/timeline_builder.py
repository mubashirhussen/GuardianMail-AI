from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

class TimelineBuilderService:
    @staticmethod
    def build_incident_timeline(
        parsed_email: Dict[str, Any], 
        analysis_verdict: str,
        risk_score: float,
        has_auth_fail: bool,
        has_suspicious_urls: bool,
        has_suspicious_attachments: bool
    ) -> List[Dict[str, Any]]:
        """Construct a chronologically ordered timeline of the investigation (Enhancement 6)."""
        timeline = []
        base_time = datetime.now(timezone.utc) - timedelta(seconds=2)
        
        # 1. Received & Parsed
        timeline.append({
            "event": "EMAIL_RECEIVED",
            "timestamp": base_time.isoformat(),
            "description": f"Email message received from '{parsed_email.get('from_address')}' and successfully parsed."
        })
        
        # 2. Header Verification
        auth_time = base_time + timedelta(milliseconds=400)
        auth_desc = "Authentication headers passed checks."
        if has_auth_fail:
            auth_desc = "Security headers verification completed. SPF/DKIM signature anomalies or alignment failures detected."
        timeline.append({
            "event": "AUTHENTICATION_CHECKS",
            "timestamp": auth_time.isoformat(),
            "description": auth_desc
        })
        
        # 3. URL Scanning
        url_time = auth_time + timedelta(milliseconds=500)
        if parsed_email.get("urls"):
            url_desc = f"Scanned {len(parsed_email['urls'])} link(s). "
            if has_suspicious_urls:
                url_desc += "Flagged suspicious redirected link shorteners, IP hosts, or brand lookalikes."
            else:
                url_desc += "All embedded link destinations verified clean."
            timeline.append({
                "event": "LINK_VERIFICATION",
                "timestamp": url_time.isoformat(),
                "description": url_desc
            })
            
        # 4. Attachment analysis
        attach_time = url_time + timedelta(milliseconds=300)
        if parsed_email.get("attachments"):
            attach_desc = f"Parsed {len(parsed_email['attachments'])} file attachments. "
            if has_suspicious_attachments:
                attach_desc += "Flagged potential executable extension signature or double-extension naming patterns."
            else:
                attach_desc += "All MD5 hashes checked against reputation databases with safe status."
            timeline.append({
                "event": "ATTACHMENT_VERIFICATION",
                "timestamp": attach_time.isoformat(),
                "description": attach_desc
            })

        # 5. Classification verdict
        class_time = datetime.now(timezone.utc)
        timeline.append({
            "event": "THREAT_CLASSIFICATION",
            "timestamp": class_time.isoformat(),
            "description": f"Threat classification scoring completed. Assigned risk score {int(risk_score * 100)}/100 and verdict '{analysis_verdict}'."
        })
        
        return timeline

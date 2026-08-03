import io
import csv
import json
import zipfile
import base64
import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
import pandas as pd

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from app.services.dashboard_service import DashboardService
from app.repositories.dashboard_repo import DashboardReportsRepository
from app.services.observability import SystemObservabilityService

logger = logging.getLogger(__name__)

class DashboardReportService:
    @staticmethod
    async def compile_report_data(
        db: AsyncIOMotorDatabase,
        report_type: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        user_id: Optional[str] = None,
        is_admin: bool = False
    ) -> Dict[str, Any]:
        """Fetch and aggregate the dataset required to compile the specified report type."""
        # Query overview, threat, and incident analytics using DashboardService
        overview = await DashboardService.get_overview_metrics(db, user_id=user_id, is_admin=is_admin)
        threats = await DashboardService.get_threat_analytics(db, user_id=user_id, is_admin=is_admin)
        incidents = await DashboardService.get_incident_analytics(db, user_id=user_id, is_admin=is_admin)

        # Build raw incident/threat history query
        query: Dict[str, Any] = {"soft_delete": False}
        if not is_admin and user_id:
            query["user_id"] = user_id
            
        date_filter: Dict[str, Any] = {}
        if start_date:
            date_filter["$gte"] = start_date
        if end_date:
            date_filter["$lte"] = end_date
        if date_filter:
            query["date"] = date_filter

        emails_cursor = db["emails"].find(query).sort("date", -1).limit(100)
        raw_emails = await emails_cursor.to_list(length=100)

        cleaned_emails = []
        for em in raw_emails:
            analysis = em.get("analysis", {})
            cleaned_emails.append({
                "email_id": str(em["_id"]),
                "subject": em.get("subject", "No Subject"),
                "sender": em.get("from_address", ""),
                "date": em.get("date").isoformat() if hasattr(em.get("date"), "isoformat") else str(em.get("date")),
                "verdict": analysis.get("verdict", "SAFE"),
                "risk_score": round((analysis.get("risk_score", 0.0)) * 100, 1),
                "is_phishing": analysis.get("is_phishing", False),
                "is_bec": analysis.get("is_bec", False),
                "is_malware": analysis.get("is_malware", False)
            })

        return {
            "report_type": report_type,
            "start_date": start_date.isoformat() if start_date else "inception",
            "end_date": end_date.isoformat() if end_date else "present",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overview": overview,
            "threats": threats,
            "incidents": incidents,
            "sample_email_records": cleaned_emails
        }

    @staticmethod
    def generate_pdf_bytes(report_data: Dict[str, Any]) -> bytes:
        """Compile a multi-page PDF layout representing the Dashboard security metrics report."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        story = []
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#1A365D"),
            spaceAfter=12
        )
        section_style = ParagraphStyle(
            'ReportSection',
            parent=styles['Heading2'],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#2B6CB0"),
            spaceBefore=14,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#2D3748")
        )

        # Header Title
        story.append(Paragraph(f"GUARDIANMAIL AI - SECURITY REPORT ({report_data['report_type'].upper()})", title_style))
        story.append(Paragraph(f"<b>Reporting Scope:</b> {report_data['start_date']} to {report_data['end_date']} | <b>Generated:</b> {report_data['generated_at']}", body_style))
        story.append(Spacer(1, 10))

        # 1. Executive Summary Table
        story.append(Paragraph("Executive Summary Stats", section_style))
        ov = report_data["overview"]
        summary_data = [
            [Paragraph("<b>Metric</b>", body_style), Paragraph("<b>Value</b>", body_style), Paragraph("<b>Metric</b>", body_style), Paragraph("<b>Value</b>", body_style)],
            [Paragraph("Total Scans", body_style), Paragraph(str(ov.get("total_emails", 0)), body_style), Paragraph("Average Protection Score", body_style), Paragraph(f"{ov.get('avg_protection_score')}%", body_style)],
            [Paragraph("Phishing Emails", body_style), Paragraph(str(ov.get("phishing_emails", 0)), body_style), Paragraph("Average Risk Score", body_style), Paragraph(f"{ov.get('avg_risk_score')}%", body_style)],
            [Paragraph("Safe Emails", body_style), Paragraph(str(ov.get("safe_emails", 0)), body_style), Paragraph("Detection Accuracy", body_style), Paragraph(f"{ov.get('detection_accuracy')}%", body_style)]
        ]
        t = Table(summary_data, colWidths=[130, 120, 150, 100])
        t.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#EDF2F7")),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t)
        story.append(Spacer(1, 10))

        # 2. Threat Severity and Distributions
        story.append(Paragraph("Threat Category Breakdown", section_style))
        threats = report_data["threats"]
        severity_dist = threats.get("severity_distribution", {})
        sev_rows = [[Paragraph("<b>Verdict Severity</b>", body_style), Paragraph("<b>Volume Scanned</b>", body_style)]]
        for k, v in severity_dist.items():
            sev_rows.append([Paragraph(k, body_style), Paragraph(str(v), body_style)])
        t_sev = Table(sev_rows, colWidths=[200, 200])
        t_sev.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#EDF2F7")),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_sev)
        story.append(Spacer(1, 10))

        # 3. Sample Threat Detections
        story.append(Paragraph("Threat Activity Logs (Recent Scans)", section_style))
        records = report_data["sample_email_records"]
        if records:
            rec_rows = [[Paragraph("<b>Sender</b>", body_style), Paragraph("<b>Subject</b>", body_style), Paragraph("<b>Verdict</b>", body_style), Paragraph("<b>Risk %</b>", body_style)]]
            for r in records[:10]:
                rec_rows.append([
                    Paragraph(r["sender"][:25], body_style),
                    Paragraph(r["subject"][:35], body_style),
                    Paragraph(r["verdict"], body_style),
                    Paragraph(str(r["risk_score"]), body_style)
                ])
            t_rec = Table(rec_rows, colWidths=[120, 180, 100, 100])
            t_rec.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#EDF2F7")),
                ('PADDING', (0,0), (-1,-1), 3),
            ]))
            story.append(t_rec)
        else:
            story.append(Paragraph("No threat records mapped in this range.", body_style))

        doc.build(story)
        return buffer.getvalue()

    @staticmethod
    def generate_excel_bytes(report_data: Dict[str, Any]) -> bytes:
        """Compile a multi-tab Excel spreadsheet workbook using pandas and openpyxl."""
        output = io.BytesIO()
        writer = pd.ExcelWriter(output, engine="openpyxl")
        
        # 1. Summary sheet
        ov = report_data["overview"]
        summary_df = pd.DataFrame([
            {"Metric": "Total Emails Scanned", "Value": ov.get("total_emails")},
            {"Metric": "Safe Emails", "Value": ov.get("safe_emails")},
            {"Metric": "Suspicious Emails", "Value": ov.get("suspicious_emails")},
            {"Metric": "Phishing Threats", "Value": ov.get("phishing_emails")},
            {"Metric": "BEC Detections", "Value": ov.get("bec_emails")},
            {"Metric": "Malicious Attachments", "Value": ov.get("malicious_attachments")},
            {"Metric": "Malicious URLs", "Value": ov.get("malicious_urls")},
            {"Metric": "Average Protection Score", "Value": f"{ov.get('avg_protection_score')}%"},
            {"Metric": "Average Risk Score", "Value": f"{ov.get('avg_risk_score')}%"},
            {"Metric": "Detection Accuracy", "Value": f"{ov.get('detection_accuracy')}%"}
        ])
        summary_df.to_excel(writer, sheet_name="Overview Summary", index=False)

        # 2. Email Scans list sheet
        records = report_data["sample_email_records"]
        records_df = pd.DataFrame(records) if records else pd.DataFrame(columns=["email_id", "sender", "subject", "date", "verdict", "risk_score"])
        records_df.to_excel(writer, sheet_name="Threat Scans Log", index=False)

        # 3. Severity sheets
        threats = report_data["threats"]
        sev_df = pd.DataFrame([{"Severity": k, "Volume": v} for k, v in threats.get("severity_distribution", {}).items()])
        sev_df.to_excel(writer, sheet_name="Severity Distribution", index=False)

        writer.close()
        return output.getvalue()

    @staticmethod
    def generate_csv_string(report_data: Dict[str, Any]) -> str:
        """Generate a flat CSV summary of email scans."""
        records = report_data["sample_email_records"]
        df = pd.DataFrame(records) if records else pd.DataFrame(columns=["email_id", "sender", "subject", "date", "verdict", "risk_score"])
        return df.to_csv(index=False)

    @staticmethod
    async def create_and_store_report(
        db: AsyncIOMotorDatabase,
        report_type: str,
        export_format: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        created_by: str = "system",
        user_id: Optional[str] = None,
        is_admin: bool = False
    ) -> Dict[str, Any]:
        """Run aggregation services, build PDF/Excel/CSV binary assets, and insert metadata in MongoDB."""
        start_time = datetime.now(timezone.utc)
        
        # 1. Gather all report source data
        report_data = await DashboardReportService.compile_report_data(
            db=db,
            report_type=report_type,
            start_date=start_date,
            end_date=end_date,
            user_id=user_id,
            is_admin=is_admin
        )
        
        # 2. Compile document depending on format
        payload_bytes = b""
        if export_format == "pdf":
            payload_bytes = DashboardReportService.generate_pdf_bytes(report_data)
        elif export_format == "xlsx" or export_format == "excel":
            export_format = "xlsx" # normalize
            payload_bytes = DashboardReportService.generate_excel_bytes(report_data)
        elif export_format == "csv":
            payload_bytes = DashboardReportService.generate_csv_string(report_data).encode("utf-8")
        elif export_format == "json":
            payload_bytes = json.dumps(report_data, indent=2).encode("utf-8")
        elif export_format == "zip":
            # Packaging ZIP containing PDF, CSV, XLSX, and JSON
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("report.pdf", DashboardReportService.generate_pdf_bytes(report_data))
                z.writestr("report.csv", DashboardReportService.generate_csv_string(report_data).encode("utf-8"))
                z.writestr("report.xlsx", DashboardReportService.generate_excel_bytes(report_data))
                z.writestr("report.json", json.dumps(report_data, indent=2).encode("utf-8"))
            payload_bytes = zip_buffer.getvalue()
        else:
            raise ValueError(f"Unsupported report export format: {export_format}")

        # 3. Base64 payload storage
        payload_b64 = base64.b64encode(payload_bytes).decode("utf-8")
        
        # Generate unique report reference code
        report_num = f"REP-{datetime.now(timezone.utc).year}-{hashlib.md5(payload_bytes).hexdigest()[:8].upper()}" if payload_bytes else f"REP-{datetime.now(timezone.utc).year}-DEFAULT"

        report_record = {
            "report_id": report_num,
            "report_type": report_type,
            "export_format": export_format,
            "parameters": {
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None,
                "scope_user_id": user_id
            },
            "content_payload": payload_b64,
            "file_size_bytes": len(payload_bytes),
            "created_by": created_by,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "soft_delete": False
        }

        # Save to database
        reports_repo = DashboardReportsRepository(db)
        created_report = await reports_repo.create(report_record)
        
        # Log latency metric
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        SystemObservabilityService.record_report_gen(duration)

        created_report["_id"] = str(created_report["_id"])
        # Return binary bytes alongside metadata
        return {
            "report_metadata": created_report,
            "binary_payload": payload_bytes
        }

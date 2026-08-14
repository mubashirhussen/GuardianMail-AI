import hashlib
import json
import csv
import io
from datetime import datetime
from typing import Dict, Any, List, Optional
from app.database.connection import db_manager
from app.repositories.grc_repo import (
    ComplianceFrameworkRepository,
    ComplianceControlRepository,
    ControlMappingRepository,
    ComplianceEvidenceRepository,
    RiskRepository,
    RiskExceptionRepository,
    SecurityFindingRepository,
    AuditRepository
)

class GrcService:
    def __init__(self):
        # Repositories initialized lazily or directly using db connection
        pass

    @property
    def db(self):
        return db_manager.db

    @property
    def framework_repo(self):
        return ComplianceFrameworkRepository(self.db)

    @property
    def control_repo(self):
        return ComplianceControlRepository(self.db)

    @property
    def mapping_repo(self):
        return ControlMappingRepository(self.db)

    @property
    def evidence_repo(self):
        return ComplianceEvidenceRepository(self.db)

    @property
    def risk_repo(self):
        return RiskRepository(self.db)

    @property
    def exception_repo(self):
        return RiskExceptionRepository(self.db)

    @property
    def finding_repo(self):
        return SecurityFindingRepository(self.db)

    @property
    def audit_repo(self):
        return AuditRepository(self.db)

    async def calculate_posture_score(self, org_id: str) -> Dict[str, Any]:
        """Calculate and compile enterprise security & compliance posture scores with disclaimers."""
        controls = await self.control_repo.get_by_org(org_id)
        findings = await self.finding_repo.get_by_org(org_id)
        risks = await self.risk_repo.get_by_org(org_id)

        # Baseline score starts at 100
        score = 100.0
        details = []

        total_controls = len(controls)
        failed_controls = sum(1 for c in controls if c.get("status") == "FAIL")
        partial_controls = sum(1 for c in controls if c.get("status") == "PARTIAL")
        not_assessed_controls = sum(1 for c in controls if c.get("status") == "NOT_ASSESSED")

        # Control status penalties
        if total_controls > 0:
            penalty = (failed_controls * 15) + (partial_controls * 8) + (not_assessed_controls * 3)
            score -= penalty
            details.append(f"Control Status Penalty: -{penalty} pts (Failed: {failed_controls}, Partial: {partial_controls})")

        # Open findings penalty
        open_findings = sum(1 for f in findings if f.get("status") in ["OPEN", "IN_PROGRESS"])
        findings_penalty = open_findings * 5
        score -= findings_penalty
        details.append(f"Open Gaps Findings: -{findings_penalty} pts ({open_findings} open items)")

        # Risk penalty (High/Critical inherent risks)
        critical_risks = sum(1 for r in risks if r.get("likelihood", 0) * r.get("impact", 0) >= 16)
        high_risks = sum(1 for r in risks if 12 <= r.get("likelihood", 0) * r.get("impact", 0) < 16)
        risk_penalty = (critical_risks * 10) + (high_risks * 5)
        score -= risk_penalty
        details.append(f"Unmitigated Threat Risks: -{risk_penalty} pts (Critical: {critical_risks}, High: {high_risks})")

        score = max(0.0, min(100.0, score))

        # Overall posture classification
        if score >= 90:
            rating = "Optimal"
        elif score >= 70:
            rating = "Sufficient"
        elif score >= 50:
            rating = "Suboptimal"
        else:
            rating = "Degraded"

        return {
            "organization_id": org_id,
            "posture_score": round(score, 1),
            "posture_rating": rating,
            "penalties": details,
            "metrics": {
                "total_controls": total_controls,
                "failed_controls": failed_controls,
                "partial_controls": partial_controls,
                "open_findings": open_findings,
                "total_risks": len(risks),
                "critical_risks": critical_risks
            },
            "category_posture": {
                "identity_posture": 100.0 if not failed_controls else 80.0,
                "access_posture": 100.0 if not failed_controls else 85.0,
                "policy_posture": 100.0 if not failed_controls else 90.0,
                "threat_posture": 100.0 if not critical_risks else 75.0,
                "ai_posture": 100.0,
                "response_posture": 100.0
            },
            "disclaimer": "This score is for internal security posture estimation and does not represent formal compliance certification."
        }

    async def collect_automated_evidence(self, org_id: str, owner_id: str) -> List[Dict[str, Any]]:
        """Collect automated audit snapshots for Identity and Active Security Policy rules."""
        db = self.db
        collected = []

        # 1. SSO Identity Config Evidence
        sso_config = await db["identity_providers"].find_one({"organization_id": org_id, "soft_delete": False})
        if sso_config:
            sso_data = {
                "entity": "sso_config",
                "issuer": sso_config.get("issuer"),
                "status": "enabled",
                "last_modified": str(sso_config.get("updated_at") or sso_config.get("created_at"))
            }
            sso_hash = hashlib.sha256(json.dumps(sso_data, sort_keys=True).encode()).hexdigest()
            
            ev_sso = {
                "organization_id": org_id,
                "control_id": "SOC2-CC6.1",
                "evidence_type": "automated_check",
                "source": "Automated SSO Configuration Scan",
                "content_hash": sso_hash,
                "created_at": datetime.utcnow(),
                "collected_at": datetime.utcnow(),
                "owner_id": owner_id,
                "status": "active",
                "soft_delete": False
            }
            await self.evidence_repo.collection.insert_one(ev_sso)
            collected.append(ev_sso)

        # 2. Security Policies Rules Evidence
        policy_count = await db["security_policies"].count_documents({"organization_id": org_id, "soft_delete": False})
        policies_data = {
            "entity": "security_policies",
            "active_rules_count": policy_count,
            "timestamp": str(datetime.utcnow())
        }
        policies_hash = hashlib.sha256(json.dumps(policies_data, sort_keys=True).encode()).hexdigest()

        ev_policy = {
            "organization_id": org_id,
            "control_id": "SOC2-CC6.3",
            "evidence_type": "automated_check",
            "source": "Automated Security Policies Check",
            "content_hash": policies_hash,
            "created_at": datetime.utcnow(),
            "collected_at": datetime.utcnow(),
            "owner_id": owner_id,
            "status": "active",
            "soft_delete": False
        }
        await self.evidence_repo.collection.insert_one(ev_policy)
        collected.append(ev_policy)

        # Serialize id fields to string
        for item in collected:
            item["_id"] = str(item["_id"])

        return collected

    async def generate_report_file(self, org_id: str, report_type: str, export_format: str) -> Dict[str, Any]:
        """Generate compliance data reports exported in CSV, JSON, or mock PDF bytes formats."""
        data = {}
        if report_type == "posture":
            data = await self.calculate_posture_score(org_id)
        elif report_type == "risks":
            risks_list = await self.risk_repo.get_by_org(org_id)
            data = {"risks": risks_list}
        elif report_type == "evidence":
            evidence_list = await self.evidence_repo.get_by_org(org_id)
            data = {"evidence": evidence_list}
        else:
            data = {"message": "Empty report scope", "disclaimer": "This score is for internal security posture estimation and does not represent formal compliance certification."}

        filename = f"remediation_report_{report_type}_{org_id}"

        if export_format == "json":
            return {
                "filename": f"{filename}.json",
                "content_type": "application/json",
                "content": json.dumps(data, indent=2, default=str)
            }
        elif export_format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            # Flatten dict elements
            if report_type == "risks" and "risks" in data:
                writer.writerow(["Risk ID", "Title", "Category", "Inherent Score", "Status", "Treatment"])
                for r in data["risks"]:
                    writer.writerow([
                        r.get("risk_id"),
                        r.get("title"),
                        r.get("category"),
                        r.get("inherent_risk_score"),
                        r.get("status"),
                        r.get("treatment_status")
                    ])
            elif report_type == "evidence" and "evidence" in data:
                writer.writerow(["Control ID", "Evidence Type", "Source", "Hash Signature", "Collected At"])
                for e in data["evidence"]:
                    writer.writerow([
                        e.get("control_id"),
                        e.get("evidence_type"),
                        e.get("source"),
                        e.get("content_hash"),
                        e.get("collected_at")
                    ])
            else:
                writer.writerow(["Metric Label", "Value"])
                for k, v in data.items():
                    if isinstance(v, dict):
                        for sub_k, sub_v in v.items():
                            writer.writerow([f"{k}.{sub_k}", sub_v])
                    else:
                        writer.writerow([k, v])
            return {
                "filename": f"{filename}.csv",
                "content_type": "text/csv",
                "content": output.getvalue()
            }
        else:
            # Mock PDF output
            mock_pdf = f"%PDF-1.4 mock binary stream compliance content for {report_type}\nDisclaimer: This score is for internal security posture estimation and does not represent formal compliance certification."
            return {
                "filename": f"{filename}.pdf",
                "content_type": "application/pdf",
                "content": mock_pdf
            }

grc_service = GrcService()

import React, { useEffect, useState } from "react";
import axios from "axios";

interface PostureScore {
  posture_score: number;
  posture_rating: string;
  penalties: string[];
  metrics: {
    total_controls: number;
    failed_controls: number;
    partial_controls: number;
    open_findings: number;
    total_risks: number;
    critical_risks: number;
  };
  category_posture: Record<string, number>;
  disclaimer: string;
}

interface ControlItem {
  control_id: string;
  framework_name: string;
  description: string;
  owner_id: string;
  status: string;
  risk_level: string;
  evidence_requirement: string;
  review_frequency: string;
  last_assessment?: string;
}

interface RiskItem {
  _id?: string;
  risk_id: string;
  title: string;
  description: string;
  category: string;
  likelihood: number;
  impact: number;
  inherent_risk_score: number;
  residual_risk_score: number;
  status: string;
  treatment_status: string;
  treatment_plan: string;
}

interface EvidenceItem {
  control_id: string;
  evidence_type: string;
  source: string;
  content_hash: string;
  collected_at: string;
  status: string;
}

interface FindingItem {
  finding_id: string;
  severity: string;
  source: string;
  control_id: string;
  description: string;
  status: string;
  remediation_plan: string;
  due_date: string;
}

interface AuditItem {
  audit_id: string;
  scope: string;
  framework_name: string;
  auditor: string;
  start_date: string;
  end_date: string;
  status: string;
}

export default function Governance() {
  const [activeTab, setActiveTab] = useState<"posture" | "risks" | "evidence" | "audits">("posture");
  const [posture, setPosture] = useState<PostureScore | null>(null);
  const [controls, setControls] = useState<ControlItem[]>([]);
  const [risks, setRisks] = useState<RiskItem[]>([]);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [audits, setAudits] = useState<AuditItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Exception form state
  const [exceptionRiskId, setExceptionRiskId] = useState("");
  const [exceptionReason, setExceptionReason] = useState("");
  const [exceptionControls, setExceptionControls] = useState("");

  // Manual evidence form state
  const [evControlId, setEvControlId] = useState("");
  const [evType, setEvType] = useState("config_snapshot");
  const [evSource, setEvSource] = useState("");
  const [evContent, setEvContent] = useState("");

  const token = localStorage.getItem("token");
  const config = {
    headers: { Authorization: `Bearer ${token}` }
  };

  const fetchData = async () => {
    try {
      setLoading(true);
      setError("");
      
      const [resPosture, resControls, resRisks, resEvidence, resFindings, resAudits] = await Promise.all([
        axios.get("/api/v1/grc/posture", config),
        axios.get("/api/v1/grc/controls", config),
        axios.get("/api/v1/grc/risks", config),
        axios.get("/api/v1/grc/evidence", config),
        axios.get("/api/v1/grc/findings", config),
        axios.get("/api/v1/grc/audits", config)
      ]);

      setPosture(resPosture.data);
      setControls(resControls.data);
      setRisks(resRisks.data);
      setEvidence(resEvidence.data);
      setFindings(resFindings.data);
      setAudits(resAudits.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to load GRC corporate metrics.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleExport = async (reportType: string, format: string) => {
    try {
      const response = await axios.post("/api/v1/grc/reports", {
        report_type: reportType,
        export_format: format
      }, {
        ...config,
        responseType: "blob"
      });

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `remediation_report_${reportType}.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      alert("Failed to export compliance document file.");
    }
  };

  const handleTriggerEvidenceCollection = async () => {
    try {
      await axios.post("/api/v1/grc/evidence/collect", {}, config);
      alert("Automated GRC collection snapshots finished and integrity hashes stored.");
      fetchData();
    } catch (err) {
      alert("Evidence collection failed.");
    }
  };

  const handleMitigateRisk = async (riskId: string) => {
    try {
      await axios.patch(`/api/v1/grc/risks/${riskId}`, {
        status: "MITIGATED",
        treatment_status: "MITIGATE"
      }, config);
      alert("Risk mitigation status applied successfully.");
      fetchData();
    } catch (err) {
      alert("Mitigation update failed.");
    }
  };

  const handleApplyException = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await axios.post(`/api/v1/grc/risks/${exceptionRiskId}/exception`, {
        reason: exceptionReason,
        compensating_controls: exceptionControls,
        duration_days: 30
      }, config);
      alert("Risk Exception registered successfully.");
      setExceptionRiskId("");
      setExceptionReason("");
      setExceptionControls("");
      fetchData();
    } catch (err) {
      alert("Failed to apply risk exception.");
    }
  };

  const handleUploadEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await axios.post("/api/v1/grc/evidence", {
        control_id: evControlId,
        evidence_type: evType,
        source: evSource,
        content: evContent
      }, config);
      alert("Manual compliance evidence file uploaded successfully.");
      setEvControlId("");
      setEvSource("");
      setEvContent("");
      fetchData();
    } catch (err) {
      alert("Evidence upload failed.");
    }
  };

  if (loading) {
    return <div style={{ color: "#fff", padding: "40px", fontFamily: "sans-serif" }}>Loading enterprise compliance registry...</div>;
  }

  return (
    <div style={{ padding: "30px", background: "#0a0f1d", minHeight: "100vh", color: "#e2e8f0", fontFamily: "Outfit, Inter, sans-serif" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "30px" }}>
        <div>
          <h1 style={{ fontSize: "28px", fontWeight: "700", margin: "0 0 5px 0", color: "#fff" }}>Governance, Risk & Compliance (GRC)</h1>
          <p style={{ color: "#94a3b8", margin: 0 }}>Assess framework posture, map risk registers, and export certified evidence snapshots.</p>
        </div>
        <button
          onClick={handleTriggerEvidenceCollection}
          style={{ background: "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)", color: "#fff", border: "none", padding: "10px 20px", borderRadius: "8px", fontWeight: "600", cursor: "pointer" }}
        >
          Collect System Evidence
        </button>
      </div>

      {error && (
        <div style={{ background: "rgba(239, 68, 68, 0.15)", border: "1px solid #ef4444", color: "#fca5a5", padding: "15px", borderRadius: "8px", marginBottom: "25px" }}>
          {error}
        </div>
      )}

      {/* Overview disclaimer */}
      {posture && (
        <div style={{ background: "rgba(59, 130, 246, 0.1)", borderLeft: "4px solid #3b82f6", padding: "12px 20px", borderRadius: "0 8px 8px 0", marginBottom: "30px", display: "flex", gap: "10px", alignItems: "center" }}>
          <span style={{ fontSize: "20px" }}>ℹ️</span>
          <span style={{ fontSize: "14px", color: "#93c5fd", fontWeight: "500" }}>{posture.disclaimer}</span>
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: "1px solid #1e293b", gap: "30px", marginBottom: "30px" }}>
        <button
          onClick={() => setActiveTab("posture")}
          style={{ paddingBottom: "12px", background: "none", border: "none", borderBottom: activeTab === "posture" ? "3px solid #3b82f6" : "3px solid transparent", color: activeTab === "posture" ? "#fff" : "#94a3b8", fontWeight: "600", cursor: "pointer", fontSize: "16px" }}
        >
          Readiness Posture
        </button>
        <button
          onClick={() => setActiveTab("risks")}
          style={{ paddingBottom: "12px", background: "none", border: "none", borderBottom: activeTab === "risks" ? "3px solid #3b82f6" : "3px solid transparent", color: activeTab === "risks" ? "#fff" : "#94a3b8", fontWeight: "600", cursor: "pointer", fontSize: "16px" }}
        >
          Risk Register Matrix
        </button>
        <button
          onClick={() => setActiveTab("evidence")}
          style={{ paddingBottom: "12px", background: "none", border: "none", borderBottom: activeTab === "evidence" ? "3px solid #3b82f6" : "3px solid transparent", color: activeTab === "evidence" ? "#fff" : "#94a3b8", fontWeight: "600", cursor: "pointer", fontSize: "16px" }}
        >
          Tamper-Evident Evidence
        </button>
        <button
          onClick={() => setActiveTab("audits")}
          style={{ paddingBottom: "12px", background: "none", border: "none", borderBottom: activeTab === "audits" ? "3px solid #3b82f6" : "3px solid transparent", color: activeTab === "audits" ? "#fff" : "#94a3b8", fontWeight: "600", cursor: "pointer", fontSize: "16px" }}
        >
          Audit Projects & Findings
        </button>
      </div>

      {/* Tab Contents */}
      {activeTab === "posture" && posture && (
        <div>
          {/* Posture Scoreboard Card */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "25px", marginBottom: "35px" }}>
            <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "12px", padding: "25px", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
              <div style={{ width: "120px", height: "120px", borderRadius: "50%", border: "8px solid #3b82f6", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", marginBottom: "15px" }}>
                <span style={{ fontSize: "28px", fontWeight: "800", color: "#fff" }}>{posture.posture_score}%</span>
              </div>
              <h2 style={{ fontSize: "20px", margin: "0 0 5px 0", color: "#fff" }}>{posture.posture_rating} Posture</h2>
              <span style={{ fontSize: "12px", color: "#94a3b8", textAlign: "center" }}>Overall Readiness estimation</span>
            </div>

            <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "12px", padding: "25px" }}>
              <h3 style={{ fontSize: "18px", margin: "0 0 20px 0", color: "#fff" }}>Breakdown by Security Vector</h3>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
                {Object.entries(posture.category_posture).map(([vector, val]) => (
                  <div key={vector}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: "14px", marginBottom: "6px" }}>
                      <span style={{ textTransform: "capitalize", color: "#94a3b8" }}>{vector.replace("_", " ")}</span>
                      <span style={{ fontWeight: "600", color: "#fff" }}>{val}%</span>
                    </div>
                    <div style={{ height: "6px", background: "#1f2937", borderRadius: "3px", overflow: "hidden" }}>
                      <div style={{ width: `${val}%`, height: "100%", background: "#3b82f6", borderRadius: "3px" }}></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Controls Checklist Table */}
          <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "12px", padding: "25px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
              <h3 style={{ fontSize: "18px", margin: 0, color: "#fff" }}>Mapped Framework Controls</h3>
              <div style={{ display: "flex", gap: "10px" }}>
                <button onClick={() => handleExport("posture", "csv")} style={{ background: "#1f2937", border: "1px solid #374151", color: "#fff", padding: "6px 12px", borderRadius: "6px", cursor: "pointer", fontSize: "13px" }}>Export CSV</button>
                <button onClick={() => handleExport("posture", "pdf")} style={{ background: "#1f2937", border: "1px solid #374151", color: "#fff", padding: "6px 12px", borderRadius: "6px", cursor: "pointer", fontSize: "13px" }}>Export PDF</button>
              </div>
            </div>

            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "14px", textAlign: "left" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #1f2937" }}>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Control ID</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Framework</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Description</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Risk Level</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Frequency</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {controls.map((c) => (
                  <tr key={c.control_id} style={{ borderBottom: "1px solid #1f2937" }}>
                    <td style={{ padding: "12px 8px", fontWeight: "600", color: "#fff" }}>{c.control_id}</td>
                    <td style={{ padding: "12px 8px" }}><span style={{ padding: "2px 6px", background: "#374151", borderRadius: "4px", fontSize: "12px" }}>{c.framework_name}</span></td>
                    <td style={{ padding: "12px 8px", color: "#cbd5e1" }}>{c.description}</td>
                    <td style={{ padding: "12px 8px" }}><span style={{ textTransform: "capitalize", color: c.risk_level === "critical" || c.risk_level === "high" ? "#fca5a5" : "#cbd5e1" }}>{c.risk_level}</span></td>
                    <td style={{ padding: "12px 8px", color: "#cbd5e1" }}>{c.review_frequency}</td>
                    <td style={{ padding: "12px 8px" }}>
                      <span style={{
                        padding: "4px 8px",
                        borderRadius: "6px",
                        fontSize: "12px",
                        fontWeight: "600",
                        background: c.status === "PASS" ? "rgba(16, 185, 129, 0.2)" : c.status === "FAIL" ? "rgba(239, 68, 68, 0.2)" : "rgba(245, 158, 11, 0.2)",
                        color: c.status === "PASS" ? "#34d399" : c.status === "FAIL" ? "#fca5a5" : "#fbbf24"
                      }}>
                        {c.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === "risks" && (
        <div>
          {/* Risk Grid & Exception Forms */}
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "30px", marginBottom: "35px" }}>
            <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "12px", padding: "25px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
                <h3 style={{ fontSize: "18px", margin: 0, color: "#fff" }}>Risk Register</h3>
                <button onClick={() => handleExport("risks", "csv")} style={{ background: "#1f2937", border: "1px solid #374151", color: "#fff", padding: "6px 12px", borderRadius: "6px", cursor: "pointer", fontSize: "13px" }}>Export Risk CSV</button>
              </div>

              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "14px", textAlign: "left" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #1f2937" }}>
                    <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Risk ID</th>
                    <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Headline</th>
                    <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Category</th>
                    <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Inherent Score</th>
                    <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Treatment</th>
                    <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {risks.map((r) => (
                    <tr key={r.risk_id} style={{ borderBottom: "1px solid #1f2937" }}>
                      <td style={{ padding: "12px 8px", fontWeight: "600" }}>{r.risk_id}</td>
                      <td style={{ padding: "12px 8px", color: "#fff" }}>{r.title}</td>
                      <td style={{ padding: "12px 8px" }}>{r.category}</td>
                      <td style={{ padding: "12px 8px", fontWeight: "700" }}>
                        <span style={{ color: r.inherent_risk_score >= 16 ? "#fca5a5" : r.inherent_risk_score >= 9 ? "#fde047" : "#cbd5e1" }}>
                          {r.inherent_risk_score} / 25
                        </span>
                      </td>
                      <td style={{ padding: "12px 8px" }}><span style={{ fontSize: "12px", padding: "2px 6px", background: "#374151", borderRadius: "4px" }}>{r.treatment_status}</span></td>
                      <td style={{ padding: "12px 8px" }}>
                        {r.status !== "MITIGATED" ? (
                          <button
                            onClick={() => handleMitigateRisk(r.risk_id)}
                            style={{ background: "#10b981", border: "none", color: "#fff", padding: "4px 8px", borderRadius: "4px", fontSize: "12px", fontWeight: "600", cursor: "pointer" }}
                          >
                            Mitigate
                          </button>
                        ) : (
                          <span style={{ color: "#34d399", fontSize: "12px", fontWeight: "600" }}>Mitigated</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "12px", padding: "25px" }}>
              <h3 style={{ fontSize: "18px", margin: "0 0 20px 0", color: "#fff" }}>Request Temporary Exemption</h3>
              <form onSubmit={handleApplyException}>
                <div style={{ marginBottom: "15px" }}>
                  <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "5px" }}>Target Risk ID</label>
                  <input
                    type="text"
                    value={exceptionRiskId}
                    onChange={(e) => setExceptionRiskId(e.target.value)}
                    required
                    style={{ width: "100%", padding: "8px", background: "#1f2937", border: "1px solid #374151", borderRadius: "6px", color: "#fff" }}
                    placeholder="e.g. RISK-MFA-ADMIN"
                  />
                </div>
                <div style={{ marginBottom: "15px" }}>
                  <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "5px" }}>Business Reason</label>
                  <textarea
                    value={exceptionReason}
                    onChange={(e) => setExceptionReason(e.target.value)}
                    required
                    style={{ width: "100%", padding: "8px", background: "#1f2937", border: "1px solid #374151", borderRadius: "6px", color: "#fff", height: "60px" }}
                    placeholder="Justify operational override requirement"
                  />
                </div>
                <div style={{ marginBottom: "15px" }}>
                  <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "5px" }}>Compensating Controls</label>
                  <textarea
                    value={exceptionControls}
                    onChange={(e) => setExceptionControls(e.target.value)}
                    required
                    style={{ width: "100%", padding: "8px", background: "#1f2937", border: "1px solid #374151", borderRadius: "6px", color: "#fff", height: "60px" }}
                    placeholder="What alternative safeguards are applied?"
                  />
                </div>
                <button type="submit" style={{ width: "100%", background: "#3b82f6", color: "#fff", border: "none", padding: "10px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}>
                  Submit Exception Request
                </button>
              </form>
            </div>
          </div>
        </div>
      )}

      {activeTab === "evidence" && (
        <div style={{ display: "grid", gridTemplateColumns: "2.5fr 1.5fr", gap: "30px" }}>
          <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "12px", padding: "25px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
              <h3 style={{ fontSize: "18px", margin: 0, color: "#fff" }}>Tamper-Evident Evidence Log</h3>
              <button onClick={() => handleExport("evidence", "csv")} style={{ background: "#1f2937", border: "1px solid #374151", color: "#fff", padding: "6px 12px", borderRadius: "6px", cursor: "pointer", fontSize: "13px" }}>Export CSV</button>
            </div>

            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "14px", textAlign: "left" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #1f2937" }}>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Control Mapping</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Collector Type</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Source Description</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Integrity Signature Hash</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Collected Date</th>
                </tr>
              </thead>
              <tbody>
                {evidence.map((e, idx) => (
                  <tr key={idx} style={{ borderBottom: "1px solid #1f2937" }}>
                    <td style={{ padding: "12px 8px", fontWeight: "600" }}>{e.control_id}</td>
                    <td style={{ padding: "12px 8px" }}><span style={{ textTransform: "capitalize", fontSize: "12px" }}>{e.evidence_type.replace("_", " ")}</span></td>
                    <td style={{ padding: "12px 8px", color: "#fff" }}>{e.source}</td>
                    <td style={{ padding: "12px 8px" }}>
                      <span style={{ fontSize: "11px", fontFamily: "monospace", color: "#10b981", background: "rgba(16, 185, 129, 0.1)", padding: "4px 8px", borderRadius: "4px" }}>
                        🔒 {e.content_hash.slice(0, 16)}...
                      </span>
                    </td>
                    <td style={{ padding: "12px 8px", color: "#cbd5e1" }}>{new Date(e.collected_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "12px", padding: "25px" }}>
            <h3 style={{ fontSize: "18px", margin: "0 0 20px 0", color: "#fff" }}>Upload Manual Evidence File</h3>
            <form onSubmit={handleUploadEvidence}>
              <div style={{ marginBottom: "15px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "5px" }}>Target Control ID</label>
                <input
                  type="text"
                  value={evControlId}
                  onChange={(e) => setEvControlId(e.target.value)}
                  required
                  style={{ width: "100%", padding: "8px", background: "#1f2937", border: "1px solid #374151", borderRadius: "6px", color: "#fff" }}
                  placeholder="e.g. SOC2-CC6.1"
                />
              </div>
              <div style={{ marginBottom: "15px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "5px" }}>Evidence Type</label>
                <select
                  value={evType}
                  onChange={(e) => setEvType(e.target.value)}
                  style={{ width: "100%", padding: "8px", background: "#1f2937", border: "1px solid #374151", borderRadius: "6px", color: "#fff" }}
                >
                  <option value="config_snapshot">Configuration Snapshot</option>
                  <option value="audit_log">Audit Log Snap</option>
                  <option value="security_report">Compliance Report Doc</option>
                  <option value="screenshot">Remediation Screenshot</option>
                </select>
              </div>
              <div style={{ marginBottom: "15px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "5px" }}>Source Description</label>
                <input
                  type="text"
                  value={evSource}
                  onChange={(e) => setEvSource(e.target.value)}
                  required
                  style={{ width: "100%", padding: "8px", background: "#1f2937", border: "1px solid #374151", borderRadius: "6px", color: "#fff" }}
                  placeholder="e.g. Admin access log screenshot"
                />
              </div>
              <div style={{ marginBottom: "15px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "5px" }}>Content Payload</label>
                <textarea
                  value={evContent}
                  onChange={(e) => setEvContent(e.target.value)}
                  required
                  style={{ width: "100%", padding: "8px", background: "#1f2937", border: "1px solid #374151", borderRadius: "6px", color: "#fff", height: "80px" }}
                  placeholder="Paste snapshot JSON config details or verification logs text"
                />
              </div>
              <button type="submit" style={{ width: "100%", background: "#10b981", color: "#fff", border: "none", padding: "10px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}>
                Upload & Seal Hash
              </button>
            </form>
          </div>
        </div>
      )}

      {activeTab === "audits" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "30px" }}>
          {/* Active Audits */}
          <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "12px", padding: "25px" }}>
            <h3 style={{ fontSize: "18px", margin: "0 0 20px 0", color: "#fff" }}>Audit Project Timelines</h3>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "14px", textAlign: "left" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #1f2937" }}>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Audit Project ID</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Scope Summary</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Standard</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Assessor Entity</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Timeline Range</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Progress Status</th>
                </tr>
              </thead>
              <tbody>
                {audits.map((a) => (
                  <tr key={a.audit_id} style={{ borderBottom: "1px solid #1f2937" }}>
                    <td style={{ padding: "12px 8px", fontWeight: "600" }}>{a.audit_id}</td>
                    <td style={{ padding: "12px 8px", color: "#fff" }}>{a.scope}</td>
                    <td style={{ padding: "12px 8px" }}><span style={{ padding: "2px 6px", background: "#374151", borderRadius: "4px" }}>{a.framework_name}</span></td>
                    <td style={{ padding: "12px 8px" }}>{a.auditor}</td>
                    <td style={{ padding: "12px 8px", color: "#cbd5e1" }}>{new Date(a.start_date).toLocaleDateString()} - {new Date(a.end_date).toLocaleDateString()}</td>
                    <td style={{ padding: "12px 8px" }}>
                      <span style={{ fontSize: "12px", fontWeight: "600", color: a.status === "COMPLETED" ? "#34d399" : "#fbbf24" }}>
                        {a.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Gaps Findings */}
          <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "12px", padding: "25px" }}>
            <h3 style={{ fontSize: "18px", margin: "0 0 20px 0", color: "#fff" }}>Remediation Findings Register</h3>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "14px", textAlign: "left" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #1f2937" }}>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Finding ID</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Severity</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Control ID</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Detected Defect</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Recommended Mitigation Actions</th>
                  <th style={{ padding: "12px 8px", color: "#94a3b8" }}>State</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.finding_id} style={{ borderBottom: "1px solid #1f2937" }}>
                    <td style={{ padding: "12px 8px", fontWeight: "600" }}>{f.finding_id}</td>
                    <td style={{ padding: "12px 8px" }}>
                      <span style={{ color: f.severity === "critical" || f.severity === "high" ? "#fca5a5" : "#cbd5e1", textTransform: "uppercase", fontSize: "12px", fontWeight: "700" }}>
                        {f.severity}
                      </span>
                    </td>
                    <td style={{ padding: "12px 8px" }}><span style={{ padding: "2px 6px", background: "#374151", borderRadius: "4px" }}>{f.control_id}</span></td>
                    <td style={{ padding: "12px 8px", color: "#fff" }}>{f.description}</td>
                    <td style={{ padding: "12px 8px", color: "#cbd5e1" }}>{f.remediation_plan}</td>
                    <td style={{ padding: "12px 8px" }}>
                      <span style={{ fontSize: "12px", fontWeight: "600", color: f.status === "CLOSED" || f.status === "REMEDIATED" ? "#34d399" : "#fca5a5" }}>
                        {f.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

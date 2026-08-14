import React, { useEffect, useState } from "react";
import axios from "axios";

interface DetectionItem {
  _id?: string;
  rule_id: string;
  name: string;
  description: string;
  status: string;
  severity: string;
  confidence: string;
  author: string;
  data_sources: string[];
  time_window: number;
  mitre_attack_techniques: string[];
  false_positive_guidance: string;
  conditions?: any;
  updated_at: string;
  versions?: any[];
  audits?: any[];
}

export default function Detections() {
  const [rules, setRules] = useState<DetectionItem[]>([]);
  const [selectedRule, setSelectedRule] = useState<DetectionItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Filter States
  const [filterStatus, setFilterStatus] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterSource, setFilterSource] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

  // Create Form State
  const [wizardOpen, setWizardOpen] = useState(false);
  const [newId, setNewId] = useState("");
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newSeverity, setNewSeverity] = useState("MEDIUM");
  const [newConfidence, setNewConfidence] = useState("MEDIUM");
  const [newDataSources, setNewDataSources] = useState("syslog");
  const [newWindow, setNewWindow] = useState(60);
  const [newMitre, setNewMitre] = useState("T1566");
  const [newFP, setNewFP] = useState("");

  // Edit / Version update State
  const [editOpen, setEditOpen] = useState(false);
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editChangeInfo, setEditChangeInfo] = useState("");

  const token = localStorage.getItem("token");
  const config = {
    headers: { Authorization: `Bearer ${token}` }
  };

  const fetchData = async () => {
    try {
      setLoading(true);
      setError("");
      
      // Build query string
      const params = new URLSearchParams();
      if (filterStatus) params.append("status", filterStatus);
      if (filterSeverity) params.append("severity", filterSeverity);
      if (filterSource) params.append("data_source", filterSource);
      if (searchQuery) params.append("search", searchQuery);

      const res = await axios.get(`/api/v1/detections?${params.toString()}`, config);
      setRules(res.data);
      if (res.data.length > 0) {
        handleSelectRule(res.data[0].rule_id);
      } else {
        setSelectedRule(null);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to load rules.");
    } finally {
      setLoading(false);
    }
  };

  const handleSelectRule = async (ruleId: string) => {
    try {
      const res = await axios.get(`/api/v1/detections/${ruleId}`, config);
      setSelectedRule(res.data);
    } catch (err) {
      console.error("Failed to load rule history", err);
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await axios.post("/api/v1/detections", {
        rule_id: newId,
        name: newName,
        description: newDesc,
        severity: newSeverity.toUpperCase(),
        confidence: newConfidence.toUpperCase(),
        data_sources: newDataSources.split(",").map(x => x.trim()),
        time_window: Number(newWindow),
        mitre_attack_techniques: newMitre.split(",").map(x => x.trim()),
        false_positive_guidance: newFP,
        conditions: { event_type: "login" }
      }, config);

      alert("Detection rule initialized successfully in DRAFT state.");
      setWizardOpen(false);
      // Reset
      setNewId("");
      setNewName("");
      setNewDesc("");
      setNewFP("");
      fetchData();
    } catch (err: any) {
      alert(`Save failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const handleUpdateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedRule) return;

    try {
      await axios.patch(`/api/v1/detections/${selectedRule.rule_id}`, {
        name: editName,
        description: editDesc,
        change_info: editChangeInfo
      }, config);

      alert("Rule version updated successfully.");
      setEditOpen(false);
      setEditChangeInfo("");
      fetchData();
    } catch (err: any) {
      alert(`Update failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const handleTransitionStatus = async (ruleId: string, nextStatus: string) => {
    try {
      await axios.post(`/api/v1/detections/${ruleId}/status`, { status: nextStatus }, config);
      alert(`Rule status transitioned to ${nextStatus}.`);
      fetchData();
    } catch (err: any) {
      alert(`Lifecycle Transition Rejected: ${err.response?.data?.detail || err.message}`);
    }
  };

  useEffect(() => {
    fetchData();
  }, [filterStatus, filterSeverity, filterSource]);

  const triggerSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchData();
  };

  const openEditModal = () => {
    if (!selectedRule) return;
    setEditName(selectedRule.name);
    setEditDesc(selectedRule.description);
    setEditOpen(true);
  };

  if (loading && rules.length === 0) {
    return <div style={{ color: "#fff", padding: "40px" }}>Loading detection rules...</div>;
  }

  return (
    <div style={{ padding: "30px", background: "#05070f", minHeight: "100vh", color: "#e2e8f0", fontFamily: "Outfit, sans-serif" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "30px" }}>
        <div>
          <h1 style={{ fontSize: "28px", fontWeight: "700", margin: "0 0 5px 0", color: "#fff" }}>Detection-as-Code Studio</h1>
          <p style={{ color: "#94a3b8", margin: 0 }}>Configure security parameters, control immutable versions, and enforce lifecycle transitions.</p>
        </div>
        <button
          onClick={() => setWizardOpen(true)}
          style={{ background: "#3b82f6", color: "#fff", border: "none", padding: "10px 20px", borderRadius: "8px", fontWeight: "600", cursor: "pointer" }}
        >
          Initialize Detection Rule
        </button>
      </div>

      {/* Filter / Search Bar */}
      <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "10px", padding: "15px", marginBottom: "25px", display: "flex", flexWrap: "wrap", gap: "15px", alignItems: "center" }}>
        <form onSubmit={triggerSearch} style={{ display: "flex", gap: "10px", flex: 1 }}>
          <input
            type="text"
            placeholder="Search rules by name, description or ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ flex: 1, padding: "8px 12px", background: "#111827", border: "1px solid #1f2937", borderRadius: "6px", color: "#fff" }}
          />
          <button type="submit" style={{ background: "#1e293b", border: "1px solid #334155", color: "#fff", padding: "8px 15px", borderRadius: "6px", cursor: "pointer" }}>
            Search
          </button>
        </form>

        <div style={{ display: "flex", gap: "10px" }}>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            style={{ padding: "8px 12px", background: "#111827", border: "1px solid #1f2937", borderRadius: "6px", color: "#fff" }}
          >
            <option value="">All Statuses</option>
            <option value="DRAFT">Draft</option>
            <option value="TESTING">Testing</option>
            <option value="REVIEW">Review</option>
            <option value="ACTIVE">Active</option>
            <option value="DISABLED">Disabled</option>
            <option value="DEPRECATED">Deprecated</option>
            <option value="RETIRED">Retired</option>
          </select>

          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            style={{ padding: "8px 12px", background: "#111827", border: "1px solid #1f2937", borderRadius: "6px", color: "#fff" }}
          >
            <option value="">All Severities</option>
            <option value="LOW">Low</option>
            <option value="MEDIUM">Medium</option>
            <option value="HIGH">High</option>
            <option value="CRITICAL">Critical</option>
          </select>

          <select
            value={filterSource}
            onChange={(e) => setFilterSource(e.target.value)}
            style={{ padding: "8px 12px", background: "#111827", border: "1px solid #1f2937", borderRadius: "6px", color: "#fff" }}
          >
            <option value="">All Data Sources</option>
            <option value="syslog">syslog</option>
            <option value="auth">auth</option>
            <option value="email">email</option>
          </select>
        </div>
      </div>

      {error && <div style={{ color: "#ef4444", marginBottom: "20px" }}>{error}</div>}

      <div style={{ display: "grid", gridTemplateColumns: "380px 1fr", gap: "30px", alignItems: "start" }}>
        {/* Rules List Column */}
        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
          <h3 style={{ fontSize: "16px", color: "#94a3b8", margin: "0 0 15px 0" }}>Detection Rules</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {rules.length === 0 ? (
              <div style={{ textAlign: "center", color: "#64748b", padding: "30px 0" }}>No rules match criteria.</div>
            ) : (
              rules.map((rule) => (
                <div
                  key={rule.rule_id}
                  onClick={() => handleSelectRule(rule.rule_id)}
                  style={{
                    background: selectedRule?.rule_id === rule.rule_id ? "#1e293b" : "#111827",
                    border: selectedRule?.rule_id === rule.rule_id ? "1px solid #3b82f6" : "1px solid #1f2937",
                    padding: "15px",
                    borderRadius: "8px",
                    cursor: "pointer"
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", marginBottom: "5px" }}>
                    <span style={{ color: "#94a3b8" }}>{rule.rule_id}</span>
                    <span style={{ color: rule.severity === "CRITICAL" ? "#ef4444" : "#f59e0b" }}>{rule.severity}</span>
                  </div>
                  <h4 style={{ margin: "0 0 8px 0", color: "#fff", fontSize: "15px" }}>{rule.name}</h4>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: "11px", background: "#1f2937", padding: "2px 6px", borderRadius: "4px", color: "#cbd5e1" }}>
                      {rule.status}
                    </span>
                    <span style={{ fontSize: "11px", color: "#64748b" }}>
                      Window: {rule.time_window}s
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Selected Rule details / workspace Column */}
        {selectedRule ? (
          <div style={{ display: "flex", flexDirection: "column", gap: "30px" }}>
            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "25px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <h2 style={{ margin: 0, color: "#fff", fontSize: "22px" }}>{selectedRule.name}</h2>
                    <span style={{ background: "#3b82f6", color: "#fff", fontSize: "11px", padding: "2px 6px", borderRadius: "4px" }}>
                      {selectedRule.status}
                    </span>
                  </div>
                  <span style={{ color: "#94a3b8", fontSize: "13px" }}>ID: {selectedRule.rule_id} | Author: {selectedRule.author}</span>
                </div>

                <div style={{ display: "flex", gap: "10px" }}>
                  <button
                    onClick={openEditModal}
                    style={{ background: "#1e293b", border: "1px solid #334155", color: "#fff", padding: "8px 16px", borderRadius: "6px", cursor: "pointer" }}
                  >
                    Edit properties ✏️
                  </button>
                  
                  {/* Status transitions options */}
                  {selectedRule.status === "DRAFT" && (
                    <button
                      onClick={() => handleTransitionStatus(selectedRule.rule_id, "TESTING")}
                      style={{ background: "#f59e0b", color: "#fff", border: "none", padding: "8px 16px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}
                    >
                      Promote to TESTING
                    </button>
                  )}
                  {selectedRule.status === "TESTING" && (
                    <button
                      onClick={() => handleTransitionStatus(selectedRule.rule_id, "REVIEW")}
                      style={{ background: "#10b981", color: "#fff", border: "none", padding: "8px 16px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}
                    >
                      Promote to REVIEW
                    </button>
                  )}
                  {selectedRule.status === "REVIEW" && (
                    <button
                      onClick={() => handleTransitionStatus(selectedRule.rule_id, "ACTIVE")}
                      style={{ background: "#3b82f6", color: "#fff", border: "none", padding: "8px 16px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}
                    >
                      Activate Rule ✅
                    </button>
                  )}
                  {selectedRule.status === "ACTIVE" && (
                    <button
                      onClick={() => handleTransitionStatus(selectedRule.rule_id, "DISABLED")}
                      style={{ background: "#ef4444", color: "#fff", border: "none", padding: "8px 16px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}
                    >
                      Disable Rule ❌
                    </button>
                  )}
                  {selectedRule.status === "DISABLED" && (
                    <div style={{ display: "flex", gap: "5px" }}>
                      <button
                        onClick={() => handleTransitionStatus(selectedRule.rule_id, "ACTIVE")}
                        style={{ background: "#3b82f6", color: "#fff", border: "none", padding: "8px 12px", borderRadius: "6px", cursor: "pointer" }}
                      >
                        Re-Activate
                      </button>
                      <button
                        onClick={() => handleTransitionStatus(selectedRule.rule_id, "RETIRED")}
                        style={{ background: "#374151", color: "#fff", border: "none", padding: "8px 12px", borderRadius: "6px", cursor: "pointer" }}
                      >
                        Retire
                      </button>
                    </div>
                  )}
                </div>
              </div>

              {/* Meta Parameters Grid */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "15px", background: "#090d16", padding: "15px", borderRadius: "8px", marginBottom: "25px" }}>
                <div>
                  <span style={{ fontSize: "11px", color: "#64748b", display: "block" }}>SEVERITY</span>
                  <span style={{ color: "#fff", fontSize: "14px", fontWeight: "600" }}>{selectedRule.severity}</span>
                </div>
                <div>
                  <span style={{ fontSize: "11px", color: "#64748b", display: "block" }}>CONFIDENCE</span>
                  <span style={{ color: "#fff", fontSize: "14px", fontWeight: "600" }}>{selectedRule.confidence}</span>
                </div>
                <div>
                  <span style={{ fontSize: "11px", color: "#64748b", display: "block" }}>TIME WINDOW</span>
                  <span style={{ color: "#fff", fontSize: "14px", fontWeight: "600" }}>{selectedRule.time_window} seconds</span>
                </div>
                <div>
                  <span style={{ fontSize: "11px", color: "#64748b", display: "block" }}>MITRE TECHNIQUES</span>
                  <span style={{ color: "#fff", fontSize: "14px", fontWeight: "600" }}>{selectedRule.mitre_attack_techniques?.join(", ") || "None"}</span>
                </div>
              </div>

              {/* Conditions / Guidance */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "25px" }}>
                <div>
                  <h4 style={{ fontSize: "14px", color: "#94a3b8", marginBottom: "10px" }}>Detection Conditions (Immutable JSON)</h4>
                  <pre style={{ background: "#111827", border: "1px solid #1f2937", padding: "12px", borderRadius: "6px", color: "#a855f7", fontSize: "13px", margin: 0, overflowX: "auto" }}>
                    {JSON.stringify(selectedRule.conditions, null, 2)}
                  </pre>
                </div>

                <div>
                  <h4 style={{ fontSize: "14px", color: "#94a3b8", marginBottom: "10px" }}>False Positive Guidance</h4>
                  <div style={{ background: "#111827", border: "1px solid #1f2937", padding: "12px", borderRadius: "6px", fontSize: "13px", height: "100px", overflowY: "auto" }}>
                    {selectedRule.false_positive_guidance || "No FP guidance declared."}
                  </div>
                </div>
              </div>

              {/* Version History List */}
              <div style={{ borderTop: "1px solid #1e293b", paddingTop: "20px", marginBottom: "25px" }}>
                <h3 style={{ fontSize: "16px", color: "#fff", marginBottom: "12px" }}>Version History</h3>
                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  {selectedRule.versions?.map((v: any, index: number) => (
                    <div key={index} style={{ display: "flex", justifyContent: "space-between", background: "#111827", padding: "12px", borderRadius: "6px", fontSize: "13px" }}>
                      <div>
                        <span style={{ fontWeight: "600", color: "#38bdf8" }}>Version {v.version_number}</span>
                        <span style={{ color: "#64748b", marginLeft: "10px" }}>by {v.author}</span>
                        <p style={{ margin: "5px 0 0 0", color: "#94a3b8" }}>{v.change_info}</p>
                      </div>
                      <span style={{ color: "#64748b" }}>{new Date(v.created_at).toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Audit Trail List */}
              <div style={{ borderTop: "1px solid #1e293b", paddingTop: "20px" }}>
                <h3 style={{ fontSize: "16px", color: "#fff", marginBottom: "12px" }}>Audit Trail</h3>
                <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                  {selectedRule.audits?.map((a: any, index: number) => (
                    <div key={index} style={{ display: "flex", justifyContent: "space-between", fontSize: "13px", color: "#cbd5e1" }}>
                      <span>
                        ⚙️ <strong style={{ color: "#f43f5e" }}>{a.action}</strong> by user {a.actor}
                      </span>
                      <span style={{ color: "#64748b" }}>{new Date(a.timestamp).toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          </div>
        ) : (
          <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "40px", textAlign: "center" }}>
            Select a rule to display details.
          </div>
        )}
      </div>

      {/* Creation Modal */}
      {wizardOpen && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }}>
          <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "30px", width: "520px" }}>
            <h3 style={{ fontSize: "20px", margin: "0 0 20px 0", color: "#fff" }}>Initialize Detection Rule</h3>
            <form onSubmit={handleCreateRule}>
              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Rule ID</label>
                <input
                  type="text"
                  value={newId}
                  onChange={(e) => setNewId(e.target.value)}
                  required
                  placeholder="e.g. RULE-PASSWORD-SPRAY"
                  style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                />
              </div>

              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Rule Name</label>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  required
                  placeholder="e.g. Password Spraying Attack"
                  style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                />
              </div>

              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Description</label>
                <textarea
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  required
                  placeholder="Triggered when multiple target logins failures trigger from a single IP..."
                  style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff", height: "50px", resize: "none" }}
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", marginBottom: "12px" }}>
                <div>
                  <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value)}
                    style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                  >
                    <option value="LOW">Low</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="HIGH">High</option>
                    <option value="CRITICAL">Critical</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Confidence</label>
                  <select
                    value={newConfidence}
                    onChange={(e) => setNewConfidence(e.target.value)}
                    style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                  >
                    <option value="LOW">Low</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="HIGH">High</option>
                  </select>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", marginBottom: "12px" }}>
                <div>
                  <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Data Sources (Comma-separated)</label>
                  <input
                    type="text"
                    value={newDataSources}
                    onChange={(e) => setNewDataSources(e.target.value)}
                    style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                  />
                </div>
                <div>
                  <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Time Window (seconds)</label>
                  <input
                    type="number"
                    value={newWindow}
                    onChange={(e) => setNewWindow(Number(e.target.value))}
                    min={1}
                    style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                  />
                </div>
              </div>

              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>MITRE Techniques (e.g. T1110, T1078)</label>
                <input
                  type="text"
                  value={newMitre}
                  onChange={(e) => setNewMitre(e.target.value)}
                  style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                />
              </div>

              <div style={{ marginBottom: "20px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>False Positive Guidance</label>
                <textarea
                  value={newFP}
                  onChange={(e) => setNewFP(e.target.value)}
                  placeholder="Exclude internal vulnerability scanners activity..."
                  style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff", height: "45px", resize: "none" }}
                />
              </div>

              <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
                <button
                  type="button"
                  onClick={() => setWizardOpen(false)}
                  style={{ background: "none", border: "1px solid #334155", color: "#94a3b8", padding: "8px 16px", borderRadius: "6px", cursor: "pointer" }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{ background: "#3b82f6", color: "#fff", border: "none", padding: "8px 16px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}
                >
                  Initialize Draft
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Properties Modal */}
      {editOpen && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }}>
          <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "30px", width: "480px" }}>
            <h3 style={{ fontSize: "20px", margin: "0 0 20px 0", color: "#fff" }}>Edit Detection Properties</h3>
            <form onSubmit={handleUpdateRule}>
              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Rule Name</label>
                <input
                  type="text"
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  required
                  style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                />
              </div>

              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Description</label>
                <textarea
                  value={editDesc}
                  onChange={(e) => setEditDesc(e.target.value)}
                  required
                  style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff", height: "60px", resize: "none" }}
                />
              </div>

              <div style={{ marginBottom: "20px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Change Comments (Logs in new Version Document)</label>
                <input
                  type="text"
                  value={editChangeInfo}
                  onChange={(e) => setEditChangeInfo(e.target.value)}
                  required
                  placeholder="e.g. Tuned name thresholds parameter"
                  style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                />
              </div>

              <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
                <button
                  type="button"
                  onClick={() => setEditOpen(false)}
                  style={{ background: "none", border: "1px solid #334155", color: "#94a3b8", padding: "8px 16px", borderRadius: "6px", cursor: "pointer" }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{ background: "#10b981", color: "#fff", border: "none", padding: "8px 16px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}
                >
                  Save Version Update
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

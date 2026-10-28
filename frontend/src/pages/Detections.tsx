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

  const [activeTab, setActiveTab] = useState("overview");
  const [tests, setTests] = useState<any[]>([]);
  const [selectedTest, setSelectedTest] = useState<any | null>(null);
  const [testResults, setTestResults] = useState<any[]>([]);
  const [testMatches, setTestMatches] = useState<any[]>([]);
  
  // Test creation wizard state
  const [testWizardOpen, setTestWizardOpen] = useState(false);
  const [testName, setTestName] = useState("");
  const [testDesc, setTestDesc] = useState("");
  const [testType, setTestType] = useState("controlled_event");
  const [testTargetVersion, setTestTargetVersion] = useState<number>(1);
  const [testRawEvent, setTestRawEvent] = useState('{\n  "event_type": "login",\n  "severity": "high",\n  "payload": {\n    "user": "admin"\n  }\n}');
  const [testExpectedMatch, setTestExpectedMatch] = useState(true);
  
  // Version comparison state
  const [compareV1, setCompareV1] = useState(1);
  const [compareV2, setCompareV2] = useState(1);
  const [comparisonResult, setComparisonResult] = useState<any | null>(null);

  // E11.3 Production findings and stats state
  const [executionStats, setExecutionStats] = useState<any | null>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);

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

  const fetchTests = async (ruleId: string) => {
    try {
      const res = await axios.get(`/api/v1/detections/${ruleId}/tests`, config);
      setTests(res.data);
      if (res.data.length > 0) {
        handleSelectTest(ruleId, res.data[0]._id);
      } else {
        setSelectedTest(null);
        setTestResults([]);
        setTestMatches([]);
      }
    } catch (err) {
      console.error("Failed to load tests", err);
    }
  };

  const handleSelectTest = async (ruleId: string, testId: string) => {
    try {
      const res = await axios.get(`/api/v1/detections/${ruleId}/tests/${testId}`, config);
      setSelectedTest(res.data);
      
      // Load results and matches
      const resResults = await axios.get(`/api/v1/detections/${ruleId}/tests/${testId}/results`, config);
      setTestResults(resResults.data);
      
      if (resResults.data.length > 0) {
        const latestResultId = resResults.data[0]._id;
        const resMatches = await axios.get(`/api/v1/detections/${ruleId}/tests/${testId}/matches?result_id=${latestResultId}`, config);
        setTestMatches(resMatches.data);
      } else {
        setTestMatches([]);
      }
    } catch (err) {
      console.error("Failed to load test details", err);
    }
  };

  const handleCreateTest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedRule) return;

    try {
      let testCases = [];
      if (testType === "controlled_event") {
        testCases.push({
          input_event: JSON.parse(testRawEvent),
          expected_match: testExpectedMatch
        });
      }

      const payload = {
        name: testName,
        description: testDesc,
        test_type: testType,
        version_number: Number(testTargetVersion),
        test_cases: testCases,
        max_events: 100
      };

      await axios.post(`/api/v1/detections/${selectedRule.rule_id}/tests`, payload, config);
      alert("Detection test configuration created successfully.");
      setTestWizardOpen(false);
      setTestName("");
      setTestDesc("");
      fetchTests(selectedRule.rule_id);
    } catch (err: any) {
      alert(`Create test failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const handleRunTest = async (testId: string) => {
    if (!selectedRule) return;
    try {
      const res = await axios.post(`/api/v1/detections/${selectedRule.rule_id}/tests/${testId}/run`, {}, config);
      if (res.data.status === "queued") {
        alert("Asynchronous historical replay test queued in background.");
      } else {
        alert("Test executed successfully.");
      }
      handleSelectTest(selectedRule.rule_id, testId);
    } catch (err: any) {
      alert(`Execution failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const handleCancelTest = async (testId: string) => {
    if (!selectedRule) return;
    try {
      await axios.post(`/api/v1/detections/${selectedRule.rule_id}/tests/${testId}/cancel`, {}, config);
      alert("Cancellation request sent.");
      handleSelectTest(selectedRule.rule_id, testId);
    } catch (err: any) {
      alert(`Cancellation failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const handleCompareVersions = async () => {
    if (!selectedRule) return;
    try {
      const res = await axios.post(`/api/v1/detections/${selectedRule.rule_id}/compare-versions`, {
        v1: Number(compareV1),
        v2: Number(compareV2)
      }, config);
      setComparisonResult(res.data);
    } catch (err: any) {
      alert(`Comparison failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const fetchExecutionStats = async () => {
    try {
      const res = await axios.get("/api/v1/detections/execution-stats", config);
      setExecutionStats(res.data);
    } catch (err) {
      console.error("Failed to fetch execution stats", err);
    }
  };

  const fetchFindings = async () => {
    try {
      const res = await axios.get("/api/v1/detections/findings", config);
      setFindings(res.data);
    } catch (err) {
      console.error("Failed to fetch detection findings", err);
    }
  };

  const handleSelectRule = async (ruleId: string) => {
    try {
      const res = await axios.get(`/api/v1/detections/${ruleId}`, config);
      setSelectedRule(res.data);
      fetchTests(ruleId);
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

              {/* Tab Selector */}
              <div style={{ display: "flex", gap: "20px", borderBottom: "1px solid #1e293b", marginBottom: "20px", paddingBottom: "10px" }}>
                <span
                  onClick={() => setActiveTab("overview")}
                  style={{ cursor: "pointer", fontWeight: "600", color: activeTab === "overview" ? "#3b82f6" : "#64748b", borderBottom: activeTab === "overview" ? "2px solid #3b82f6" : "none", paddingBottom: "8px" }}
                >
                  Overview
                </span>
                <span
                  onClick={() => setActiveTab("versions")}
                  style={{ cursor: "pointer", fontWeight: "600", color: activeTab === "versions" ? "#3b82f6" : "#64748b", borderBottom: activeTab === "versions" ? "2px solid #3b82f6" : "none", paddingBottom: "8px" }}
                >
                  Versions
                </span>
                <span
                  onClick={() => setActiveTab("testing")}
                  style={{ cursor: "pointer", fontWeight: "600", color: activeTab === "testing" ? "#3b82f6" : "#64748b", borderBottom: activeTab === "testing" ? "2px solid #3b82f6" : "none", paddingBottom: "8px" }}
                >
                  Testing & Validation
                </span>
                <span
                  onClick={() => {
                    setActiveTab("monitoring");
                    fetchExecutionStats();
                    fetchFindings();
                  }}
                  style={{ cursor: "pointer", fontWeight: "600", color: activeTab === "monitoring" ? "#3b82f6" : "#64748b", borderBottom: activeTab === "monitoring" ? "2px solid #3b82f6" : "none", paddingBottom: "8px" }}
                >
                  Production Monitoring
                </span>
                <span
                  onClick={() => setActiveTab("audit")}
                  style={{ cursor: "pointer", fontWeight: "600", color: activeTab === "audit" ? "#3b82f6" : "#64748b", borderBottom: activeTab === "audit" ? "2px solid #3b82f6" : "none", paddingBottom: "8px" }}
                >
                  Audit Trail
                </span>
              </div>

              {/* Tab Contents */}
              {activeTab === "overview" && (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
                  <div>
                    <h4 style={{ fontSize: "14px", color: "#94a3b8", marginBottom: "10px" }}>Detection Conditions (Immutable JSON)</h4>
                    <pre style={{ background: "#111827", border: "1px solid #1f2937", padding: "12px", borderRadius: "6px", color: "#a855f7", fontSize: "13px", margin: 0, overflowX: "auto" }}>
                      {JSON.stringify(selectedRule.conditions, null, 2)}
                    </pre>
                  </div>

                  <div>
                    <h4 style={{ fontSize: "14px", color: "#94a3b8", marginBottom: "10px" }}>False Positive Guidance</h4>
                    <div style={{ background: "#111827", border: "1px solid #1f2937", padding: "12px", borderRadius: "6px", fontSize: "13px", height: "180px", overflowY: "auto" }}>
                      {selectedRule.false_positive_guidance || "No FP guidance declared."}
                    </div>
                  </div>
                </div>
              )}

              {activeTab === "versions" && (
                <div style={{ display: "flex", flexDirection: "column", gap: "25px" }}>
                  {/* Version Comparison Sub-UI */}
                  <div style={{ background: "#090d16", border: "1px solid #1e293b", padding: "20px", borderRadius: "8px" }}>
                    <h4 style={{ margin: "0 0 15px 0", color: "#fff", fontSize: "15px" }}>Compare Detection Versions</h4>
                    <div style={{ display: "flex", gap: "15px", alignItems: "center", marginBottom: "15px" }}>
                      <div>
                        <label style={{ display: "block", fontSize: "11px", color: "#64748b", marginBottom: "4px" }}>Version A</label>
                        <select
                          value={compareV1}
                          onChange={(e) => setCompareV1(Number(e.target.value))}
                          style={{ padding: "6px 12px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                        >
                          {selectedRule.versions?.map((v: any) => (
                            <option key={v.version_number} value={v.version_number}>Version {v.version_number}</option>
                          ))}
                        </select>
                      </div>
                      <span style={{ color: "#64748b", marginTop: "15px" }}>VS</span>
                      <div>
                        <label style={{ display: "block", fontSize: "11px", color: "#64748b", marginBottom: "4px" }}>Version B</label>
                        <select
                          value={compareV2}
                          onChange={(e) => setCompareV2(Number(e.target.value))}
                          style={{ padding: "6px 12px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                        >
                          {selectedRule.versions?.map((v: any) => (
                            <option key={v.version_number} value={v.version_number}>Version {v.version_number}</option>
                          ))}
                        </select>
                      </div>
                      <button
                        onClick={handleCompareVersions}
                        style={{ marginTop: "18px", background: "#3b82f6", color: "#fff", border: "none", padding: "6px 15px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}
                      >
                        Compare
                      </button>
                    </div>

                    {comparisonResult && (
                      <div style={{ background: "#111827", padding: "15px", borderRadius: "6px", fontSize: "13px" }}>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "15px", borderBottom: "1px solid #1e293b", paddingBottom: "10px", marginBottom: "10px" }}>
                          <div>
                            <span style={{ color: "#38bdf8", fontWeight: "700" }}>Version {comparisonResult.v1.version_number}</span>
                            <p style={{ margin: "5px 0 0 0", color: "#cbd5e1" }}>Matches: {comparisonResult.v1.match_count}</p>
                            <p style={{ margin: "3px 0 0 0", color: "#ef4444" }}>FPs: {comparisonResult.v1.false_positives}</p>
                            <p style={{ margin: "3px 0 0 0", color: "#a855f7" }}>Precision: {comparisonResult.v1.precision !== null ? `${(comparisonResult.v1.precision * 100).toFixed(1)}%` : "N/A"}</p>
                          </div>
                          <div>
                            <span style={{ color: "#38bdf8", fontWeight: "700" }}>Version {comparisonResult.v2.version_number}</span>
                            <p style={{ margin: "5px 0 0 0", color: "#cbd5e1" }}>Matches: {comparisonResult.v2.match_count}</p>
                            <p style={{ margin: "3px 0 0 0", color: "#ef4444" }}>FPs: {comparisonResult.v2.false_positives}</p>
                            <p style={{ margin: "3px 0 0 0", color: "#a855f7" }}>Precision: {comparisonResult.v2.precision !== null ? `${(comparisonResult.v2.precision * 100).toFixed(1)}%` : "N/A"}</p>
                          </div>
                        </div>
                        <div style={{ color: "#10b981", fontWeight: "600" }}>
                          Match Delta: {comparisonResult.comparison.match_count_delta > 0 ? `+${comparisonResult.comparison.match_count_delta}` : comparisonResult.comparison.match_count_delta}
                        </div>
                      </div>
                    )}
                  </div>

                  <div>
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
                </div>
              )}

              {activeTab === "testing" && (
                <div style={{ display: "flex", flexDirection: "column", gap: "25px" }}>
                  {/* Test Controls / Wizard Button */}
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <h3 style={{ fontSize: "16px", color: "#fff", margin: 0 }}>Rules Testing Configurations</h3>
                    <button
                      onClick={() => {
                        setTestTargetVersion(selectedRule.versions ? selectedRule.versions[selectedRule.versions.length - 1].version_number : 1);
                        setTestWizardOpen(true);
                      }}
                      style={{ background: "#3b82f6", color: "#fff", border: "none", padding: "6px 12px", borderRadius: "6px", cursor: "pointer", fontSize: "13px" }}
                    >
                      New Test Configuration ➕
                    </button>
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "250px 1fr", gap: "20px", alignItems: "start" }}>
                    {/* Tests List */}
                    <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                      {tests.length === 0 ? (
                        <div style={{ color: "#64748b", fontSize: "13px", padding: "10px 0" }}>No tests configured.</div>
                      ) : (
                        tests.map((t: any) => (
                          <div
                            key={t._id}
                            onClick={() => handleSelectTest(selectedRule.rule_id, t._id)}
                            style={{
                              background: selectedTest?._id === t._id ? "#1e293b" : "#111827",
                              border: selectedTest?._id === t._id ? "1px solid #3b82f6" : "1px solid #1f2937",
                              padding: "10px 12px",
                              borderRadius: "6px",
                              cursor: "pointer",
                              fontSize: "13px"
                            }}
                          >
                            <div style={{ fontWeight: "600", color: "#fff", marginBottom: "3px" }}>{t.name}</div>
                            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", color: "#94a3b8" }}>
                              <span>v{t.version_number} | {t.test_type === "controlled_event" ? "Sync" : "Async"}</span>
                              <span style={{
                                color: t.status === "PASSED" ? "#10b981" : (t.status === "FAILED" ? "#ef4444" : (t.status === "RUNNING" ? "#f59e0b" : "#64748b"))
                              }}>{t.status}</span>
                            </div>
                          </div>
                        ))
                      )}
                    </div>

                    {/* Selected Test workspace */}
                    {selectedTest ? (
                      <div style={{ background: "#090d16", border: "1px solid #1e293b", padding: "20px", borderRadius: "8px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "15px", borderBottom: "1px solid #1e293b", paddingBottom: "15px" }}>
                          <div>
                            <h4 style={{ margin: "0 0 5px 0", color: "#fff", fontSize: "16px" }}>{selectedTest.name}</h4>
                            <p style={{ margin: 0, color: "#94a3b8", fontSize: "12px" }}>{selectedTest.description || "No description provided."}</p>
                            <div style={{ display: "flex", gap: "10px", marginTop: "8px", fontSize: "11px" }}>
                              <span style={{ color: "#38bdf8" }}>Version under test: {selectedTest.version_number}</span>
                              <span style={{ color: "#a855f7" }}>Type: {selectedTest.test_type}</span>
                            </div>
                          </div>

                          <div style={{ display: "flex", gap: "8px" }}>
                            {selectedTest.status === "RUNNING" || selectedTest.status === "PENDING" ? (
                              <button
                                onClick={() => handleCancelTest(selectedTest._id)}
                                style={{ background: "#ef4444", color: "#fff", border: "none", padding: "6px 12px", borderRadius: "6px", cursor: "pointer", fontSize: "12px" }}
                              >
                                Cancel 🛑
                              </button>
                            ) : (
                              <button
                                onClick={() => handleRunTest(selectedTest._id)}
                                style={{ background: "#10b981", color: "#fff", border: "none", padding: "6px 12px", borderRadius: "6px", cursor: "pointer", fontSize: "12px" }}
                              >
                                Run Test 🚀
                              </button>
                            )}
                          </div>
                        </div>

                        {/* Test Results view */}
                        {testResults.length > 0 ? (
                          <div>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
                              <span style={{ fontSize: "13px", fontWeight: "700", color: "#fff" }}>Latest Run Output</span>
                              <span style={{ fontSize: "11px", color: "#64748b" }}>Duration: {testResults[0].duration_ms.toFixed(2)}ms</span>
                            </div>

                            {/* Stat Cards */}
                            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "10px", marginBottom: "15px" }}>
                              <div style={{ background: "#111827", padding: "10px", borderRadius: "6px", textAlign: "center" }}>
                                <span style={{ fontSize: "10px", color: "#64748b", display: "block" }}>PRECISION</span>
                                <span style={{ fontSize: "16px", color: "#10b981", fontWeight: "700" }}>
                                  {testResults[0].precision !== null ? `${(testResults[0].precision * 100).toFixed(1)}%` : "N/A"}
                                </span>
                              </div>
                              <div style={{ background: "#111827", padding: "10px", borderRadius: "6px", textAlign: "center" }}>
                                <span style={{ fontSize: "10px", color: "#64748b", display: "block" }}>RECALL</span>
                                <span style={{ fontSize: "16px", color: "#38bdf8", fontWeight: "700" }}>
                                  {testResults[0].recall !== null ? `${(testResults[0].recall * 100).toFixed(1)}%` : "N/A"}
                                </span>
                              </div>
                              <div style={{ background: "#111827", padding: "10px", borderRadius: "6px", textAlign: "center" }}>
                                <span style={{ fontSize: "10px", color: "#64748b", display: "block" }}>F1 SCORE</span>
                                <span style={{ fontSize: "16px", color: "#a855f7", fontWeight: "700" }}>
                                  {testResults[0].f1_score !== null ? `${(testResults[0].f1_score * 100).toFixed(1)}%` : "N/A"}
                                </span>
                              </div>
                            </div>

                            <div style={{ fontSize: "12px", color: "#cbd5e1", marginBottom: "15px" }}>
                              <div style={{ display: "flex", justifyContent: "space-between", margin: "4px 0" }}>
                                <span>Total events evaluated:</span>
                                <span>{testResults[0].total_events_evaluated}</span>
                              </div>
                              <div style={{ display: "flex", justifyContent: "space-between", margin: "4px 0" }}>
                                <span>Actual Matches:</span>
                                <span>{testResults[0].match_count} (Rate: {(testResults[0].match_rate * 100).toFixed(1)}%)</span>
                              </div>
                              <div style={{ display: "flex", justifyContent: "space-between", margin: "4px 0" }}>
                                <span>Unexpected Matches (FPs):</span>
                                <span style={{ color: testResults[0].false_positives > 0 ? "#ef4444" : "#10b981" }}>{testResults[0].false_positives}</span>
                              </div>
                              <div style={{ display: "flex", justifyContent: "space-between", margin: "4px 0" }}>
                                <span>Missed Matches (FNs):</span>
                                <span style={{ color: testResults[0].false_negatives > 0 ? "#ef4444" : "#10b981" }}>{testResults[0].false_negatives}</span>
                              </div>
                            </div>

                            {/* Match Inspection list */}
                            {testMatches.length > 0 && (
                              <div>
                                <span style={{ fontSize: "12px", fontWeight: "600", color: "#94a3b8", display: "block", marginBottom: "8px" }}>Matched Events Inspection</span>
                                <div style={{ display: "flex", flexDirection: "column", gap: "6px", maxHeight: "120px", overflowY: "auto" }}>
                                  {testMatches.map((m: any, idx: number) => (
                                    <div key={idx} style={{ display: "flex", justifyContent: "space-between", background: "#111827", padding: "6px 10px", borderRadius: "4px", fontSize: "11px" }}>
                                      <span style={{ color: "#cbd5e1" }}>Event type: {m.event_type} | Source: {m.source}</span>
                                      <span style={{
                                        color: m.status === "TP" ? "#10b981" : (m.status === "FP" ? "#ef4444" : "#e2e8f0"),
                                        fontWeight: "600"
                                      }}>{m.status}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        ) : (
                          <div style={{ textAlign: "center", color: "#64748b", padding: "20px 0", fontSize: "13px" }}>
                            Test configuration is ready. Click "Run Test" to evaluate.
                          </div>
                        )}
                      </div>
                    ) : (
                      <div style={{ color: "#64748b", fontSize: "13px", padding: "20px", textAlign: "center" }}>Select or create a test configuration from the list.</div>
                    )}
                  </div>
                </div>
              )}

              {activeTab === "audit" && (
                <div>
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
              )}

              {activeTab === "monitoring" && (
                <div style={{ display: "flex", flexDirection: "column", gap: "25px" }}>
                  {/* Execution Stats Dashboard */}
                  <div>
                    <h3 style={{ fontSize: "16px", color: "#fff", marginBottom: "12px" }}>Operational Health & Execution Metrics</h3>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "10px" }}>
                      <div style={{ background: "#111827", padding: "12px", borderRadius: "6px", textAlign: "center" }}>
                        <span style={{ fontSize: "10px", color: "#64748b", display: "block" }}>EVENTS EVALUATED</span>
                        <span style={{ fontSize: "18px", color: "#38bdf8", fontWeight: "700" }}>
                          {executionStats?.events_processed || 0}
                        </span>
                      </div>
                      <div style={{ background: "#111827", padding: "12px", borderRadius: "6px", textAlign: "center" }}>
                        <span style={{ fontSize: "10px", color: "#64748b", display: "block" }}>MATCHES</span>
                        <span style={{ fontSize: "18px", color: "#10b981", fontWeight: "700" }}>
                          {executionStats?.matches || 0}
                        </span>
                      </div>
                      <div style={{ background: "#111827", padding: "12px", borderRadius: "6px", textAlign: "center" }}>
                        <span style={{ fontSize: "10px", color: "#64748b", display: "block" }}>NO MATCHES</span>
                        <span style={{ fontSize: "18px", color: "#94a3b8", fontWeight: "700" }}>
                          {executionStats?.no_matches || 0}
                        </span>
                      </div>
                      <div style={{ background: "#111827", padding: "12px", borderRadius: "6px", textAlign: "center" }}>
                        <span style={{ fontSize: "10px", color: "#64748b", display: "block" }}>DEDUPLICATED</span>
                        <span style={{ fontSize: "18px", color: "#a855f7", fontWeight: "700" }}>
                          {executionStats?.deduplicated || 0}
                        </span>
                      </div>
                      <div style={{ background: "#111827", padding: "12px", borderRadius: "6px", textAlign: "center" }}>
                        <span style={{ fontSize: "10px", color: "#64748b", display: "block" }}>ERRORS</span>
                        <span style={{ fontSize: "18px", color: "#ef4444", fontWeight: "700" }}>
                          {executionStats?.errors || 0}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Findings Inspector */}
                  <div>
                    <h3 style={{ fontSize: "16px", color: "#fff", marginBottom: "12px" }}>Production Findings</h3>
                    <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: "20px", alignItems: "start" }}>
                      
                      {/* Findings List */}
                      <div style={{ display: "flex", flexDirection: "column", gap: "10px", maxHeight: "350px", overflowY: "auto" }}>
                        {findings.length === 0 ? (
                          <div style={{ color: "#64748b", fontSize: "13px", padding: "10px 0" }}>No production findings logged.</div>
                        ) : (
                          findings.map((f: any) => (
                            <div
                              key={f._id}
                              onClick={() => setSelectedFinding(f)}
                              style={{
                                background: selectedFinding?._id === f._id ? "#1e293b" : "#111827",
                                border: selectedFinding?._id === f._id ? "1px solid #3b82f6" : "1px solid #1f2937",
                                padding: "10px 12px",
                                borderRadius: "6px",
                                cursor: "pointer",
                                fontSize: "13px"
                              }}
                            >
                              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "3px" }}>
                                <span style={{ fontWeight: "600", color: "#fff" }}>Finding {f._id.substring(18)}</span>
                                <span style={{
                                  color: f.severity === "CRITICAL" || f.severity === "HIGH" ? "#ef4444" : "#f59e0b",
                                  fontSize: "11px",
                                  fontWeight: "700"
                                }}>{f.severity}</span>
                              </div>
                              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", color: "#94a3b8" }}>
                                <span>Rule: {f.detection_id}</span>
                                <span>{new Date(f.timestamp).toLocaleTimeString()}</span>
                              </div>
                            </div>
                          ))
                        )}
                      </div>

                      {/* Selected Finding evidence details */}
                      {selectedFinding ? (
                        <div style={{ background: "#090d16", border: "1px solid #1e293b", padding: "20px", borderRadius: "8px" }}>
                          <h4 style={{ margin: "0 0 12px 0", color: "#fff", fontSize: "15px" }}>Finding Evidence Context</h4>
                          
                          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "15px", fontSize: "13px", marginBottom: "15px" }}>
                            <div>
                              <span style={{ color: "#64748b", display: "block" }}>FINDING ID</span>
                              <span style={{ color: "#cbd5e1" }}>{selectedFinding._id}</span>
                            </div>
                            <div>
                              <span style={{ color: "#64748b", display: "block" }}>DETECTION RULE</span>
                              <span style={{ color: "#cbd5e1" }}>{selectedFinding.detection_id} (Version {selectedFinding.version_number})</span>
                            </div>
                            <div>
                              <span style={{ color: "#64748b", display: "block" }}>SEVERITY / CONFIDENCE</span>
                              <span style={{ color: "#cbd5e1" }}>{selectedFinding.severity} / {selectedFinding.confidence}</span>
                            </div>
                            <div>
                              <span style={{ color: "#64748b", display: "block" }}>LINKED INCIDENT</span>
                              <span style={{ color: "#10b981", fontWeight: "700" }}>{selectedFinding.incident_id || "None"}</span>
                            </div>
                          </div>

                          <div style={{ borderTop: "1px solid #1e293b", paddingTop: "15px" }}>
                            <span style={{ fontSize: "12px", color: "#94a3b8", display: "block", marginBottom: "6px" }}>Sanitized Telemetry Payload</span>
                            <pre style={{ background: "#111827", padding: "10px", borderRadius: "6px", fontSize: "11px", color: "#a855f7", overflowX: "auto", margin: 0 }}>
                              {JSON.stringify(selectedFinding.evidence.payload || {}, null, 2)}
                            </pre>
                          </div>
                        </div>
                      ) : (
                        <div style={{ color: "#64748b", fontSize: "13px", padding: "20px", textAlign: "center", border: "1px dashed #1e293b", borderRadius: "8px" }}>
                          Select a finding to inspect its evidence and case context.
                        </div>
                      )}

                    </div>
                  </div>
                </div>
              )}

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

      {/* Test Creation Modal */}
      {testWizardOpen && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }}>
          <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "30px", width: "520px" }}>
            <h3 style={{ fontSize: "20px", margin: "0 0 20px 0", color: "#fff" }}>Configure Detection Test</h3>
            <form onSubmit={handleCreateTest}>
              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Test Name</label>
                <input
                  type="text"
                  value={testName}
                  onChange={(e) => setTestName(e.target.value)}
                  required
                  placeholder="e.g. Brute Force Validation Run"
                  style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                />
              </div>

              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Description</label>
                <input
                  type="text"
                  value={testDesc}
                  onChange={(e) => setTestDesc(e.target.value)}
                  placeholder="Verify rule triggers on multiple high severity authentication events"
                  style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", marginBottom: "12px" }}>
                <div>
                  <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Test Type</label>
                  <select
                    value={testType}
                    onChange={(e) => setTestType(e.target.value)}
                    style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                  >
                    <option value="controlled_event">Controlled Event (Mock Data)</option>
                    <option value="historical_replay">Historical Replay (Telemetry Data)</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "4px" }}>Target Rule Version</label>
                  <select
                    value={testTargetVersion}
                    onChange={(e) => setTestTargetVersion(Number(e.target.value))}
                    style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
                  >
                    {selectedRule?.versions?.map((v: any) => (
                      <option key={v.version_number} value={v.version_number}>Version {v.version_number}</option>
                    ))}
                  </select>
                </div>
              </div>

              {testType === "controlled_event" ? (
                <div style={{ marginBottom: "20px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                    <label style={{ fontSize: "13px", color: "#94a3b8" }}>Mock Event Payload (JSON)</label>
                    <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                      <input
                        type="checkbox"
                        id="expectedMatchCheck"
                        checked={testExpectedMatch}
                        onChange={(e) => setTestExpectedMatch(e.target.checked)}
                      />
                      <label htmlFor="expectedMatchCheck" style={{ fontSize: "11px", color: "#cbd5e1" }}>Expect Match Verdict</label>
                    </div>
                  </div>
                  <textarea
                    value={testRawEvent}
                    onChange={(e) => setTestRawEvent(e.target.value)}
                    required
                    style={{ width: "100%", padding: "8px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#a855f7", height: "100px", fontFamily: "monospace", fontSize: "12px", resize: "none" }}
                  />
                </div>
              ) : (
                <div style={{ marginBottom: "20px", fontSize: "12px", color: "#94a3b8" }}>
                  ℹ️ Historical Replay runs evaluate telemetry ingested into the Data Platform over the last 30 days. No manual event configuration is required.
                </div>
              )}

              <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
                <button
                  type="button"
                  onClick={() => setTestWizardOpen(false)}
                  style={{ background: "none", border: "1px solid #334155", color: "#94a3b8", padding: "8px 16px", borderRadius: "6px", cursor: "pointer" }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{ background: "#3b82f6", color: "#fff", border: "none", padding: "8px 16px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}
                >
                  Create Configuration
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

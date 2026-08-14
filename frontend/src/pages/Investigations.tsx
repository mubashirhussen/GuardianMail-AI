import { useEffect, useState } from "react";
import axios from "axios";

interface InvestigationItem {
  _id?: string;
  investigation_id: string;
  title: string;
  priority: string;
  status: string;
  entities: any[];
  evidence: any[];
  timeline: any[];
  created_at: string;
}

interface GraphData {
  nodes: { id: string; label: string; type: string; color: string }[];
  edges: { source: string; target: string; type: string; label: string }[];
}

interface AiSummaryData {
  summary: string;
  observed_facts: string[];
  model_inferences: string[];
}

export default function Investigations() {
  const [cases, setCases] = useState<InvestigationItem[]>([]);
  const [selectedCase, setSelectedCase] = useState<InvestigationItem | null>(null);
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [aiSummary, setAiSummary] = useState<AiSummaryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("timeline");

  const token = localStorage.getItem("token");
  const config = {
    headers: { Authorization: `Bearer ${token}` }
  };

  const fetchData = async () => {
    try {
      setLoading(true);
      const res = await axios.get("/api/v1/investigations", config);
      setCases(res.data);
      if (res.data.length > 0) {
        handleSelectCase(res.data[0]);
      }
    } catch (err) {
      console.error("Failed to load cases", err);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectCase = async (item: InvestigationItem) => {
    setSelectedCase(item);
    setGraph(null);
    setAiSummary(null);
    try {
      const resGraph = await axios.get(`/api/v1/investigations/${item.investigation_id}/graph`, config);
      setGraph(resGraph.data);

      const resAi = await axios.get(`/api/v1/investigations/${item.investigation_id}/ai-summary`, config);
      setAiSummary(resAi.data);
    } catch (err) {
      console.error("Failed to load details", err);
    }
  };

  const handleTriggerSOAR = async (id: string) => {
    try {
      const res = await axios.post(`/api/v1/investigations/${id}/soar`, {}, config);
      alert(`SOAR Playbook Triggered: ${res.data.remediation_workflow_id}. Remediation steps deployed: ${res.data.remediation_actions.join(", ")}`);
    } catch (err) {
      alert("Failed to deploy SOAR actions.");
    }
  };

  const handleExportGRC = async (id: string) => {
    try {
      const res = await axios.post(`/api/v1/investigations/${id}/grc`, {}, config);
      alert(`Exported successfully to compliance module! Registered GRC Evidence ID: ${res.data.evidence_id}`);
    } catch (err) {
      alert("Failed to export compliance logs.");
    }
  };

  const handleCreateMockCase = async () => {
    try {
      const mockId = `INV-${Math.floor(Math.random() * 9000) + 1000}`;
      await axios.post("/api/v1/investigations", {
        investigation_id: mockId,
        title: "Anomalous Login Overlap",
        priority: "high",
        entities: [
          { type: "USER", value: "analyst@enterprise.com" },
          { type: "IP", value: "198.51.100.12" }
        ],
        evidence: [
          { type: "syslog", description: "IP mapped to Tor Exit node", confidence: "high" }
        ]
      }, config);
      alert("Mock investigation case file created successfully!");
      fetchData();
    } catch (err) {
      alert("Failed to create mock investigation.");
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  if (loading) {
    return <div style={{ color: "#fff", padding: "40px" }}>Loading active investigations...</div>;
  }

  return (
    <div style={{ padding: "30px", background: "#05070f", minHeight: "100vh", color: "#e2e8f0", fontFamily: "Outfit, Inter, sans-serif" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "30px" }}>
        <div>
          <h1 style={{ fontSize: "28px", fontWeight: "700", margin: "0 0 5px 0", color: "#fff" }}>SOC Investigations Workspace</h1>
          <p style={{ color: "#94a3b8", margin: 0 }}>Correlate network entities, audit attack paths graph, and analyze AI grounding summaries.</p>
        </div>
        <button
          onClick={handleCreateMockCase}
          style={{ background: "#3b82f6", color: "#fff", border: "none", padding: "10px 20px", borderRadius: "8px", fontWeight: "600", cursor: "pointer" }}
        >
          Open Mock Investigation File
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "350px 1fr", gap: "30px", alignItems: "start" }}>
        {/* Cases list */}
        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
          <h3 style={{ fontSize: "16px", color: "#94a3b8", margin: "0 0 15px 0" }}>Open Case Files</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {cases.length === 0 ? (
              <div style={{ textAlign: "center", color: "#64748b", padding: "20px 0" }}>No investigations logged.</div>
            ) : (
              cases.map((c) => (
                <div
                  key={c.investigation_id}
                  onClick={() => handleSelectCase(c)}
                  style={{
                    background: selectedCase?.investigation_id === c.investigation_id ? "#1e293b" : "#111827",
                    border: selectedCase?.investigation_id === c.investigation_id ? "1px solid #3b82f6" : "1px solid #1f2937",
                    padding: "15px",
                    borderRadius: "8px",
                    cursor: "pointer"
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", color: "#94a3b8", marginBottom: "5px" }}>
                    <span>{c.investigation_id}</span>
                    <span style={{ color: c.priority === "high" ? "#ef4444" : "#cbd5e1" }}>{c.priority.toUpperCase()}</span>
                  </div>
                  <h4 style={{ margin: 0, color: "#fff", fontSize: "15px" }}>{c.title}</h4>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Selected Case Workspace */}
        {selectedCase ? (
          <div style={{ display: "flex", flexDirection: "column", gap: "30px" }}>
            {/* Overview Card */}
            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "25px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
                <div>
                  <h2 style={{ margin: 0, color: "#fff", fontSize: "22px" }}>{selectedCase.title}</h2>
                  <span style={{ color: "#94a3b8", fontSize: "13px" }}>ID: {selectedCase.investigation_id} | Created: {new Date(selectedCase.created_at).toLocaleString()}</span>
                </div>
                <div style={{ display: "flex", gap: "10px" }}>
                  <button
                    onClick={() => handleTriggerSOAR(selectedCase.investigation_id)}
                    style={{ background: "#ef4444", color: "#fff", border: "none", padding: "8px 16px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}
                  >
                    Deploy SOAR Workflow
                  </button>
                  <button
                    onClick={() => handleExportGRC(selectedCase.investigation_id)}
                    style={{ background: "#10b981", color: "#fff", border: "none", padding: "8px 16px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}
                  >
                    Log GRC Evidence
                  </button>
                </div>
              </div>

              {/* Tabs */}
              <div style={{ display: "flex", gap: "15px", borderBottom: "1px solid #1e293b", marginBottom: "20px" }}>
                {["timeline", "graph", "ai_copilot"].map((t) => (
                  <button
                    key={t}
                    onClick={() => setActiveTab(t)}
                    style={{
                      background: "none",
                      border: "none",
                      borderBottom: activeTab === t ? "2px solid #3b82f6" : "2px solid transparent",
                      color: activeTab === t ? "#fff" : "#64748b",
                      padding: "8px 16px",
                      fontSize: "14px",
                      cursor: "pointer",
                      fontWeight: "600"
                    }}
                  >
                    {t === "ai_copilot" ? "AI Copilot" : t.toUpperCase()}
                  </button>
                ))}
              </div>

              {/* Tab Contents */}
              {activeTab === "timeline" && (
                <div>
                  <h3 style={{ fontSize: "16px", color: "#fff", marginBottom: "15px" }}>Case Investigation Timeline</h3>
                  <div style={{ borderLeft: "2px solid #1e293b", paddingLeft: "20px", display: "flex", flexDirection: "column", gap: "15px" }}>
                    {selectedCase.timeline.map((item, idx) => (
                      <div key={idx} style={{ position: "relative" }}>
                        <div style={{ position: "absolute", left: "-27px", top: "5px", width: "12px", height: "12px", borderRadius: "50%", background: "#3b82f6" }}></div>
                        <div style={{ fontSize: "13px", color: "#64748b" }}>{new Date(item.timestamp).toLocaleString()}</div>
                        <div style={{ color: "#fff", fontWeight: "600", marginTop: "2px" }}>{item.activity}</div>
                        <div style={{ fontSize: "12px", color: "#94a3b8" }}>Triggered by: {item.actor}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {activeTab === "graph" && (
                <div>
                  <h3 style={{ fontSize: "16px", color: "#fff", marginBottom: "15px" }}>Interactive Attack Graph Node-Link</h3>
                  {graph && (
                    <div style={{ background: "#090d1a", border: "1px solid #1f2937", borderRadius: "8px", padding: "20px" }}>
                      <h4 style={{ margin: "0 0 10px 0", color: "#94a3b8", fontSize: "13px" }}>Resolved Graph Entities</h4>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "10px", marginBottom: "20px" }}>
                        {graph.nodes.map((node) => (
                          <div
                            key={node.id}
                            style={{
                              background: node.color,
                              color: "#fff",
                              padding: "6px 12px",
                              borderRadius: "20px",
                              fontSize: "12px",
                              fontWeight: "600"
                            }}
                          >
                            [{node.type}] {node.label}
                          </div>
                        ))}
                      </div>

                      <h4 style={{ margin: "0 0 10px 0", color: "#94a3b8", fontSize: "13px" }}>Derived Relationship Links</h4>
                      <div style={{ display: "flex", flexDirection: "column", gap: "5px" }}>
                        {graph.edges.map((edge, idx) => (
                          <div key={idx} style={{ fontSize: "13px", color: "#cbd5e1" }}>
                            <span style={{ color: "#38bdf8" }}>{edge.source}</span>
                            {" "}──({edge.label})──➔{" "}
                            <span style={{ color: "#fb7185" }}>{edge.target}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeTab === "ai_copilot" && aiSummary && (
                <div style={{ background: "rgba(59, 130, 246, 0.05)", border: "1px solid rgba(59, 130, 246, 0.2)", borderRadius: "8px", padding: "20px" }}>
                  <h3 style={{ fontSize: "16px", color: "#60a5fa", margin: "0 0 10px 0", display: "flex", alignItems: "center", gap: "8px" }}>
                    🤖 AI Assistant Copilot Grounding Report
                  </h3>
                  <p style={{ color: "#fff", fontSize: "15px", lineHeight: "1.5", marginBottom: "20px" }}>{aiSummary.summary}</p>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
                    <div>
                      <h4 style={{ color: "#34d399", fontSize: "13px", margin: "0 0 10px 0" }}>Facts (Observed Evidence)</h4>
                      <ul style={{ margin: 0, paddingLeft: "15px", fontSize: "13px", color: "#cbd5e1" }}>
                        {aiSummary.observed_facts.map((fact, idx) => (
                          <li key={idx} style={{ marginBottom: "6px" }}>{fact}</li>
                        ))}
                      </ul>
                    </div>

                    <div>
                      <h4 style={{ color: "#a78bfa", fontSize: "13px", margin: "0 0 10px 0" }}>Model Inferences</h4>
                      <ul style={{ margin: 0, paddingLeft: "15px", fontSize: "13px", color: "#cbd5e1" }}>
                        {aiSummary.model_inferences.map((inf, idx) => (
                          <li key={idx} style={{ marginBottom: "6px" }}>{inf}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "40px", textAlign: "center" }}>
            Select an active investigation case file to view details.
          </div>
        )}
      </div>
    </div>
  );
}

import React, { useEffect, useState } from "react";
import axios from "axios";

interface IntegrationItem {
  _id?: string;
  integration_id: string;
  provider: string;
  status: string;
  auth_method: string;
  health_status: string;
  last_sync_at?: string;
  last_error?: string;
}

interface DeliveryItem {
  integration_id: string;
  event_type: string;
  status: string;
  retry_count: number;
  last_attempt_at: string;
  error_message?: string;
  correlation_id: string;
}

export default function Integrations() {
  const [integrations, setIntegrations] = useState<IntegrationItem[]>([]);
  const [deliveries, setDeliveries] = useState<DeliveryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Connection Wizard Form State
  const [wizardOpen, setWizardOpen] = useState(false);
  const [newId, setNewId] = useState("");
  const [newProvider, setNewProvider] = useState("siem");
  const [newUrl, setNewUrl] = useState("");
  const [newSecret, setNewSecret] = useState("");

  const token = localStorage.getItem("token");
  const config = {
    headers: { Authorization: `Bearer ${token}` }
  };

  const fetchData = async () => {
    try {
      setLoading(true);
      setError("");
      
      const resList = await axios.get("/api/v1/integrations", config);
      setIntegrations(resList.data);

      // Load deliveries for the first integration if present
      if (resList.data.length > 0) {
        const firstId = resList.data[0].integration_id;
        const resDel = await axios.get(`/api/v1/integrations/${firstId}/deliveries`, config);
        setDeliveries(resDel.data);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to load security integrations catalog.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleTestConnection = async (id: string) => {
    try {
      const res = await axios.post(`/api/v1/integrations/${id}/test`, {}, config);
      if (res.data.success) {
        alert("Connection test succeeded! Safe URL target resolved successfully.");
      } else {
        alert("Connection test failed.");
      }
      fetchData();
    } catch (err: any) {
      alert(`Connection failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const handleToggleStatus = async (item: IntegrationItem) => {
    try {
      const action = item.status === "ACTIVE" ? "disable" : "enable";
      await axios.post(`/api/v1/integrations/${item.integration_id}/${action}`, {}, config);
      alert(`Integration is now ${action === "enable" ? "ACTIVE" : "DISABLED"}.`);
      fetchData();
    } catch (err) {
      alert("Failed to toggle integration status.");
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm("Are you sure you want to remove this integration configuration?")) return;
    try {
      await axios.delete(`/api/v1/integrations/${id}`, config);
      alert("Integration removed successfully.");
      fetchData();
    } catch (err) {
      alert("Failed to delete integration.");
    }
  };

  const handleCreateIntegration = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await axios.post("/api/v1/integrations", {
        integration_id: newId,
        provider: newProvider,
        config: {
          url: newUrl,
          webhook_secret: newSecret
        }
      }, config);
      alert("New integration provider adapter created successfully.");
      setWizardOpen(false);
      setNewId("");
      setNewUrl("");
      setNewSecret("");
      fetchData();
    } catch (err: any) {
      alert(`Failed to configure integration: ${err.response?.data?.detail || err.message}`);
    }
  };

  if (loading) {
    return <div style={{ color: "#fff", padding: "40px", fontFamily: "sans-serif" }}>Loading security integrations...</div>;
  }

  return (
    <div style={{ padding: "30px", background: "#0a0f1d", minHeight: "100vh", color: "#e2e8f0", fontFamily: "Outfit, Inter, sans-serif" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "30px" }}>
        <div>
          <h1 style={{ fontSize: "28px", fontWeight: "700", margin: "0 0 5px 0", color: "#fff" }}>Security Integrations (SIEM/SOC)</h1>
          <p style={{ color: "#94a3b8", margin: 0 }}>Configure and audit connected SIEM logs, ServiceNow ticketing adapters, and secure outbound webhooks.</p>
        </div>
        <button
          onClick={() => setWizardOpen(true)}
          style={{ background: "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)", color: "#fff", border: "none", padding: "10px 20px", borderRadius: "8px", fontWeight: "600", cursor: "pointer" }}
        >
          Add Integration Provider
        </button>
      </div>

      {error && (
        <div style={{ background: "rgba(239, 68, 68, 0.15)", border: "1px solid #ef4444", color: "#fca5a5", padding: "15px", borderRadius: "8px", marginBottom: "25px" }}>
          {error}
        </div>
      )}

      {/* Installed Integrations Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(350px, 1fr))", gap: "20px", marginBottom: "40px" }}>
        {integrations.length === 0 ? (
          <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "12px", padding: "40px", textAlign: "center", gridColumn: "1/-1" }}>
            <span style={{ fontSize: "40px", display: "block", marginBottom: "15px" }}>🔌</span>
            <h3 style={{ margin: "0 0 10px 0", color: "#fff" }}>No Integrations Configured</h3>
            <p style={{ color: "#94a3b8", margin: "0 0 20px 0" }}>Connect your workflow, ticketing, or SIEM endpoints to establish downstream events streaming.</p>
            <button
              onClick={() => setWizardOpen(true)}
              style={{ background: "#3b82f6", color: "#fff", border: "none", padding: "8px 16px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}
            >
              Launch Wizard
            </button>
          </div>
        ) : (
          integrations.map((item) => (
            <div key={item.integration_id} style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "12px", padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "15px" }}>
                <div>
                  <span style={{ textTransform: "uppercase", fontSize: "11px", fontWeight: "700", letterSpacing: "0.05em", padding: "2px 6px", background: "#1f2937", borderRadius: "4px", color: "#cbd5e1" }}>
                    {item.provider}
                  </span>
                  <h3 style={{ fontSize: "18px", margin: "8px 0 2px 0", color: "#fff" }}>{item.integration_id}</h3>
                </div>
                <span style={{
                  padding: "4px 8px",
                  borderRadius: "6px",
                  fontSize: "12px",
                  fontWeight: "600",
                  background: item.status === "ACTIVE" ? "rgba(16, 185, 129, 0.2)" : "rgba(148, 163, 184, 0.2)",
                  color: item.status === "ACTIVE" ? "#34d399" : "#94a3b8"
                }}>
                  {item.status}
                </span>
              </div>

              <div style={{ display: "flex", gap: "15px", fontSize: "13px", color: "#94a3b8", marginBottom: "20px" }}>
                <div>
                  Health: <span style={{ color: item.health_status === "healthy" ? "#34d399" : "#fca5a5", fontWeight: "600" }}>{item.health_status}</span>
                </div>
                <div>•</div>
                <div>Auth: <span style={{ color: "#fff" }}>{item.auth_method}</span></div>
              </div>

              <div style={{ display: "flex", gap: "10px" }}>
                <button
                  onClick={() => handleTestConnection(item.integration_id)}
                  style={{ flex: 1, background: "#1f2937", border: "1px solid #374151", color: "#fff", padding: "8px", borderRadius: "6px", fontSize: "13px", fontWeight: "600", cursor: "pointer" }}
                >
                  Test Connection
                </button>
                <button
                  onClick={() => handleToggleStatus(item)}
                  style={{ background: "none", border: "1px solid #374151", color: "#cbd5e1", padding: "8px 12px", borderRadius: "6px", fontSize: "13px", cursor: "pointer" }}
                >
                  {item.status === "ACTIVE" ? "Disable" : "Enable"}
                </button>
                <button
                  onClick={() => handleDelete(item.integration_id)}
                  style={{ background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.2)", color: "#fca5a5", padding: "8px 12px", borderRadius: "6px", fontSize: "13px", cursor: "pointer" }}
                >
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Outbound Delivery Logs */}
      {deliveries.length > 0 && (
        <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "12px", padding: "25px" }}>
          <h3 style={{ fontSize: "18px", margin: "0 0 20px 0", color: "#fff" }}>Outbound Delivery Audits (Retry Queue)</h3>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "14px", textAlign: "left" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #1f2937" }}>
                <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Event Category</th>
                <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Status</th>
                <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Retries Count</th>
                <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Attempt Timestamp</th>
                <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Correlation ID</th>
                <th style={{ padding: "12px 8px", color: "#94a3b8" }}>Errors</th>
              </tr>
            </thead>
            <tbody>
              {deliveries.map((d, idx) => (
                <tr key={idx} style={{ borderBottom: "1px solid #1f2937" }}>
                  <td style={{ padding: "12px 8px", fontWeight: "600", color: "#fff" }}>{d.event_type}</td>
                  <td style={{ padding: "12px 8px" }}>
                    <span style={{
                      padding: "2px 6px",
                      borderRadius: "4px",
                      fontSize: "12px",
                      background: d.status === "SENT" ? "rgba(16, 185, 129, 0.15)" : "rgba(239, 68, 68, 0.15)",
                      color: d.status === "SENT" ? "#34d399" : "#fca5a5"
                    }}>
                      {d.status}
                    </span>
                  </td>
                  <td style={{ padding: "12px 8px" }}>{d.retry_count}</td>
                  <td style={{ padding: "12px 8px", color: "#cbd5e1" }}>{new Date(d.last_attempt_at).toLocaleString()}</td>
                  <td style={{ padding: "12px 8px", fontFamily: "monospace", fontSize: "12px" }}>{d.correlation_id}</td>
                  <td style={{ padding: "12px 8px", color: "#fca5a5", fontSize: "13px" }}>{d.error_message || "None"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Connection Wizard Modal */}
      {wizardOpen && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }}>
          <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "12px", padding: "30px", width: "450px" }}>
            <h3 style={{ fontSize: "20px", margin: "0 0 20px 0", color: "#fff" }}>Configure Integration Adapter</h3>
            
            <form onSubmit={handleCreateIntegration}>
              <div style={{ marginBottom: "15px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "5px" }}>Unique Integration ID</label>
                <input
                  type="text"
                  value={newId}
                  onChange={(e) => setNewId(e.target.value)}
                  required
                  style={{ width: "100%", padding: "8px", background: "#1f2937", border: "1px solid #374151", borderRadius: "6px", color: "#fff" }}
                  placeholder="e.g. SPLUNK-SIEM-PROD"
                />
              </div>

              <div style={{ marginBottom: "15px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "5px" }}>Adapter Provider</label>
                <select
                  value={newProvider}
                  onChange={(e) => setNewProvider(e.target.value)}
                  style={{ width: "100%", padding: "8px", background: "#1f2937", border: "1px solid #374151", borderRadius: "6px", color: "#fff" }}
                >
                  <option value="siem">SIEM Adapter</option>
                  <option value="jira">Jira Tickets</option>
                  <option value="servicenow">ServiceNow Incident</option>
                  <option value="webhook">Custom Webhook</option>
                </select>
              </div>

              <div style={{ marginBottom: "15px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "5px" }}>Destination URL (SSRF Safe Check Enforced)</label>
                <input
                  type="url"
                  value={newUrl}
                  onChange={(e) => setNewUrl(e.target.value)}
                  required
                  style={{ width: "100%", padding: "8px", background: "#1f2937", border: "1px solid #374151", borderRadius: "6px", color: "#fff" }}
                  placeholder="https://siem-collector.enterprise.com/events"
                />
              </div>

              <div style={{ marginBottom: "25px" }}>
                <label style={{ display: "block", fontSize: "13px", color: "#94a3b8", marginBottom: "5px" }}>Webhook Shared HMAC Secret Key (Optional)</label>
                <input
                  type="password"
                  value={newSecret}
                  onChange={(e) => setNewSecret(e.target.value)}
                  style={{ width: "100%", padding: "8px", background: "#1f2937", border: "1px solid #374151", borderRadius: "6px", color: "#fff" }}
                  placeholder="Sealed cryptographic signature key"
                />
              </div>

              <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
                <button
                  type="button"
                  onClick={() => setWizardOpen(false)}
                  style={{ background: "none", border: "1px solid #374151", color: "#cbd5e1", padding: "8px 16px", borderRadius: "6px", cursor: "pointer" }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{ background: "#3b82f6", color: "#fff", border: "none", padding: "8px 16px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}
                >
                  Save Configuration
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

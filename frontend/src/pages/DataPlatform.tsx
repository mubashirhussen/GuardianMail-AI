import { useEffect, useState } from "react";
import axios from "axios";

interface TelemetryItem {
  _id?: string;
  event_id: string;
  event_type: string;
  timestamp: string;
  severity: string;
  source: string;
  payload: any;
  partition_key: string;
  rolling_rate_60s?: number;
}

interface FeatureItem {
  feature_id: string;
  entity_id: string;
  feature_name: string;
  value: number;
  updated_at: string;
}

export default function DataPlatform() {
  const [telemetry, setTelemetry] = useState<TelemetryItem[]>([]);
  const [features, setFeatures] = useState<FeatureItem[]>([]);
  const [searchField, setSearchField] = useState("syslog");
  const [rate, setRate] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const token = localStorage.getItem("token");
  const config = {
    headers: { Authorization: `Bearer ${token}` }
  };

  const fetchHealthAndFeatures = async () => {
    try {
      const resHealth = await axios.get("/api/v1/data-platform/health", config);
      setRate(resHealth.data.ingestion_rate_60s || 0);

      // Fetch sample entity features
      const resFeat = await axios.get("/api/v1/data-platform/features/global", config);
      setFeatures(resFeat.data);
    } catch (err) {
      console.error("Failed to load metrics", err);
    }
  };

  const fetchQuery = async () => {
    try {
      setError("");
      const res = await axios.post("/api/v1/data-platform/query", {
        criteria: { event_type: searchField }
      }, config);
      setTelemetry(res.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Threat hunting query failed.");
    }
  };

  const handleTriggerMockIngest = async () => {
    try {
      await axios.post("/api/v1/data-platform/ingest", {
        event_type: "syslog",
        severity: "high",
        source: "192.168.1.100",
        payload: {
          action: "Blocked Port Scan",
          attempt_count: Math.floor(Math.random() * 50) + 1
        }
      }, config);
      alert("Mock telemetry log event ingested successfully!");
      fetchHealthAndFeatures();
      fetchQuery();
    } catch (err) {
      alert("Failed to ingest mock event.");
    }
  };

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      await fetchHealthAndFeatures();
      // Insert initial features for visualization if empty
      try {
        await axios.post("/api/v1/data-platform/features", {
          entity_id: "global",
          feature_name: "FEAT-EMAIL-FREQUENCY",
          value: 45.8
        }, config);
        await axios.post("/api/v1/data-platform/features", {
          entity_id: "global",
          feature_name: "FEAT-ATTACHMENT-ANOMALY-FACTOR",
          value: 0.89
        }, config);
      } catch {}
      await fetchHealthAndFeatures();
      await fetchQuery();
      setLoading(false);
    };
    init();
  }, []);

  if (loading) {
    return <div style={{ color: "#fff", padding: "40px", fontFamily: "sans-serif" }}>Loading Security Data Lake...</div>;
  }

  return (
    <div style={{ padding: "30px", background: "#060913", minHeight: "100vh", color: "#e2e8f0", fontFamily: "Outfit, Inter, sans-serif" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "30px" }}>
        <div>
          <h1 style={{ fontSize: "28px", fontWeight: "700", margin: "0 0 5px 0", color: "#fff" }}>Security Data Platform</h1>
          <p style={{ color: "#94a3b8", margin: 0 }}>High-throughput ingestion bus, partition-aware security data lake, and ML feature stores.</p>
        </div>
        <button
          onClick={handleTriggerMockIngest}
          style={{ background: "linear-gradient(135deg, #10b981 0%, #059669 100%)", color: "#fff", border: "none", padding: "10px 20px", borderRadius: "8px", fontWeight: "600", cursor: "pointer" }}
        >
          Ingest Mock Telemetry Event
        </button>
      </div>

      {/* Analytics widgets */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "20px", marginBottom: "30px" }}>
        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
          <h3 style={{ fontSize: "14px", textTransform: "uppercase", color: "#94a3b8", margin: "0 0 10px 0" }}>Rolling Ingestion Rate (60s)</h3>
          <div style={{ display: "flex", alignItems: "baseline", gap: "10px" }}>
            <span style={{ fontSize: "36px", fontWeight: "700", color: "#fff" }}>{rate}</span>
            <span style={{ fontSize: "14px", color: "#10b981" }}>events/min</span>
          </div>
          {rate > 100 && (
            <div style={{ marginTop: "10px", color: "#f87171", fontSize: "12px", fontWeight: "600" }}>
              ⚠️ High Event Ingestion Rate Spike Alert Detected!
            </div>
          )}
        </div>

        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
          <h3 style={{ fontSize: "14px", textTransform: "uppercase", color: "#94a3b8", margin: "0 0 10px 0" }}>Data Lake Storage Type</h3>
          <div style={{ fontSize: "24px", fontWeight: "700", color: "#38bdf8", marginTop: "5px" }}>Parquet-Partitioned</div>
          <div style={{ fontSize: "13px", color: "#64748b", marginTop: "5px" }}>Warm Partition: YYYY-MM-DD</div>
        </div>

        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
          <h3 style={{ fontSize: "14px", textTransform: "uppercase", color: "#94a3b8", margin: "0 0 10px 0" }}>Pipeline Analytics status</h3>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "10px" }}>
            <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#10b981", display: "inline-block" }}></span>
            <span style={{ fontSize: "15px", color: "#fff", fontWeight: "600" }}>Active Event Streaming</span>
          </div>
        </div>
      </div>

      {/* Threat Hunting console */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 350px", gap: "30px" }}>
        {/* Logs query results */}
        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "25px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
            <h3 style={{ fontSize: "18px", margin: 0, color: "#fff" }}>Threat Hunting Query Results</h3>
            <div style={{ display: "flex", gap: "10px" }}>
              <select
                value={searchField}
                onChange={(e) => setSearchField(e.target.value)}
                style={{ padding: "6px 12px", background: "#1e293b", border: "1px solid #334155", borderRadius: "6px", color: "#fff" }}
              >
                <option value="syslog">syslog</option>
                <option value="flow">flow</option>
                <option value="login">login</option>
                <option value="email_scan">email_scan</option>
              </select>
              <button
                onClick={fetchQuery}
                style={{ background: "#3b82f6", color: "#fff", border: "none", padding: "6px 16px", borderRadius: "6px", fontWeight: "600", cursor: "pointer" }}
              >
                Execute Query
              </button>
            </div>
          </div>

          {error && <div style={{ color: "#f87171", marginBottom: "15px" }}>{error}</div>}

          {telemetry.length === 0 ? (
            <div style={{ textAlign: "center", color: "#64748b", padding: "40px 0" }}>No matching events found in partition store.</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "14px" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #1e293b" }}>
                    <th style={{ padding: "10px 5px", color: "#64748b" }}>Timestamp</th>
                    <th style={{ padding: "10px 5px", color: "#64748b" }}>Source</th>
                    <th style={{ padding: "10px 5px", color: "#64748b" }}>Severity</th>
                    <th style={{ padding: "10px 5px", color: "#64748b" }}>Payload</th>
                    <th style={{ padding: "10px 5px", color: "#64748b" }}>Partition</th>
                  </tr>
                </thead>
                <tbody>
                  {telemetry.map((t, idx) => (
                    <tr key={idx} style={{ borderBottom: "1px solid #1e293b" }}>
                      <td style={{ padding: "10px 5px", color: "#cbd5e1" }}>{new Date(t.timestamp).toLocaleString()}</td>
                      <td style={{ padding: "10px 5px", fontWeight: "600", color: "#fff" }}>{t.source}</td>
                      <td style={{ padding: "10px 5px" }}>
                        <span style={{
                          padding: "2px 6px",
                          borderRadius: "4px",
                          fontSize: "11px",
                          background: t.severity === "high" ? "rgba(239, 68, 68, 0.15)" : "rgba(245, 158, 11, 0.15)",
                          color: t.severity === "high" ? "#ef4444" : "#f59e0b"
                        }}>
                          {t.severity}
                        </span>
                      </td>
                      <td style={{ padding: "10px 5px", fontFamily: "monospace", fontSize: "12px", color: "#94a3b8" }}>
                        {JSON.stringify(t.payload)}
                      </td>
                      <td style={{ padding: "10px 5px", color: "#64748b" }}>{t.partition_key}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Feature Store */}
        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "25px" }}>
          <h3 style={{ fontSize: "18px", margin: "0 0 20px 0", color: "#fff" }}>ML Feature Registry</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "15px" }}>
            {features.map((f, idx) => (
              <div key={idx} style={{ borderBottom: "1px solid #1e293b", paddingBottom: "12px" }}>
                <div style={{ fontSize: "13px", color: "#94a3b8", fontWeight: "600" }}>{f.feature_name}</div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginTop: "5px" }}>
                  <span style={{ fontSize: "20px", fontWeight: "700", color: "#fff" }}>{f.value}</span>
                  <span style={{ fontSize: "11px", color: "#64748b" }}>Updated: {new Date(f.updated_at).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Search, Plus, Trash2, ShieldAlert, Activity,
  History, Play, AlertCircle, ShieldCheck
} from 'lucide-react';

interface FilterRow {
  field: string;
  operator: string;
  value: string;
}

export const ThreatHunting: React.FC = () => {
  const [filters, setFilters] = useState<FilterRow[]>([
    { field: 'event_type', operator: 'eq', value: 'login' }
  ]);
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');
  const [enrichIntel, setEnrichIntel] = useState(true);
  const [enrichUeba, setEnrichUeba] = useState(true);

  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [sessions, setSessions] = useState<any[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<any | null>(null);

  // Escalation modal state
  const [escalateModalOpen, setEscalateModalOpen] = useState(false);
  const [escalateSeverity, setEscalateSeverity] = useState('MEDIUM');
  const [escalateNotes, setEscalateNotes] = useState('');
  const [escalating, setEscalating] = useState(false);

  // Session saving state
  const [sessionName, setSessionName] = useState('');
  const [sessionDesc, setSessionDesc] = useState('');
  const [saveSessionOpen, setSaveSessionOpen] = useState(false);

  const token = localStorage.getItem('token');
  const config = {
    headers: { Authorization: `Bearer ${token}` }
  };

  useEffect(() => {
    fetchSessions();
  }, []);

  const fetchSessions = async () => {
    try {
      const res = await axios.get('/api/v1/threat-hunting/sessions', config);
      setSessions(res.data);
    } catch (err) {
      console.error('Failed to fetch hunt sessions', err);
    }
  };

  const handleAddFilter = () => {
    setFilters([...filters, { field: 'event_type', operator: 'eq', value: '' }]);
  };

  const handleRemoveFilter = (index: number) => {
    setFilters(filters.filter((_, idx) => idx !== index));
  };

  const handleFilterChange = (index: number, key: keyof FilterRow, val: string) => {
    const updated = [...filters];
    updated[index][key] = val;
    setFilters(updated);
  };

  const executeHuntSearch = async () => {
    setLoading(true);
    setError('');
    setSelectedEvent(null);
    try {
      // Build query AST structure
      const query_ast: any = {
        filters: filters.map(f => ({
          field: f.field,
          operator: f.operator,
          value: f.field === 'rolling_rate_60s' ? Number(f.value) : f.value
        }))
      };

      if (startTime || endTime) {
        query_ast.time_range = {};
        if (startTime) query_ast.time_range.start = new Date(startTime).toISOString();
        if (endTime) query_ast.time_range.end = new Date(endTime).toISOString();
      }

      const res = await axios.post('/api/v1/threat-hunting/search', {
        query_ast,
        enrich_intel: enrichIntel,
        enrich_ueba: enrichUeba
      }, config);
      setResults(res.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Threat hunting query execution failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveSession = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const query_ast = {
        filters: filters.map(f => ({
          field: f.field,
          operator: f.operator,
          value: f.field === 'rolling_rate_60s' ? Number(f.value) : f.value
        })),
        time_range: {
          start: startTime ? new Date(startTime).toISOString() : undefined,
          end: endTime ? new Date(endTime).toISOString() : undefined
        }
      };

      await axios.post('/api/v1/threat-hunting/sessions', {
        name: sessionName,
        description: sessionDesc,
        query_ast
      }, config);

      setSessionName('');
      setSessionDesc('');
      setSaveSessionOpen(false);
      fetchSessions();
    } catch (err: any) {
      alert('Failed to save session: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleLoadSession = (session: any) => {
    const ast = session.query_ast || {};
    const loadedFilters = ast.filters || [];
    setFilters(loadedFilters.map((f: any) => ({
      field: f.field,
      operator: f.operator,
      value: String(f.value)
    })));
    if (ast.time_range?.start) {
      setStartTime(new Date(ast.time_range.start).toISOString().slice(0, 16));
    } else {
      setStartTime('');
    }
    if (ast.time_range?.end) {
      setEndTime(new Date(ast.time_range.end).toISOString().slice(0, 16));
    } else {
      setEndTime('');
    }
  };

  const handleEscalate = async () => {
    if (!selectedEvent) return;
    setEscalating(true);
    try {
      const res = await axios.post('/api/v1/threat-hunting/escalate', {
        event_id: selectedEvent.event_id,
        severity: escalateSeverity,
        notes: escalateNotes
      }, config);

      // Update selected event locally with the link to incident ID
      setSelectedEvent({
        ...selectedEvent,
        active_finding: {
          finding_id: res.data._id,
          status: 'NEW',
          severity: escalateSeverity
        },
        incident_id: res.data.incident_id
      });

      setEscalateNotes('');
      setEscalateModalOpen(false);
      alert(`Successfully escalated. Incident ID: ${res.data.incident_id}`);
    } catch (err: any) {
      alert('Escalation failed: ' + (err.response?.data?.detail || err.message));
    } finally {
      setEscalating(false);
    }
  };

  return (
    <div style={{ padding: '24px', background: '#090d16', minHeight: '100vh', color: '#f1f5f9' }}>
      
      {/* Brand Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h2 style={{ fontSize: '24px', fontWeight: '700', color: '#fff', margin: 0 }}>Threat Hunting Console</h2>
          <p style={{ color: '#64748b', fontSize: '13px', margin: '4px 0 0 0' }}>
            Safely search high-volume partitioned security telemetry and cross-reference indicators.
          </p>
        </div>
        <button
          onClick={() => setSaveSessionOpen(true)}
          style={{
            background: '#1e293b',
            color: '#fff',
            border: '1px solid #334155',
            padding: '10px 16px',
            borderRadius: '8px',
            cursor: 'pointer',
            fontSize: '13px',
            fontWeight: '600'
          }}
        >
          Save Query Session
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: '20px', alignItems: 'start' }}>
        
        {/* Main Hunting Workspace */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* Query Builder AST panel */}
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '20px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: '600', color: '#fff', margin: '0 0 15px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Activity size={18} style={{ color: '#06b6d4' }} /> Safe AST Query Builder
            </h3>

            {/* Filter Rows */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginBottom: '15px' }}>
              {filters.map((row, idx) => (
                <div key={idx} style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                  <select
                    value={row.field}
                    onChange={(e) => handleFilterChange(idx, 'field', e.target.value)}
                    style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff', padding: '8px', width: '180px' }}
                  >
                    <option value="event_type">Event Type</option>
                    <option value="severity">Severity</option>
                    <option value="source">Source IP / Component</option>
                    <option value="user_id">User ID (Key)</option>
                    <option value="rolling_rate_60s">Rolling Count (60s)</option>
                    <option value="payload.user">Payload User</option>
                    <option value="payload.ip">Payload IP</option>
                    <option value="payload.domain">Payload Domain</option>
                  </select>

                  <select
                    value={row.operator}
                    onChange={(e) => handleFilterChange(idx, 'operator', e.target.value)}
                    style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff', padding: '8px', width: '130px' }}
                  >
                    <option value="eq">equals</option>
                    <option value="ne">does not equal</option>
                    <option value="contains">contains</option>
                    <option value="in">is in list</option>
                    <option value="gt">&gt; greater than</option>
                    <option value="lt">&lt; less than</option>
                  </select>

                  <input
                    type="text"
                    value={row.value}
                    onChange={(e) => handleFilterChange(idx, 'value', e.target.value)}
                    placeholder="Value (e.g. login, high, admin)"
                    style={{ flex: 1, background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff', padding: '8px' }}
                  />

                  {filters.length > 1 && (
                    <button
                      onClick={() => handleRemoveFilter(idx)}
                      style={{ background: 'transparent', border: 'none', color: '#ef4444', cursor: 'pointer', padding: '6px' }}
                    >
                      <Trash2 size={16} />
                    </button>
                  )}
                </div>
              ))}
            </div>

            {/* Time controls & Enrichment Options */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', borderTop: '1px solid #1e293b', paddingTop: '15px', marginBottom: '15px' }}>
              <div style={{ display: 'flex', gap: '10px' }}>
                <div style={{ flex: 1 }}>
                  <label style={{ display: 'block', fontSize: '11px', color: '#64748b', marginBottom: '4px' }}>START DATE/TIME</label>
                  <input
                    type="datetime-local"
                    value={startTime}
                    onChange={(e) => setStartTime(e.target.value)}
                    style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff', padding: '8px' }}
                  />
                </div>
                <div style={{ flex: 1 }}>
                  <label style={{ display: 'block', fontSize: '11px', color: '#64748b', marginBottom: '4px' }}>END DATE/TIME</label>
                  <input
                    type="datetime-local"
                    value={endTime}
                    onChange={(e) => setEndTime(e.target.value)}
                    style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff', padding: '8px' }}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '13px' }}>
                  <input
                    type="checkbox"
                    checked={enrichIntel}
                    onChange={(e) => setEnrichIntel(e.target.checked)}
                    style={{ cursor: 'pointer' }}
                  />
                  Enrich E4 Threat Intel
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '13px' }}>
                  <input
                    type="checkbox"
                    checked={enrichUeba}
                    onChange={(e) => setEnrichUeba(e.target.checked)}
                    style={{ cursor: 'pointer' }}
                  />
                  Enrich E9 UEBA Scores
                </label>
              </div>
            </div>

            {/* Run controls */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <button
                onClick={handleAddFilter}
                style={{
                  background: 'transparent',
                  color: '#06b6d4',
                  border: '1px solid #06b6d4',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  fontSize: '12px',
                  fontWeight: '600'
                }}
              >
                <Plus size={14} /> Add Query Row
              </button>

              <button
                onClick={executeHuntSearch}
                disabled={loading}
                style={{
                  background: '#06b6d4',
                  color: '#000',
                  border: 'none',
                  padding: '10px 20px',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  fontSize: '13px',
                  fontWeight: '700'
                }}
              >
                <Search size={16} /> {loading ? 'Searching Telemetry...' : 'Run Threat Hunt'}
              </button>
            </div>
          </div>

          {/* Results display */}
          {error && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', padding: '12px', borderRadius: '8px', color: '#f87171', fontSize: '13px' }}>
              <AlertCircle size={18} />
              {error}
            </div>
          )}

          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '20px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: '600', color: '#fff', margin: '0 0 15px 0' }}>Search Results ({results.length})</h3>

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #1e293b', color: '#64748b' }}>
                    <th style={{ padding: '10px' }}>Timestamp</th>
                    <th style={{ padding: '10px' }}>Event Type</th>
                    <th style={{ padding: '10px' }}>Severity</th>
                    <th style={{ padding: '10px' }}>Source IP</th>
                    <th style={{ padding: '10px' }}>E4 Threat Intel</th>
                    <th style={{ padding: '10px' }}>E9 UEBA Score</th>
                    <th style={{ padding: '10px' }}>E11 Detections</th>
                  </tr>
                </thead>
                <tbody>
                  {results.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', color: '#64748b', padding: '30px 0' }}>
                        No matching telemetry events. Construct an AST filter and run threat hunt.
                      </td>
                    </tr>
                  ) : (
                    results.map((evt, idx) => (
                      <tr
                        key={idx}
                        onClick={() => setSelectedEvent(evt)}
                        style={{
                          borderBottom: '1px solid #1e293b',
                          cursor: 'pointer',
                          background: selectedEvent?.event_id === evt.event_id ? '#1e293b' : 'transparent',
                          transition: 'background 0.15s'
                        }}
                      >
                        <td style={{ padding: '10px', color: '#cbd5e1' }}>{new Date(evt.timestamp).toLocaleString()}</td>
                        <td style={{ padding: '10px' }}><span style={{ background: '#3b82f6/10', color: '#60a5fa', padding: '2px 6px', borderRadius: '4px', fontSize: '11px' }}>{evt.event_type}</span></td>
                        <td style={{ padding: '10px', color: evt.severity === 'high' || evt.severity === 'critical' ? '#f87171' : '#fbbf24' }}>{evt.severity?.toUpperCase()}</td>
                        <td style={{ padding: '10px', color: '#cbd5e1' }}>{evt.source}</td>
                        <td style={{ padding: '10px' }}>
                          {evt.threat_intel_match ? (
                            <span style={{ color: '#f87171', fontWeight: '600' }}>⚠️ Malicious ({evt.threat_intel_details?.severity})</span>
                          ) : (
                            <span style={{ color: '#10b981' }}>Clean</span>
                          )}
                        </td>
                        <td style={{ padding: '10px', color: evt.user_risk_score > 0.5 ? '#f87171' : '#cbd5e1' }}>
                          {evt.user_risk_score > 0 ? `${Math.round(evt.user_risk_score * 100)}/100` : 'Normal'}
                        </td>
                        <td style={{ padding: '10px' }}>
                          {evt.active_finding ? (
                            <span style={{ color: '#fbbf24' }}>Finding active</span>
                          ) : (
                            <span style={{ color: '#64748b' }}>None</span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Sidebar details / Saved Sessions */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* Selected Event Details Panel */}
          {selectedEvent ? (
            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '20px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: '600', color: '#fff', margin: '0 0 15px 0' }}>Event Investigation</h3>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px', marginBottom: '20px' }}>
                <div>
                  <span style={{ color: '#64748b', display: 'block', fontSize: '11px' }}>EVENT ID</span>
                  <span style={{ color: '#fff' }}>{selectedEvent.event_id}</span>
                </div>
                <div>
                  <span style={{ color: '#64748b', display: 'block', fontSize: '11px' }}>SOURCE COMPONENT</span>
                  <span style={{ color: '#fff' }}>{selectedEvent.source}</span>
                </div>
                <div>
                  <span style={{ color: '#64748b', display: 'block', fontSize: '11px' }}>USER ID</span>
                  <span style={{ color: '#fff' }}>{selectedEvent.user_id || 'None'}</span>
                </div>
                
                {selectedEvent.threat_intel_match && (
                  <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', padding: '10px', borderRadius: '6px' }}>
                    <span style={{ color: '#f87171', fontWeight: '600', display: 'block', fontSize: '11px' }}>E4 THREAT INTEL WARNING</span>
                    <p style={{ color: '#cbd5e1', fontSize: '12px', margin: '2px 0 0 0' }}>{selectedEvent.threat_intel_details?.description}</p>
                  </div>
                )}

                {selectedEvent.user_risk_score > 0 && (
                  <div style={{ background: 'rgba(59, 130, 246, 0.1)', border: '1px solid rgba(59, 130, 246, 0.2)', padding: '10px', borderRadius: '6px' }}>
                    <span style={{ color: '#60a5fa', fontWeight: '600', display: 'block', fontSize: '11px' }}>E9 UEBA ANOMALIES</span>
                    <p style={{ color: '#cbd5e1', fontSize: '12px', margin: '2px 0 0 0' }}>Risk Features: {JSON.stringify(selectedEvent.ueba_anomaly_features)}</p>
                  </div>
                )}
              </div>

              {selectedEvent.incident_id ? (
                <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.2)', padding: '12px', borderRadius: '8px', color: '#34d399', fontSize: '13px', textAlign: 'center' }}>
                  <ShieldCheck style={{ verticalAlign: 'middle', marginRight: '6px' }} size={16} />
                  Escalated to <strong>{selectedEvent.incident_id}</strong>
                </div>
              ) : (
                <button
                  onClick={() => setEscalateModalOpen(true)}
                  style={{
                    width: '100%',
                    background: '#ef4444',
                    color: '#fff',
                    border: 'none',
                    padding: '10px',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    fontSize: '13px',
                    fontWeight: '600',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px'
                  }}
                >
                  <ShieldAlert size={16} /> Escalate to Incident Case
                </button>
              )}
            </div>
          ) : (
            <div style={{ background: '#0f172a', border: '1px dashed #1e293b', borderRadius: '12px', padding: '30px', textAlign: 'center', color: '#64748b', fontSize: '13px' }}>
              Select a telemetry event to perform drill-down investigation.
            </div>
          )}

          {/* Hunt Sessions History List */}
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '20px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: '600', color: '#fff', margin: '0 0 15px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <History size={16} style={{ color: '#64748b' }} /> Saved Hunt Sessions
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '200px', overflowY: 'auto' }}>
              {sessions.length === 0 ? (
                <div style={{ color: '#64748b', fontSize: '13px' }}>No saved hunt sessions.</div>
              ) : (
                sessions.map((s, idx) => (
                  <div
                    key={idx}
                    onClick={() => handleLoadSession(s)}
                    style={{
                      background: '#111827',
                      border: '1px solid #1f2937',
                      padding: '10px',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      fontSize: '12px'
                    }}
                  >
                    <div style={{ fontWeight: '600', color: '#fff', display: 'flex', justifyContent: 'space-between' }}>
                      <span>{s.name}</span>
                      <Play size={10} style={{ color: '#06b6d4', marginTop: '3px' }} />
                    </div>
                    <span style={{ color: '#64748b', display: 'block', marginTop: '2px' }}>{s.description}</span>
                  </div>
                ))
              )}
            </div>
          </div>

        </div>
      </div>

      {/* Escalation Modal Dialog */}
      {escalateModalOpen && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '30px', width: '480px', margin: 'auto' }}>
            <h3 style={{ fontSize: '18px', color: '#fff', margin: '0 0 15px 0' }}>Escalate Manual Hunt Finding</h3>
            
            <div style={{ marginBottom: '15px' }}>
              <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>SEVERITY LEVEL</label>
              <select
                value={escalateSeverity}
                onChange={(e) => setEscalateSeverity(e.target.value)}
                style={{ width: '100%', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff' }}
              >
                <option value="LOW">Low</option>
                <option value="MEDIUM">Medium</option>
                <option value="HIGH">High</option>
                <option value="CRITICAL">Critical</option>
              </select>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>INVESTIGATION NOTES / CRITERIA</label>
              <textarea
                value={escalateNotes}
                onChange={(e) => setEscalateNotes(e.target.value)}
                placeholder="Observed suspicious user credential logins coupled with lookalike domain indicators..."
                style={{ width: '100%', height: '100px', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff' }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                onClick={() => setEscalateModalOpen(false)}
                style={{ background: 'transparent', border: '1px solid #334155', color: '#fff', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer' }}
              >
                Cancel
              </button>
              <button
                onClick={handleEscalate}
                disabled={escalating || !escalateNotes}
                style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer', fontWeight: '600' }}
              >
                {escalating ? 'Escalating...' : 'Confirm Escalate'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Save Session Modal Dialog */}
      {saveSessionOpen && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '30px', width: '480px', margin: 'auto' }}>
            <h3 style={{ fontSize: '18px', color: '#fff', margin: '0 0 15px 0' }}>Save Hunting Session AST</h3>
            
            <form onSubmit={handleSaveSession}>
              <div style={{ marginBottom: '15px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>SESSION NAME</label>
                <input
                  type="text"
                  required
                  value={sessionName}
                  onChange={(e) => setSessionName(e.target.value)}
                  placeholder="Suspicious Logins Investigation"
                  style={{ width: '100%', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff' }}
                />
              </div>

              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>DESCRIPTION</label>
                <input
                  type="text"
                  value={sessionDesc}
                  onChange={(e) => setSessionDesc(e.target.value)}
                  placeholder="Queries matching admin logins with lookalike domains..."
                  style={{ width: '100%', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                <button
                  type="button"
                  onClick={() => setSaveSessionOpen(false)}
                  style={{ background: 'transparent', border: '1px solid #334155', color: '#fff', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{ background: '#06b6d4', color: '#000', border: 'none', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer', fontWeight: '700' }}
                >
                  Save Workspace
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
};
export default ThreatHunting;

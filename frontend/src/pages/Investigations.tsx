import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Cpu, Clock, Trash2, Play, FileText, ArrowRight
} from 'lucide-react';

interface InvestigationItem {
  _id?: string;
  investigation_id: string;
  title: string;
  description: string;
  status: string;
  priority: string;
  severity: string;
  created_by: string;
  assigned_to?: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
}

interface EvidenceItem {
  _id: string;
  evidence_type: string;
  source_id: string;
  timestamp: string;
  metadata: any;
  added_by: string;
}

interface RelationshipItem {
  _id: string;
  source_type: string;
  source_id: string;
  target_type: string;
  target_id: string;
  relationship_type: string;
  confidence: string;
  explanation: string;
  evidence_reference: string;
}

interface TimelineItem {
  timestamp: string;
  type: string;
  title: string;
  description: string;
  actor: string;
}

interface NoteItem {
  _id: string;
  content: string;
  author: string;
  timestamp: string;
}

export default function Investigations() {
  const [cases, setCases] = useState<InvestigationItem[]>([]);
  const [selectedCase, setSelectedCase] = useState<InvestigationItem | null>(null);

  // Workspace sub-items
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [entities, setEntities] = useState<any[]>([]);
  const [relationships, setRelationships] = useState<RelationshipItem[]>([]);
  const [notes, setNotes] = useState<NoteItem[]>([]);
  const [timeline, setTimeline] = useState<TimelineItem[]>([]);

  const [loading, setLoading] = useState(true);
  const [_error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('timeline');
  const [graphData, setGraphData] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });
  const [graphLoading, setGraphLoading] = useState(false);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);

  // Input states
  const [noteContent, setNoteContent] = useState('');
  const [evidenceType, setEvidenceType] = useState('USER');
  const [evidenceSourceId, setEvidenceSourceId] = useState('');
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newPriority, setNewPriority] = useState('MEDIUM');
  const [newSeverity, setNewSeverity] = useState('MEDIUM');
  const [createOpen, setCreateOpen] = useState(false);

  // SOAR/GRC triggers state
  const [soarStatus, setSoarStatus] = useState('');
  const [grcStatus, setGrcStatus] = useState('');

  const token = localStorage.getItem('token');
  const config = {
    headers: { Authorization: `Bearer ${token}` }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError('');
      const res = await axios.get('/api/v1/investigations', config);
      setCases(res.data);
      if (res.data.length > 0) {
        handleSelectCase(res.data[0]);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to load cases');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectCase = async (item: InvestigationItem) => {
    const caseId = item.investigation_id || item._id;
    if (!caseId) return;
    
    // Set basic info immediately
    setSelectedCase(item);
    setSoarStatus('');
    setGrcStatus('');

    try {
      const res = await axios.get(`/api/v1/investigations/${caseId}`, config);
      const data = res.data;
      setEvidence(data.evidence || []);
      setEntities(data.entities || []);
      setRelationships(data.relationships || []);
      setNotes(data.notes || []);
      setTimeline(data.timeline || []);
    } catch (err: any) {
      console.error('Failed to load investigation details', err);
    }
  };

  useEffect(() => {
    if (selectedCase && activeTab === 'graph') {
      fetchGraphData();
    }
  }, [selectedCase, activeTab]);

  const fetchGraphData = async () => {
    if (!selectedCase) return;
    const caseId = selectedCase.investigation_id || selectedCase._id;
    try {
      setGraphLoading(true);
      const res = await axios.get(`/api/v1/investigations/${caseId}/graph`, config);
      setGraphData(res.data);
    } catch (err) {
      console.error('Failed to fetch graph data', err);
    } finally {
      setGraphLoading(false);
    }
  };

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const payload = {
        investigation_id: `INV-${Math.floor(Math.random() * 90000) + 10000}`,
        title: newTitle,
        description: newDesc,
        priority: newPriority.toLowerCase(),
        entities: [],
        evidence: []
      };

      await axios.post('/api/v1/investigations', payload, config);
      setNewTitle('');
      setNewDesc('');
      setCreateOpen(false);
      
      // Reload and select new case
      const updatedList = await axios.get('/api/v1/investigations', config);
      setCases(updatedList.data);
      const createdItem = updatedList.data.find((c: any) => c.investigation_id === payload.investigation_id);
      if (createdItem) {
        handleSelectCase(createdItem);
      }
    } catch (err: any) {
      alert('Creation failed: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleAddEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !evidenceSourceId) return;
    const caseId = selectedCase.investigation_id || selectedCase._id;
    try {
      await axios.post(`/api/v1/investigations/${caseId}/evidence`, {
        evidence_type: evidenceType,
        source_id: evidenceSourceId
      }, config);
      setEvidenceSourceId('');
      
      // Refresh case
      handleSelectCase(selectedCase);
    } catch (err: any) {
      alert('Failed to add evidence: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleRemoveEvidence = async (evidenceId: string) => {
    if (!selectedCase) return;
    const caseId = selectedCase.investigation_id || selectedCase._id;
    if (!confirm('Are you sure you want to remove this evidence?')) return;
    try {
      await axios.delete(`/api/v1/investigations/${caseId}/evidence/${evidenceId}`, config);
      handleSelectCase(selectedCase);
    } catch (err: any) {
      alert('Failed to remove evidence: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !noteContent) return;
    const caseId = selectedCase.investigation_id || selectedCase._id;
    try {
      await axios.post(`/api/v1/investigations/${caseId}/notes`, {
        content: noteContent
      }, config);
      setNoteContent('');
      handleSelectCase(selectedCase);
    } catch (err: any) {
      alert('Failed to save note: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleRunCorrelation = async () => {
    if (!selectedCase) return;
    const caseId = selectedCase.investigation_id || selectedCase._id;
    try {
      const res = await axios.post(`/api/v1/investigations/${caseId}/correlate`, {}, config);
      alert(`Correlation Completed! Created ${res.data.relationships_created} new entity links.`);
      handleSelectCase(selectedCase);
    } catch (err: any) {
      alert('Correlation failed: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleUpdateStatus = async (statusVal: string) => {
    if (!selectedCase) return;
    const caseId = selectedCase.investigation_id || selectedCase._id;
    try {
      await axios.patch(`/api/v1/investigations/${caseId}`, {
        status: statusVal
      }, config);
      
      const updatedList = await axios.get('/api/v1/investigations', config);
      setCases(updatedList.data);
      const updatedItem = updatedList.data.find((c: any) => (c.investigation_id || c._id) === caseId);
      if (updatedItem) {
        setSelectedCase(updatedItem);
      }
    } catch (err: any) {
      alert('Status change failed: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleTriggerSOAR = async () => {
    if (!selectedCase) return;
    const caseId = selectedCase.investigation_id || selectedCase._id;
    try {
      setSoarStatus('Triggering...');
      const res = await axios.post(`/api/v1/investigations/${caseId}/soar`, {}, config);
      setSoarStatus(`SOAR Playbook Triggered: ${res.data.remediation_workflow_id}. Actions: ${res.data.remediation_actions.join(', ')}`);
    } catch (err) {
      setSoarStatus('SOAR trigger failed');
    }
  };

  const handleExportGRC = async () => {
    if (!selectedCase) return;
    const caseId = selectedCase.investigation_id || selectedCase._id;
    try {
      setGrcStatus('Exporting...');
      const res = await axios.post(`/api/v1/investigations/${caseId}/grc`, {}, config);
      setGrcStatus(`Exported! Registered GRC Evidence ID: ${res.data.evidence_id}`);
    } catch (err) {
      setGrcStatus('Export failed');
    }
  };

  return (
    <div style={{ padding: '24px', background: '#090d16', minHeight: '100vh', color: '#f1f5f9' }}>
      
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h2 style={{ fontSize: '24px', fontWeight: '700', color: '#fff', margin: 0 }}>Investigations Workspace</h2>
          <p style={{ color: '#64748b', fontSize: '13px', margin: '4px 0 0 0' }}>
            Unified investigation timeline, multi-signal threat correlation, and compliance integrations.
          </p>
        </div>
        <button
          onClick={() => setCreateOpen(true)}
          style={{
            background: '#06b6d4',
            color: '#000',
            border: 'none',
            padding: '10px 16px',
            borderRadius: '8px',
            cursor: 'pointer',
            fontSize: '13px',
            fontWeight: '700'
          }}
        >
          New Investigation File
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '20px', alignItems: 'start' }}>
        
        {/* Case List Sidebar */}
        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '20px', minHeight: '75vh' }}>
          <h3 style={{ fontSize: '15px', fontWeight: '600', color: '#fff', margin: '0 0 15px 0' }}>Active Cases</h3>
          
          {loading && cases.length === 0 ? (
            <div style={{ color: '#64748b', fontSize: '13px' }}>Loading cases...</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {cases.map((c, idx) => {
                const active = selectedCase && (selectedCase.investigation_id === c.investigation_id || selectedCase._id === c._id);
                return (
                  <div
                    key={idx}
                    onClick={() => handleSelectCase(c)}
                    style={{
                      background: active ? '#1e293b' : '#111827',
                      border: active ? '1px solid #06b6d4' : '1px solid #1f2937',
                      padding: '12px',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      transition: 'all 0.15s'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                      <span style={{ fontSize: '12px', fontWeight: '700', color: '#06b6d4' }}>{c.investigation_id}</span>
                      <span style={{
                        background: c.status === 'CLOSED' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(251, 191, 36, 0.1)',
                        color: c.status === 'CLOSED' ? '#34d399' : '#fbbf24',
                        fontSize: '10px',
                        padding: '1px 6px',
                        borderRadius: '4px',
                        fontWeight: '700'
                      }}>{c.status}</span>
                    </div>
                    <h4 style={{ fontSize: '13px', fontWeight: '600', color: '#fff', margin: '0 0 4px 0' }}>{c.title}</h4>
                    <span style={{ color: '#64748b', fontSize: '11px' }}>Priority: {c.priority?.toUpperCase()}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Selected Case Workspace */}
        {selectedCase ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            
            {/* Header Details Panel */}
            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid #1e293b', paddingBottom: '15px', marginBottom: '15px' }}>
                <div>
                  <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                    <span style={{ color: '#06b6d4', fontWeight: '700', fontSize: '14px' }}>{selectedCase.investigation_id}</span>
                    <h3 style={{ fontSize: '18px', fontWeight: '700', color: '#fff', margin: 0 }}>{selectedCase.title}</h3>
                  </div>
                  <p style={{ color: '#94a3b8', fontSize: '13px', margin: '6px 0 0 0' }}>{selectedCase.description}</p>
                </div>
                
                {/* Status transitions control */}
                <div style={{ display: 'flex', gap: '10px' }}>
                  {selectedCase.status !== 'CLOSED' ? (
                    <>
                      {selectedCase.status === 'OPEN' && (
                        <button
                          onClick={() => handleUpdateStatus('INVESTIGATING')}
                          style={{ background: '#3b82f6', color: '#fff', border: 'none', padding: '8px 12px', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: '600' }}
                        >
                          Start Investigation
                        </button>
                      )}
                      {selectedCase.status === 'INVESTIGATING' && (
                        <button
                          onClick={() => handleUpdateStatus('CONTAINED')}
                          style={{ background: '#eab308', color: '#fff', border: 'none', padding: '8px 12px', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: '600' }}
                        >
                          Mark Contained
                        </button>
                      )}
                      {selectedCase.status === 'CONTAINED' && (
                        <button
                          onClick={() => handleUpdateStatus('RESOLVED')}
                          style={{ background: '#10b981', color: '#fff', border: 'none', padding: '8px 12px', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: '600' }}
                        >
                          Mark Resolved
                        </button>
                      )}
                      {selectedCase.status === 'RESOLVED' && (
                        <button
                          onClick={() => handleUpdateStatus('CLOSED')}
                          style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '8px 12px', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: '600' }}
                        >
                          Close Case
                        </button>
                      )}
                    </>
                  ) : (
                    <button
                      onClick={() => handleUpdateStatus('OPEN')}
                      style={{ background: '#1e293b', border: '1px solid #334155', color: '#fff', padding: '8px 12px', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: '600' }}
                    >
                      Re-open Case
                    </button>
                  )}

                  <button
                    onClick={handleRunCorrelation}
                    style={{
                      background: 'transparent',
                      border: '1px solid #06b6d4',
                      color: '#06b6d4',
                      padding: '8px 12px',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      fontSize: '12px',
                      fontWeight: '600',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px'
                    }}
                  >
                    <Play size={14} /> Run Correlation
                  </button>
                </div>
              </div>

              {/* Integrations Simulated Handoff Actions */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', background: '#111827', border: '1px solid #1f2937', padding: '15px', borderRadius: '8px' }}>
                <div>
                  <h4 style={{ fontSize: '13px', margin: '0 0 6px 0', color: '#fff', display: 'flex', gap: '6px', alignItems: 'center' }}>
                    <Cpu size={14} style={{ color: '#ef4444' }} /> E6 SOAR Playbook Handoff
                  </h4>
                  <button
                    onClick={handleTriggerSOAR}
                    style={{ background: '#ef4444', border: 'none', color: '#fff', padding: '6px 12px', borderRadius: '4px', cursor: 'pointer', fontSize: '12px', fontWeight: '600' }}
                  >
                    Trigger Remediation Response
                  </button>
                  {soarStatus && <p style={{ fontSize: '11px', color: '#cbd5e1', margin: '6px 0 0 0' }}>{soarStatus}</p>}
                </div>
                <div>
                  <h4 style={{ fontSize: '13px', margin: '0 0 6px 0', color: '#fff', display: 'flex', gap: '6px', alignItems: 'center' }}>
                    <FileText size={14} style={{ color: '#10b981' }} /> E7 GRC Evidence Export
                  </h4>
                  <button
                    onClick={handleExportGRC}
                    style={{ background: '#10b981', border: 'none', color: '#fff', padding: '6px 12px', borderRadius: '4px', cursor: 'pointer', fontSize: '12px', fontWeight: '600' }}
                  >
                    Export Compliance Audit Logs
                  </button>
                  {grcStatus && <p style={{ fontSize: '11px', color: '#cbd5e1', margin: '6px 0 0 0' }}>{grcStatus}</p>}
                </div>
              </div>
            </div>

            {/* Tabs Navigation */}
            <div style={{ display: 'flex', borderBottom: '1px solid #1e293b' }}>
              {['timeline', 'evidence', 'entities', 'relationships', 'notes', 'graph'].map((tab) => (
                <button
                  key={tab}
                  onClick={() => {
                    setActiveTab(tab);
                    setSelectedNode(null);
                  }}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    borderBottom: activeTab === tab ? '2px solid #06b6d4' : 'none',
                    color: activeTab === tab ? '#06b6d4' : '#64748b',
                    padding: '10px 20px',
                    cursor: 'pointer',
                    fontSize: '13px',
                    fontWeight: '600',
                    textTransform: 'capitalize'
                  }}
                >
                  {tab}
                </button>
              ))}
            </div>

            {/* Tab Contents */}
            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '20px', minHeight: '40vh' }}>
              
              {/* Dynamic Timeline */}
              {activeTab === 'timeline' && (
                <div>
                  <h3 style={{ fontSize: '15px', fontWeight: '600', color: '#fff', margin: '0 0 15px 0' }}>Unified Case Timeline</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                    {timeline.length === 0 ? (
                      <div style={{ color: '#64748b', fontSize: '13px' }}>No timeline events logged yet. Add evidence or run correlation.</div>
                    ) : (
                      timeline.map((t, idx) => (
                        <div key={idx} style={{ display: 'flex', gap: '15px', borderLeft: '2px solid #1e293b', paddingLeft: '15px', position: 'relative' }}>
                          <Clock size={12} style={{ color: '#64748b', position: 'absolute', left: '-7px', top: '2px', background: '#0f172a' }} />
                          <div>
                            <div style={{ fontSize: '12px', color: '#64748b' }}>{new Date(t.timestamp).toLocaleString()}</div>
                            <h4 style={{ fontSize: '13px', color: '#fff', fontWeight: '600', margin: '2px 0' }}>{t.title}</h4>
                            <p style={{ color: '#94a3b8', fontSize: '12px', margin: 0 }}>{t.description}</p>
                            <span style={{ fontSize: '11px', color: '#06b6d4', display: 'block', marginTop: '2px' }}>Actor: {t.actor}</span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}

              {/* Evidence Management */}
              {activeTab === 'evidence' && (
                <div>
                  <h3 style={{ fontSize: '15px', fontWeight: '600', color: '#fff', margin: '0 0 15px 0' }}>Linked Evidence References</h3>
                  
                  {/* Link Evidence Form */}
                  <form onSubmit={handleAddEvidence} style={{ display: 'flex', gap: '10px', marginBottom: '20px', background: '#111827', padding: '15px', borderRadius: '8px', border: '1px solid #1f2937' }}>
                    <select
                      value={evidenceType}
                      onChange={(e) => setEvidenceType(e.target.value)}
                      style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff', padding: '8px', width: '200px' }}
                    >
                      <option value="SECURITY_EVENT">Security Event ID</option>
                      <option value="DETECTION_FINDING">Detection Finding ID</option>
                      <option value="THREAT_INTELLIGENCE">Threat Intel IOC</option>
                      <option value="HUNT_RESULT">Hunt Finding ID</option>
                      <option value="INCIDENT">Incident ID</option>
                      <option value="USER">User Context (Email)</option>
                      <option value="DEVICE">Device ID</option>
                      <option value="IP">IP Address</option>
                      <option value="DOMAIN">Domain Name</option>
                      <option value="URL">URL link</option>
                    </select>

                    <input
                      type="text"
                      value={evidenceSourceId}
                      onChange={(e) => setEvidenceSourceId(e.target.value)}
                      placeholder="Source ID or Indicator value"
                      style={{ flex: 1, background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff', padding: '8px' }}
                    />

                    <button
                      type="submit"
                      style={{ background: '#06b6d4', border: 'none', color: '#000', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer', fontWeight: '600' }}
                    >
                      Add Evidence
                    </button>
                  </form>

                  {/* Evidence Table */}
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid #1e293b', color: '#64748b' }}>
                          <th style={{ padding: '10px' }}>Linked Date</th>
                          <th style={{ padding: '10px' }}>Evidence Type</th>
                          <th style={{ padding: '10px' }}>Source ID</th>
                          <th style={{ padding: '10px' }}>Metadata</th>
                          <th style={{ padding: '10px', textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {evidence.length === 0 ? (
                          <tr>
                            <td colSpan={5} style={{ textAlign: 'center', color: '#64748b', padding: '20px 0' }}>No evidence items linked to this investigation workspace.</td>
                          </tr>
                        ) : (
                          evidence.map((ev, idx) => (
                            <tr key={idx} style={{ borderBottom: '1px solid #1e293b' }}>
                              <td style={{ padding: '10px', color: '#cbd5e1' }}>{new Date(ev.timestamp).toLocaleString()}</td>
                              <td style={{ padding: '10px' }}><span style={{ background: 'rgba(6, 182, 212, 0.1)', color: '#06b6d4', padding: '2px 6px', borderRadius: '4px', fontSize: '11px' }}>{ev.evidence_type}</span></td>
                              <td style={{ padding: '10px', color: '#fff', fontWeight: '600' }}>{ev.source_id}</td>
                              <td style={{ padding: '10px', color: '#94a3b8' }}>{JSON.stringify(ev.metadata)}</td>
                              <td style={{ padding: '10px', textAlign: 'right' }}>
                                <button
                                  onClick={() => handleRemoveEvidence(ev._id)}
                                  style={{ background: 'transparent', border: 'none', color: '#ef4444', cursor: 'pointer' }}
                                >
                                  <Trash2 size={16} />
                                </button>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Dynamic Entity Pivot List */}
              {activeTab === 'entities' && (
                <div>
                  <h3 style={{ fontSize: '15px', fontWeight: '600', color: '#fff', margin: '0 0 15px 0' }}>Investigative Entities Pivot List</h3>
                  <p style={{ color: '#64748b', fontSize: '12px', margin: '-10px 0 15px 0' }}>Extracted automatically from evidence records. Drill-down checks isolating tenant contexts.</p>
                  
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '15px' }}>
                    {entities.length === 0 ? (
                      <div style={{ color: '#64748b', fontSize: '13px' }}>No entities found. Link evidence first.</div>
                    ) : (
                      entities.map((ent, idx) => (
                        <div key={idx} style={{ background: '#111827', border: '1px solid #1f2937', padding: '15px', borderRadius: '8px' }}>
                          <span style={{ fontSize: '10px', color: '#06b6d4', display: 'block', fontWeight: '700' }}>{ent.type}</span>
                          <span style={{ fontSize: '14px', color: '#fff', fontWeight: '700', wordBreak: 'break-all', display: 'block', marginTop: '4px' }}>{ent.id}</span>
                          <span style={{ fontSize: '11px', color: '#64748b', display: 'block', marginTop: '6px' }}>Origin: {ent.source}</span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}

              {/* Explanatory Correlation Relationships */}
              {activeTab === 'relationships' && (
                <div>
                  <h3 style={{ fontSize: '15px', fontWeight: '600', color: '#fff', margin: '0 0 15px 0' }}>Correlated Multi-Signal Relationships</h3>
                  
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {relationships.length === 0 ? (
                      <div style={{ color: '#64748b', fontSize: '13px' }}>No correlated relationships identified. Click "Run Correlation" to trigger resolution.</div>
                    ) : (
                      relationships.map((rel, idx) => (
                        <div key={idx} style={{ background: '#111827', border: '1px solid #1f2937', padding: '15px', borderRadius: '8px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px', fontWeight: '700', color: '#fff' }}>
                              <span>{rel.source_type} ({rel.source_id})</span>
                              <ArrowRight size={14} style={{ color: '#06b6d4' }} />
                              <span>{rel.target_type} ({rel.target_id})</span>
                            </div>
                            <span style={{
                              background: rel.confidence === 'HIGH' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                              color: rel.confidence === 'HIGH' ? '#34d399' : '#f87171',
                              fontSize: '10px',
                              padding: '2px 6px',
                              borderRadius: '4px',
                              fontWeight: '700'
                            }}>{rel.confidence} CONFIDENCE</span>
                          </div>
                          
                          <p style={{ color: '#cbd5e1', fontSize: '12px', margin: '4px 0' }}>{rel.explanation}</p>
                          <span style={{ fontSize: '11px', color: '#64748b', display: 'block' }}>Justification Evidence: {rel.evidence_reference}</span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}

              {/* Analyst notes log */}
              {activeTab === 'notes' && (
                <div>
                  <h3 style={{ fontSize: '15px', fontWeight: '600', color: '#fff', margin: '0 0 15px 0' }}>Analyst Investigation Notes</h3>
                  
                  {/* Notes List */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '20px' }}>
                    {notes.length === 0 ? (
                      <div style={{ color: '#64748b', fontSize: '13px' }}>No notes recorded for this case. Add comments below.</div>
                    ) : (
                      notes.map((n, idx) => (
                        <div key={idx} style={{ background: '#111827', border: '1px solid #1f2937', padding: '15px', borderRadius: '8px' }}>
                          <p style={{ margin: 0, color: '#f1f5f9', fontSize: '13px', whiteSpace: 'pre-wrap' }}>{n.content}</p>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '8px', fontSize: '11px', color: '#64748b' }}>
                            <span>Author: {n.author}</span>
                            <span>{new Date(n.timestamp).toLocaleString()}</span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Add Note Form */}
                  <form onSubmit={handleAddNote} style={{ borderTop: '1px solid #1e293b', paddingTop: '15px' }}>
                    <textarea
                      value={noteContent}
                      onChange={(e) => setNoteContent(e.target.value)}
                      placeholder="Add investigation comments, observations, and recommendations..."
                      style={{ width: '100%', height: '100px', background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', color: '#fff', padding: '10px', fontSize: '13px', marginBottom: '10px' }}
                    />
                    <button
                      type="submit"
                      disabled={!noteContent}
                      style={{ background: '#06b6d4', border: 'none', color: '#000', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer', fontWeight: '700' }}
                    >
                      Post Note
                    </button>
                  </form>
                </div>
              )}

              {activeTab === 'graph' && (() => {
                const centerX = 300;
                const centerY = 200;
                const radius = 140;
                
                const positionedNodes = graphData.nodes.map((node, index) => {
                  if (node.type === 'INVESTIGATION') {
                    return { ...node, x: centerX, y: centerY };
                  }
                  const angle = (index / (graphData.nodes.length - 1 || 1)) * 2 * Math.PI;
                  return {
                    ...node,
                    x: centerX + radius * Math.cos(angle),
                    y: centerY + radius * Math.sin(angle)
                  };
                });

                const nodeMap = new Map(positionedNodes.map(n => [n.id, n]));

                return (
                  <div>
                    <h3 style={{ fontSize: '15px', fontWeight: '600', color: '#fff', margin: '0 0 15px 0' }}>Incident Attack Path Graph</h3>
                    
                    {graphLoading ? (
                      <div style={{ color: '#64748b', fontSize: '13px' }}>Loading attack path graph...</div>
                    ) : graphData.nodes.length === 0 ? (
                      <div style={{ color: '#64748b', fontSize: '13px' }}>No graph nodes correlated for this investigation. Add evidence and run correlation.</div>
                    ) : (
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: '20px' }}>
                        {/* SVG Canvas */}
                        <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', overflow: 'hidden', position: 'relative', height: '420px' }}>
                          <svg width="100%" height="100%">
                            <defs>
                              <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                                <path d="M 0 0 L 10 5 L 0 10 z" fill="#334155" />
                              </marker>
                            </defs>

                            {/* Edges */}
                            {graphData.edges.map((edge, idx) => {
                              const sourceNode = nodeMap.get(edge.source);
                              const targetNode = nodeMap.get(edge.target);
                              if (!sourceNode || !targetNode) return null;
                              return (
                                <g key={idx}>
                                  <line
                                    x1={sourceNode.x}
                                    y1={sourceNode.y}
                                    x2={targetNode.x}
                                    y2={targetNode.y}
                                    stroke="#334155"
                                    strokeWidth="1.5"
                                    markerEnd="url(#arrow)"
                                  />
                                  <text
                                    x={(sourceNode.x + targetNode.x) / 2}
                                    y={(sourceNode.y + targetNode.y) / 2 - 4}
                                    fill="#475569"
                                    fontSize="8"
                                    fontWeight="bold"
                                    textAnchor="middle"
                                  >
                                    {edge.label}
                                  </text>
                                </g>
                              );
                            })}

                            {/* Nodes */}
                            {positionedNodes.map((node) => (
                              <g
                                key={node.id}
                                transform={`translate(${node.x},${node.y})`}
                                onClick={() => setSelectedNode(node)}
                                style={{ cursor: 'pointer' }}
                              >
                                <circle
                                  r="16"
                                  fill={node.color}
                                  stroke={selectedNode?.id === node.id ? '#fff' : 'none'}
                                  strokeWidth="2"
                                />
                                <text
                                  fill="#000"
                                  fontSize="9"
                                  fontWeight="bold"
                                  textAnchor="middle"
                                  dy="3"
                                >
                                  {node.type.slice(0, 3)}
                                </text>
                                <text
                                  fill="#94a3b8"
                                  fontSize="9"
                                  textAnchor="middle"
                                  dy="28"
                                >
                                  {node.label.length > 12 ? `${node.label.slice(0, 9)}...` : node.label}
                                </text>
                              </g>
                            ))}
                          </svg>
                        </div>

                        {/* Info Panel Sidebar */}
                        <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '15px' }}>
                          <h4 style={{ fontSize: '13px', fontWeight: '750', color: '#fff', margin: '0 0 12px 0' }}>Node Details</h4>
                          {selectedNode ? (
                            <div style={{ fontSize: '12px', color: '#cbd5e1' }}>
                              <div style={{ marginBottom: '8px' }}>
                                <span style={{ color: '#64748b', display: 'block', textTransform: 'uppercase', fontSize: '9px' }}>Type</span>
                                <strong style={{ color: selectedNode.color }}>{selectedNode.type}</strong>
                              </div>
                              <div style={{ marginBottom: '8px' }}>
                                <span style={{ color: '#64748b', display: 'block', textTransform: 'uppercase', fontSize: '9px' }}>Identifier</span>
                                <strong style={{ color: '#fff', wordBreak: 'break-all' }}>{selectedNode.label}</strong>
                              </div>
                              {selectedNode.metadata?.threat_intel_reputation && (
                                <div style={{ marginBottom: '8px', padding: '8px', background: '#451a03', border: '1px solid #78350f', borderRadius: '4px' }}>
                                  <span style={{ color: '#f59e0b', fontWeight: 'bold', display: 'block', fontSize: '9px' }}>E4 THREAT INTEL REPUTATION</span>
                                  <span style={{ color: '#fcd34d' }}>{selectedNode.metadata.threat_intel_reputation} Severity</span>
                                  <p style={{ margin: '4px 0 0 0', color: '#fef3c7', fontSize: '10px' }}>{selectedNode.metadata.threat_intel_description}</p>
                                </div>
                              )}
                              {selectedNode.metadata?.ueba_risk_score !== undefined && (
                                <div style={{ marginBottom: '8px', padding: '8px', background: '#18181b', border: '1px solid #27272a', borderRadius: '4px' }}>
                                  <span style={{ color: '#38bdf8', fontWeight: 'bold', display: 'block', fontSize: '9px' }}>E9 UEBA ANOMALY INDEX</span>
                                  <span style={{ color: '#fff' }}>Risk Score: {selectedNode.metadata.ueba_risk_score}</span>
                                </div>
                              )}
                              {selectedNode.metadata?.mitre_technique && (
                                <div style={{ marginBottom: '8px', padding: '8px', background: '#881337', border: '1px solid #9f1239', borderRadius: '4px' }}>
                                  <span style={{ color: '#f43f5e', fontWeight: 'bold', display: 'block', fontSize: '9px' }}>MITRE ATT&CK TECHNIQUE</span>
                                  <span style={{ color: '#fff', fontWeight: 'bold' }}>{selectedNode.metadata.mitre_technique}</span>
                                  <p style={{ margin: '4px 0 0 0', color: '#fda4af', fontSize: '10px' }}>{selectedNode.metadata.mitre_description}</p>
                                </div>
                              )}
                            </div>
                          ) : (
                            <div style={{ color: '#64748b', fontSize: '11px', textAlign: 'center', padding: '30px 0' }}>
                              Click on a graph node to display correlation intelligence details.
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}

            </div>
          </div>
        ) : (
          <div style={{ background: '#0f172a', border: '1px dashed #1e293b', borderRadius: '12px', padding: '40px', textAlign: 'center', color: '#64748b', fontSize: '13px' }}>
            Select an active security investigation from the sidebar to inspect workspace details.
          </div>
        )}

      </div>

      {/* Create Case Modal Dialog */}
      {createOpen && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '30px', width: '480px', margin: 'auto' }}>
            <h3 style={{ fontSize: '18px', color: '#fff', margin: '0 0 15px 0' }}>Create Investigation Workspace</h3>
            
            <form onSubmit={handleCreateCase}>
              <div style={{ marginBottom: '15px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>CASE TITLE</label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="Anomalous Domain Access Overlap"
                  style={{ width: '100%', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff' }}
                />
              </div>

              <div style={{ marginBottom: '15px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>DESCRIPTION</label>
                <input
                  type="text"
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Correlating phishing domain telemetry with elevated UEBA scores..."
                  style={{ width: '100%', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', marginBottom: '20px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>PRIORITY</label>
                  <select
                    value={newPriority}
                    onChange={(e) => setNewPriority(e.target.value)}
                    style={{ width: '100%', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff' }}
                  >
                    <option value="LOW">Low</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="HIGH">High</option>
                    <option value="CRITICAL">Critical</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>SEVERITY</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value)}
                    style={{ width: '100%', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#fff' }}
                  >
                    <option value="LOW">Low</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="HIGH">High</option>
                    <option value="CRITICAL">Critical</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                <button
                  type="button"
                  onClick={() => setCreateOpen(false)}
                  style={{ background: 'transparent', border: '1px solid #334155', color: '#fff', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{ background: '#06b6d4', color: '#000', border: 'none', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer', fontWeight: '700' }}
                >
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
}

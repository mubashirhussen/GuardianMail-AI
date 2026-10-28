import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  ShieldAlert, Layers, Target, Clock, Plus, Trash2,
  FileText, RefreshCw, AlertCircle
} from 'lucide-react';

interface CampaignItem {
  _id?: string;
  campaign_id: string;
  name: string;
  description: string;
  status: string;
  confidence: string;
  indicators: string[];
  affected_users: string[];
  related_investigations: string[];
  notes: Array<{
    content: string;
    author: string;
    timestamp: string;
  }>;
  created_at: string;
  updated_at: string;
}

interface TimelineItem {
  timestamp: string;
  type: string;
  title: string;
  description: string;
  source: string;
}

export default function Campaigns() {
  const [campaigns, setCampaigns] = useState<CampaignItem[]>([]);
  const [selectedCampaign, setSelectedCampaign] = useState<CampaignItem | null>(null);
  const [workspace, setWorkspace] = useState<{
    campaign: CampaignItem | null;
    investigations: any[];
    timeline: TimelineItem[];
  }>({ campaign: null, investigations: [], timeline: [] });

  const [loading, setLoading] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeFilter, setActiveFilter] = useState('ALL');

  // Creation/Input States
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newStatus, setNewStatus] = useState('SUSPECTED');
  const [newConfidence, setNewConfidence] = useState('medium');

  // Detail Input States
  const [noteContent, setNoteContent] = useState('');
  const [evidenceType, setEvidenceType] = useState('IP');
  const [evidenceValue, setEvidenceValue] = useState('');

  const token = localStorage.getItem('token');
  const config = {
    headers: { Authorization: `Bearer ${token}` }
  };

  useEffect(() => {
    fetchCampaigns();
  }, []);

  const fetchCampaigns = async () => {
    try {
      setLoading(true);
      setError('');
      const res = await axios.get('/api/v1/campaigns', config);
      setCampaigns(res.data);
      if (selectedCampaign) {
        // Refresh selected campaign workspace
        const matching = res.data.find((c: CampaignItem) => c.campaign_id === selectedCampaign.campaign_id);
        if (matching) {
          fetchWorkspaceDetails(matching.campaign_id);
        }
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load campaigns');
    } finally {
      setLoading(false);
    }
  };

  const fetchWorkspaceDetails = async (campId: string) => {
    try {
      const res = await axios.get(`/api/v1/campaigns/${campId}`, config);
      setWorkspace(res.data);
    } catch (err: any) {
      setError('Failed to fetch campaign workspace');
    }
  };

  const handleCreateCampaign = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setError('');
      const res = await axios.post('/api/v1/campaigns', {
        name: newName,
        description: newDesc,
        status: newStatus,
        confidence: newConfidence
      }, config);
      setCreateOpen(false);
      setNewName('');
      setNewDesc('');
      fetchCampaigns();
      handleSelectCampaign(res.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create campaign');
    }
  };

  const handleSelectCampaign = (camp: CampaignItem) => {
    setSelectedCampaign(camp);
    fetchWorkspaceDetails(camp.campaign_id);
  };

  const handleStatusChange = async (statusVal: string) => {
    if (!selectedCampaign) return;
    try {
      await axios.patch(`/api/v1/campaigns/${selectedCampaign.campaign_id}`, {
        status: statusVal
      }, config);
      fetchCampaigns();
    } catch (err: any) {
      setError('Failed to update status');
    }
  };

  const handleConfidenceChange = async (confVal: string) => {
    if (!selectedCampaign) return;
    try {
      await axios.patch(`/api/v1/campaigns/${selectedCampaign.campaign_id}`, {
        confidence: confVal
      }, config);
      fetchCampaigns();
    } catch (err: any) {
      setError('Failed to update confidence');
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCampaign || !noteContent.trim()) return;
    try {
      await axios.post(`/api/v1/campaigns/${selectedCampaign.campaign_id}/notes`, {
        content: noteContent
      }, config);
      setNoteContent('');
      fetchWorkspaceDetails(selectedCampaign.campaign_id);
    } catch (err: any) {
      setError('Failed to add note');
    }
  };

  const handleAddEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCampaign || !evidenceValue.trim()) return;
    try {
      await axios.post(`/api/v1/campaigns/${selectedCampaign.campaign_id}/evidence`, {
        evidence_type: evidenceType,
        source_id: evidenceValue
      }, config);
      setEvidenceValue('');
      fetchWorkspaceDetails(selectedCampaign.campaign_id);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to link evidence');
    }
  };

  const handleRemoveEvidence = async (type: string, val: string) => {
    if (!selectedCampaign) return;
    try {
      await axios.delete(`/api/v1/campaigns/${selectedCampaign.campaign_id}/evidence/${type}/${val}`, config);
      fetchWorkspaceDetails(selectedCampaign.campaign_id);
    } catch (err: any) {
      setError('Failed to remove evidence link');
    }
  };

  const triggerScan = async () => {
    try {
      setScanLoading(true);
      setError('');
      const res = await axios.post('/api/v1/campaigns/detect', {}, config);
      alert(`Campaign Scan Completed! Discovered ${res.data.campaigns_discovered} candidates.`);
      fetchCampaigns();
    } catch (err: any) {
      setError('Campaign scan execution failed');
    } finally {
      setScanLoading(false);
    }
  };

  const filteredCampaigns = campaigns.filter(c => {
    if (activeFilter === 'ALL') return true;
    return c.status === activeFilter;
  });

  return (
    <div className="flex-1 overflow-y-auto p-8 bg-slate-950 text-slate-100 min-h-screen">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Target className="h-8 w-8 text-indigo-500" />
            Campaign Intelligence Workspace
          </h1>
          <p className="text-slate-400 mt-1">Cross-incident infrastructure overlap and correlation management.</p>
        </div>
        <div className="flex gap-4">
          <button
            onClick={triggerScan}
            disabled={scanLoading}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-emerald-600 to-teal-500 hover:from-emerald-500 hover:to-teal-400 text-white rounded-lg font-medium transition disabled:opacity-50"
          >
            {scanLoading ? <RefreshCw className="h-5 w-5 animate-spin" /> : <RefreshCw className="h-5 w-5" />}
            Trigger Campaign Scan
          </button>
          <button
            onClick={() => setCreateOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium transition"
          >
            <Plus className="h-5 w-5" />
            Create Campaign Case
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-rose-950 border border-rose-800 rounded-lg text-rose-200 flex items-center gap-3">
          <AlertCircle className="h-5 w-5 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Creation Modal */}
      {createOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl">
            <h3 className="text-xl font-bold text-white mb-4">Manual Campaign Case File</h3>
            <form onSubmit={handleCreateCampaign} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-1">Campaign Name</label>
                <input
                  type="text"
                  required
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:outline-none focus:border-indigo-500"
                  placeholder="e.g. APT29 Phishing Infrastructure overlap"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-1">Description</label>
                <textarea
                  required
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  rows={4}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:outline-none focus:border-indigo-500"
                  placeholder="Summarize the core hypothesis..."
                ></textarea>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-1">Status</label>
                  <select
                    value={newStatus}
                    onChange={(e) => setNewStatus(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:outline-none focus:border-indigo-500"
                  >
                    <option value="SUSPECTED">Suspected</option>
                    <option value="UNDER_REVIEW">Under Review</option>
                    <option value="CONFIRMED">Confirmed</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-1">Confidence</label>
                  <select
                    value={newConfidence}
                    onChange={(e) => setNewConfidence(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:outline-none focus:border-indigo-500"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                  </select>
                </div>
              </div>
              <div className="flex justify-end gap-3 mt-6">
                <button
                  type="button"
                  onClick={() => setCreateOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition"
                >
                  Create
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="h-8 w-8 text-indigo-500 animate-spin" />
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* List Panel */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 backdrop-blur-sm">
            <h2 className="text-xl font-bold text-white mb-4">Registered Campaigns</h2>
            <div className="flex gap-2 mb-4 overflow-x-auto pb-2">
              {['ALL', 'SUSPECTED', 'UNDER_REVIEW', 'CONFIRMED', 'CLOSED', 'DISMISSED'].map((filter) => (
                <button
                  key={filter}
                  onClick={() => setActiveFilter(filter)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold uppercase tracking-wider transition shrink-0 ${
                    activeFilter === filter
                      ? 'bg-indigo-600 text-white'
                      : 'bg-slate-800 text-slate-400 hover:bg-slate-750'
                  }`}
                >
                  {filter.replace('_', ' ')}
                </button>
              ))}
            </div>

            <div className="space-y-4">
              {filteredCampaigns.map((camp) => (
                <div
                  key={camp.campaign_id}
                  onClick={() => handleSelectCampaign(camp)}
                  className={`p-4 border rounded-xl cursor-pointer transition ${
                    selectedCampaign?.campaign_id === camp.campaign_id
                      ? 'bg-slate-800/80 border-indigo-500 shadow-lg'
                      : 'bg-slate-950/60 border-slate-850 hover:bg-slate-900/60'
                  }`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className="font-bold text-white block text-sm">{camp.name}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider ${
                      camp.status === 'CONFIRMED'
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        : camp.status === 'SUSPECTED'
                        ? 'bg-amber-950 text-amber-400 border border-amber-800'
                        : 'bg-slate-900 text-slate-400 border border-slate-800'
                    }`}>
                      {camp.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 line-clamp-2 mb-3">{camp.description}</p>
                  <div className="flex justify-between items-center text-[10px] text-slate-500">
                    <span>ID: {camp.campaign_id}</span>
                    <span>Confidence: <strong className="uppercase">{camp.confidence}</strong></span>
                  </div>
                </div>
              ))}
              {filteredCampaigns.length === 0 && (
                <p className="text-slate-500 text-sm text-center py-8">No campaigns match criteria.</p>
              )}
            </div>
          </div>

          {/* Details Workspace Panel */}
          {selectedCampaign ? (
            <div className="lg:col-span-2 space-y-6">
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 backdrop-blur-sm">
                <div className="flex justify-between items-start mb-4 border-b border-slate-800 pb-4">
                  <div>
                    <h2 className="text-2xl font-bold text-white">{workspace.campaign?.name}</h2>
                    <p className="text-slate-400 text-sm mt-1">{workspace.campaign?.description}</p>
                  </div>
                  <div className="flex gap-4">
                    <div>
                      <label className="block text-[10px] uppercase font-bold text-slate-500 mb-1">Status</label>
                      <select
                        value={workspace.campaign?.status}
                        onChange={(e) => handleStatusChange(e.target.value)}
                        className="bg-slate-950 border border-slate-850 rounded p-1.5 text-xs text-white focus:outline-none"
                      >
                        <option value="SUSPECTED">Suspected</option>
                        <option value="UNDER_REVIEW">Under Review</option>
                        <option value="CONFIRMED">Confirmed</option>
                        <option value="DISMISSED">Dismissed</option>
                        <option value="CLOSED">Closed</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[10px] uppercase font-bold text-slate-500 mb-1">Confidence</label>
                      <select
                        value={workspace.campaign?.confidence}
                        onChange={(e) => handleConfidenceChange(e.target.value)}
                        className="bg-slate-950 border border-slate-850 rounded p-1.5 text-xs text-white focus:outline-none"
                      >
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                        <option value="confirmed">Confirmed</option>
                      </select>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mt-6">
                  {/* Indicators & Linked Investigations */}
                  <div>
                    <h3 className="text-md font-bold text-white flex items-center gap-2 mb-3">
                      <Layers className="h-5 w-5 text-indigo-400" />
                      Associated Evidence
                    </h3>
                    
                    <div className="space-y-4">
                      {/* Form to link */}
                      <form onSubmit={handleAddEvidence} className="flex gap-2">
                        <select
                          value={evidenceType}
                          onChange={(e) => setEvidenceType(e.target.value)}
                          className="bg-slate-950 border border-slate-850 rounded-lg p-1.5 text-xs text-white"
                        >
                          <option value="INVESTIGATION">Investigation</option>
                          <option value="IP">IP Address</option>
                          <option value="DOMAIN">Domain</option>
                          <option value="URL">URL</option>
                          <option value="FILE_HASH">File Hash</option>
                        </select>
                        <input
                          type="text"
                          required
                          value={evidenceValue}
                          onChange={(e) => setEvidenceValue(e.target.value)}
                          placeholder="Identifier value..."
                          className="flex-1 bg-slate-950 border border-slate-850 rounded-lg p-1.5 text-xs text-white placeholder-slate-600 focus:outline-none"
                        />
                        <button type="submit" className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-xs font-bold transition">
                          Link
                        </button>
                      </form>

                      {/* Display evidence */}
                      <div className="max-h-60 overflow-y-auto space-y-2 pr-2">
                        {workspace.campaign?.related_investigations?.map(inv => (
                          <div key={inv} className="flex justify-between items-center bg-slate-950 p-2.5 rounded-lg border border-slate-850">
                            <div className="text-xs text-slate-350">
                              <span className="font-bold text-indigo-400 mr-2">INCIDENT</span>
                              {inv}
                            </div>
                            <button
                              onClick={() => handleRemoveEvidence('INVESTIGATION', inv)}
                              className="text-slate-600 hover:text-rose-400 transition"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </div>
                        ))}
                        {workspace.campaign?.indicators?.map(ind => (
                          <div key={ind} className="flex justify-between items-center bg-slate-950 p-2.5 rounded-lg border border-slate-850">
                            <div className="text-xs text-slate-350">
                              <span className="font-bold text-amber-500 mr-2">IOC</span>
                              {ind}
                            </div>
                            <button
                              onClick={() => handleRemoveEvidence('IP', ind)} // Re-uses general removal
                              className="text-slate-600 hover:text-rose-400 transition"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Analyst review notes */}
                  <div>
                    <h3 className="text-md font-bold text-white flex items-center gap-2 mb-3">
                      <FileText className="h-5 w-5 text-indigo-400" />
                      Analyst Case Notes
                    </h3>

                    <form onSubmit={handleAddNote} className="mb-4">
                      <textarea
                        required
                        value={noteContent}
                        onChange={(e) => setNoteContent(e.target.value)}
                        placeholder="Log observations, campaigns attribution remarks..."
                        rows={2}
                        className="w-full bg-slate-950 border border-slate-850 rounded-lg p-2.5 text-xs text-white placeholder-slate-600 focus:outline-none mb-2"
                      />
                      <button type="submit" className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-xs font-bold transition">
                        Add Note
                      </button>
                    </form>

                    <div className="space-y-3 max-h-60 overflow-y-auto pr-2">
                      {workspace.campaign?.notes?.map((note, idx) => (
                        <div key={idx} className="bg-slate-950 p-3 rounded-lg border border-slate-850 text-xs">
                          <div className="flex justify-between text-[10px] text-slate-500 mb-1">
                            <span>Author: {note.author}</span>
                            <span>{new Date(note.timestamp).toLocaleString()}</span>
                          </div>
                          <p className="text-slate-300">{note.content}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Timeline display */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 backdrop-blur-sm">
                <h3 className="text-lg font-bold text-white flex items-center gap-2 mb-4">
                  <Clock className="h-5 w-5 text-indigo-400" />
                  Chronological Campaign Timeline
                </h3>
                <div className="space-y-6 relative before:absolute before:left-[11px] before:top-2 before:bottom-2 before:w-[2px] before:bg-slate-800">
                  {workspace.timeline?.map((evt, idx) => (
                    <div key={idx} className="relative pl-8">
                      <div className={`absolute left-0 top-1.5 w-6 h-6 rounded-full border border-slate-900 flex items-center justify-center ${
                        evt.type === 'CAMPAIGN_NOTE' ? 'bg-indigo-600' : 'bg-amber-600'
                      }`}>
                        {evt.type === 'CAMPAIGN_NOTE' ? <FileText className="h-3 w-3 text-white" /> : <ShieldAlert className="h-3 w-3 text-white" />}
                      </div>
                      <div className="flex items-center justify-between text-xs mb-1">
                        <span className="font-semibold text-white">{evt.title}</span>
                        <span className="text-slate-500">{new Date(evt.timestamp).toLocaleString()}</span>
                      </div>
                      <p className="text-slate-400 text-xs">{evt.description}</p>
                      <div className="text-[10px] text-slate-500 mt-1">Source: {evt.source}</div>
                    </div>
                  ))}
                  {workspace.timeline?.length === 0 && (
                    <p className="text-slate-500 text-xs py-4 text-center">Timeline details unavailable.</p>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="lg:col-span-2 flex flex-col items-center justify-center bg-slate-900/60 border border-slate-800 rounded-xl p-12 text-slate-500 min-h-[400px]">
              <Target className="h-16 w-16 text-slate-700 mb-4" />
              <p className="text-sm">Select a Campaign from the list to view its workspace details.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

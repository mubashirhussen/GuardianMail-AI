import React, { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { incidentsService } from '../services/incidents';
import { 
  ArrowLeft, Terminal, CheckCircle2, Clock, 
  RefreshCw, FileText, Download, 
  CheckSquare, Square, User, AlertCircle, Cpu
} from 'lucide-react';
import { Loader } from '../components/Loader';

export const IncidentDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  
  // Local input states
  const [newNote, setNewNote] = useState('');
  const [newEvent, setNewEvent] = useState('');
  const [newEventDesc, setNewEventDesc] = useState('');
  const [recipientEntity, setRecipientEntity] = useState('');
  const [templateType, setTemplateType] = useState('Trademark/Brand Spoof');
  const [generatedDraft, setGeneratedDraft] = useState<any | null>(null);

  // AI Copilot state
  const [copilotLoading, setCopilotLoading] = useState(false);
  const [copilotResponse, setCopilotResponse] = useState<string | null>(null);
  const [copilotInput, setCopilotInput] = useState('');

  const handleRunCopilotAnalysis = async () => {
    setCopilotLoading(true);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`/api/v1/copilot/investigations/${id}/analyze`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setCopilotResponse(data.content);
      } else {
        const err = await res.json();
        setCopilotResponse(`Error: ${err.detail || 'Could not analyze.'}`);
      }
    } catch (e: any) {
      setCopilotResponse(`Connection error: ${e.message}`);
    }
    setCopilotLoading(false);
  };

  const handleAskCopilot = async () => {
    if (!copilotInput.trim()) return;
    setCopilotLoading(true);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`/api/v1/copilot/chat`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          query: `Regarding investigation ID ${id}: ${copilotInput}`
        })
      });
      if (res.ok) {
        const data = await res.json();
        setCopilotResponse(data.content);
        setCopilotInput('');
      } else {
        const err = await res.json();
        setCopilotResponse(`Error: ${err.detail || 'Could not query.'}`);
      }
    } catch (e: any) {
      setCopilotResponse(`Connection error: ${e.message}`);
    }
    setCopilotLoading(false);
  };

  // 1. Query: Incident Details
  const { data: incident, isLoading: incLoading, error: incError } = useQuery({
    queryKey: ['incidents', 'detail', id],
    queryFn: () => incidentsService.getIncident(id!),
    enabled: !!id
  });

  // 2. Query: Timeline Events
  const { data: timeline, isLoading: tlLoading } = useQuery({
    queryKey: ['incidents', 'timeline', id],
    queryFn: () => incidentsService.getTimeline(id!),
    enabled: !!id
  });

  // 3. Query: Recovery Checklist Actions
  const { data: checklist, isLoading: clLoading } = useQuery({
    queryKey: ['incidents', 'recovery', id],
    queryFn: () => incidentsService.getRecoveryChecklist(id!),
    enabled: !!id
  });

  // 4. Query: Notes
  const { data: notes, isLoading: notesLoading } = useQuery({
    queryKey: ['incidents', 'notes', id],
    queryFn: () => incidentsService.getNotes(id!),
    enabled: !!id
  });

  // Mutations
  const toggleActionMutation = useMutation({
    mutationFn: ({ actionId, isCompleted }: { actionId: string; isCompleted: boolean }) => 
      incidentsService.toggleRecoveryAction(actionId, isCompleted),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents', 'recovery', id] });
    }
  });

  const addNoteMutation = useMutation({
    mutationFn: (text: string) => incidentsService.addNote(id!, text),
    onSuccess: () => {
      setNewNote('');
      queryClient.invalidateQueries({ queryKey: ['incidents', 'notes', id] });
    }
  });

  const addTimelineMutation = useMutation({
    mutationFn: ({ event, desc }: { event: string; desc: string }) => 
      incidentsService.addTimelineEvent(id!, event, desc),
    onSuccess: () => {
      setNewEvent('');
      setNewEventDesc('');
      queryClient.invalidateQueries({ queryKey: ['incidents', 'timeline', id] });
    }
  });

  const generateEvidenceMutation = useMutation({
    mutationFn: () => incidentsService.generateEvidencePackage(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents', 'detail', id] });
      alert('Forensics evidence package compiled and cached in DB.');
    }
  });

  const generateComplaintMutation = useMutation({
    mutationFn: () => incidentsService.generateComplaintDraft(id!, recipientEntity, templateType),
    onSuccess: (data) => {
      setGeneratedDraft(data);
      queryClient.invalidateQueries({ queryKey: ['incidents', 'detail', id] });
    },
    onError: (err: any) => {
      alert(err?.response?.data?.detail || 'Failed to compile takedown letter.');
    }
  });

  const handleDownloadBundle = async () => {
    try {
      const blob = await incidentsService.downloadForensicBundle(id!);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `forensics_${incident?.incident_id || 'bundle'}.zip`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch {
      alert('Forensic bundle package files not ready yet. Compile evidence packages first.');
    }
  };

  if (incLoading) {
    return (
      <div className="min-h-[400px] flex items-center justify-center">
        <Loader />
      </div>
    );
  }

  if (incError || !incident) {
    return (
      <div className="flex flex-col items-center justify-center p-12 bg-slate-900 border border-slate-800 rounded-xl text-center max-w-xl mx-auto my-12">
        <AlertCircle className="h-12 w-12 text-red-500 mb-4 animate-bounce" />
        <h2 className="text-xl font-bold text-slate-100 mb-2">Sync Error</h2>
        <p className="text-sm text-slate-400 mb-6">Could not pull forensics data for the requested incident ticket.</p>
        <Link to="/incidents" className="px-4 py-2 bg-slate-800 hover:bg-slate-750 text-slate-200 rounded-lg text-xs font-semibold">
          Return to queue
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top action header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <button 
          onClick={() => navigate('/incidents')} 
          className="inline-flex items-center gap-2 text-xs font-semibold text-slate-400 hover:text-slate-200 transition"
        >
          <ArrowLeft className="h-4 w-4" /> Return to SOC desk queue
        </button>

        <div className="flex items-center gap-3">
          <button
            onClick={() => generateEvidenceMutation.mutate()}
            disabled={generateEvidenceMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 rounded-lg text-xs font-semibold transition"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${generateEvidenceMutation.isPending ? 'animate-spin' : ''}`} />
            Compile Evidence
          </button>
          
          <button
            onClick={handleDownloadBundle}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-400 hover:to-cyan-500 text-slate-950 rounded-lg text-xs font-bold transition"
          >
            <Download className="h-3.5 w-3.5" />
            Download Forensics Bundle
          </button>
        </div>
      </div>

      {/* Main Grid: Info layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Ticket details overview */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-5">
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-cyan-400">
              <Terminal className="h-4.5 w-4.5" />
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">{incident.incident_id}</h3>
            </div>
            
            <div className="grid grid-cols-2 gap-4 text-xs font-semibold">
              <div className="p-2.5 bg-slate-950/40 border border-slate-850 rounded-lg">
                <span className="text-slate-500 block text-[9px] uppercase tracking-wider mb-1">Clearance Severity</span>
                <span className="text-red-400">{incident.threat_severity}</span>
              </div>
              <div className="p-2.5 bg-slate-950/40 border border-slate-850 rounded-lg">
                <span className="text-slate-500 block text-[9px] uppercase tracking-wider mb-1">Incident Status</span>
                <span className="text-amber-400">{incident.status}</span>
              </div>
            </div>
          </div>

          <hr className="border-slate-800" />

          {/* Forensic tags & identities */}
          <div className="space-y-3.5 text-xs font-medium">
            <div>
              <span className="text-slate-500 block text-[9px] uppercase">Threat Category</span>
              <span className="text-slate-350">{incident.threat_category}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[9px] uppercase">Affected Identity</span>
              <span className="text-slate-350 truncate block">{incident.affected_email}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[9px] uppercase">Detection Time</span>
              <span className="text-slate-350">{new Date(incident.detection_time).toLocaleString()}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[9px] uppercase">Incident Tags</span>
              <div className="flex flex-wrap gap-1.5 mt-1">
                {incident.tags?.map((tag) => (
                  <span key={tag} className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-slate-950 border border-slate-850 text-slate-400">
                    {tag}
                  </span>
                )) || <span className="text-slate-600">None</span>}
              </div>
            </div>
          </div>

          <hr className="border-slate-800" />

          {/* Notes module */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Investigation Logs</h4>
            <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
              {notesLoading ? (
                <div className="text-[10px] text-slate-500">Loading analyst logs...</div>
              ) : notes && notes.length > 0 ? (
                notes.map((n, idx) => (
                  <div key={idx} className="p-2.5 bg-slate-950/40 border border-slate-850 rounded-lg text-[10px] space-y-1">
                    <p className="text-slate-300 font-sans">{n.note_content || n.content}</p>
                    <div className="flex items-center justify-between text-slate-550 font-bold">
                      <span className="flex items-center gap-1"><User className="h-3 w-3" /> SOC Analyst</span>
                      <span>{n.created_at ? new Date(n.created_at).toLocaleDateString() : ''}</span>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-[10px] text-slate-550 italic">No notes logged. Enter updates below.</p>
              )}
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                placeholder="Log containment actions..."
                className="flex-1 bg-slate-950/60 border border-slate-800 rounded-lg px-2.5 py-1.5 text-[10px] text-slate-200 outline-none placeholder:text-slate-600"
              />
              <button 
                onClick={() => newNote && addNoteMutation.mutate(newNote)}
                className="px-3 py-1.5 bg-slate-850 hover:bg-slate-750 text-slate-300 border border-slate-800 rounded-lg text-[10px] font-semibold transition"
              >
                Log
              </button>
            </div>
          </div>

        </div>

        {/* Right Columns: Incident checklists & Timelines */}
        <div className="lg:col-span-2 space-y-6">
          {/* Recovery checklist actions */}
          <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-4">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4.5 w-4.5 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200">Incident Mitigation Checklist</h3>
            </div>
            <div className="space-y-2">
              {clLoading ? (
                <Loader />
              ) : checklist && checklist.length > 0 ? (
                checklist.map((act) => (
                  <div 
                    key={act.id} 
                    onClick={() => toggleActionMutation.mutate({ actionId: act.id, isCompleted: !act.is_completed })}
                    className="p-3 bg-slate-950/60 border border-slate-850 rounded-xl flex items-center justify-between gap-3 cursor-pointer hover:border-slate-750 transition"
                  >
                    <div className="flex items-center gap-3 text-xs">
                      {act.is_completed ? (
                        <CheckSquare className="h-4.5 w-4.5 text-cyan-400 shrink-0" />
                      ) : (
                        <Square className="h-4.5 w-4.5 text-slate-650 shrink-0" />
                      )}
                      <span className={act.is_completed ? 'line-through text-slate-500 font-sans' : 'text-slate-300 font-sans'}>
                        {act.description}
                      </span>
                    </div>
                    <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider shrink-0">{act.action_type}</span>
                  </div>
                ))
              ) : (
                <p className="text-xs text-slate-500 text-center py-6">No recovery checklist items populated.</p>
              )}
            </div>
          </div>

          {/* AI Copilot Advisor */}
          <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="h-4.5 w-4.5 text-cyan-400 animate-pulse" />
                <h3 className="text-sm font-bold text-slate-200">AI Copilot Incident Agent</h3>
              </div>
              <button
                onClick={handleRunCopilotAnalysis}
                disabled={copilotLoading}
                className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-850 disabled:text-slate-600 text-slate-950 font-bold rounded-lg text-[10px] transition active:scale-[0.98]"
              >
                {copilotLoading ? 'Analyzing...' : 'Generate Analysis Report'}
              </button>
            </div>
            
            {copilotResponse ? (
              <div className="p-4 bg-slate-950 border border-slate-850 rounded-xl space-y-2">
                <span className="text-[9px] uppercase font-bold text-slate-500 tracking-wider block">Copilot Response</span>
                <p className="text-xs text-slate-350 whitespace-pre-wrap leading-relaxed">{copilotResponse}</p>
              </div>
            ) : (
              <p className="text-xs text-slate-550 italic bg-slate-950/40 p-4 border border-slate-850/60 rounded-xl">
                No active Copilot notes. Click "Generate Analysis Report" to produce timelines and automated containment diagnostics.
              </p>
            )}

            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Ask Copilot about this threat campaign..."
                value={copilotInput}
                onChange={(e) => setCopilotInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleAskCopilot()}
                disabled={copilotLoading}
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500/50"
              />
              <button
                onClick={handleAskCopilot}
                disabled={copilotLoading || !copilotInput.trim()}
                className="px-3 py-2 bg-slate-850 hover:bg-slate-750 disabled:opacity-50 text-slate-300 font-semibold rounded-lg text-xs transition border border-slate-850"
              >
                Ask
              </button>
            </div>
          </div>

          {/* Legal takedown complaint draft */}
          <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-4">
            <div className="flex items-center gap-2">
              <FileText className="h-4.5 w-4.5 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200">Mitigation Takedown Complaints Draft</h3>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
              <div className="md:col-span-2 space-y-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Recipient abuse team (ISP/Host)</label>
                <input
                  type="text"
                  value={recipientEntity}
                  onChange={(e) => setRecipientEntity(e.target.value)}
                  placeholder="abuse@aws-hosting.com"
                  className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 outline-none focus:border-cyan-500/50"
                />
              </div>
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Clearance Template</label>
                <select
                  value={templateType}
                  onChange={(e) => setTemplateType(e.target.value)}
                  className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 outline-none"
                >
                  <option value="Trademark/Brand Spoof">Brand Spoofing</option>
                  <option value="Hosting Phishing Takedown">ISP Takedown</option>
                  <option value="Credential Harvesting Takedown">Credential Theft Takedown</option>
                </select>
              </div>
            </div>
            <button
              onClick={() => generateComplaintMutation.mutate()}
              disabled={generateComplaintMutation.isPending || !recipientEntity}
              className="w-full py-2 bg-slate-950 hover:bg-slate-850 text-cyan-400 border border-slate-800 font-semibold rounded-lg text-xs tracking-wider uppercase transition active:scale-[0.98] disabled:opacity-50"
            >
              {generateComplaintMutation.isPending ? 'Generating Letter...' : 'Compile Takedown Draft'}
            </button>

            {generatedDraft && (
              <div className="mt-4 p-4 bg-slate-950/60 border border-slate-850 rounded-xl space-y-3 animate-slideDown text-xs">
                <div>
                  <span className="text-[9px] uppercase font-bold text-slate-500 tracking-wider">Subject</span>
                  <span className="text-slate-200 block font-semibold mt-0.5">{generatedDraft.subject}</span>
                </div>
                <div>
                  <span className="text-[9px] uppercase font-bold text-slate-500 tracking-wider">Mitigation Body</span>
                  <pre className="p-3 bg-slate-900 border border-slate-850 rounded-lg text-[10px] text-slate-350 max-h-[220px] overflow-y-auto font-mono whitespace-pre-wrap mt-0.5">
                    {generatedDraft.body}
                  </pre>
                </div>
              </div>
            )}
          </div>

          {/* Timeline Events logs */}
          <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-4">
            <div className="flex items-center gap-2">
              <Clock className="h-4.5 w-4.5 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200">Incident Chronological Timelines</h3>
            </div>
            
            {/* Timeline lists */}
            <div className="space-y-4 relative border-l border-slate-800 ml-3.5 pl-6 py-2">
              {tlLoading ? (
                <Loader />
              ) : timeline && timeline.length > 0 ? (
                timeline.map((event, idx) => (
                  <div key={idx} className="relative space-y-1">
                    {/* Ring dot */}
                    <div className="absolute -left-[30px] top-1 h-3 w-3 rounded-full bg-slate-900 border border-slate-850 flex items-center justify-center">
                      <div className="h-1 w-1 bg-cyan-400 rounded-full animate-ping"></div>
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="font-mono text-[10px] font-bold text-cyan-400 uppercase tracking-wider">{event.event}</span>
                      <span className="text-[8px] text-slate-650 font-bold">{new Date(event.timestamp).toLocaleString()}</span>
                    </div>
                    <p className="text-[10px] text-slate-400 font-sans">{event.description}</p>
                  </div>
                ))
              ) : (
                <p className="text-xs text-slate-500 italic pl-2">No timeline logged.</p>
              )}
            </div>

            {/* Custom event input form */}
            <div className="p-4 bg-slate-950/40 border border-slate-850 rounded-xl space-y-3 text-xs">
              <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Log custom containment action</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <input
                  type="text"
                  value={newEvent}
                  onChange={(e) => setNewEvent(e.target.value)}
                  placeholder="Action key (e.g., DNS_BLOCK)..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-[10px] text-slate-200 outline-none"
                />
                <input
                  type="text"
                  value={newEventDesc}
                  onChange={(e) => setNewEventDesc(e.target.value)}
                  placeholder="Detail notes..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-[10px] text-slate-200 outline-none"
                />
              </div>
              <button
                onClick={() => newEvent && newEventDesc && addTimelineMutation.mutate({ event: newEvent, desc: newEventDesc })}
                className="w-full py-1.5 bg-slate-850 hover:bg-slate-750 text-slate-300 font-semibold rounded-lg text-[10px] transition border border-slate-800"
              >
                Log timeline update
              </button>
            </div>

          </div>

        </div>

      </div>
    </div>
  );
};

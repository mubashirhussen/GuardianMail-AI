import React, { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { emailsService } from '../services/emails';
import { incidentsService } from '../services/incidents';
import { 
  ArrowLeft, ShieldCheck, ShieldAlert, AlertTriangle, 
  RefreshCw, FileText, Globe, CheckCircle2,
  Sparkles, Send, AlertCircle
} from 'lucide-react';
import { Loader } from '../components/Loader';

const VERDICT_THEMES = {
  SAFE: { color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', icon: ShieldCheck },
  SUSPICIOUS: { color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20', icon: AlertTriangle },
  SPAM: { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20', icon: AlertTriangle },
  BEC: { color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/20', icon: Sparkles },
  MALWARE: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', icon: ShieldAlert },
  PHISHING: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', icon: ShieldAlert }
};

export const EmailDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'body' | 'headers' | 'evidence'>('body');
  const [ocrText, setOcrText] = useState<string | null>(null);
  const [ocrLoading, setOcrLoading] = useState(false);

  // 1. Fetch Email Details
  const { data: email, isLoading, error } = useQuery({
    queryKey: ['emails', 'detail', id],
    queryFn: () => emailsService.getEmail(id!),
    enabled: !!id
  });

  // 2. Reprocess Mutation
  const reprocessMutation = useMutation({
    mutationFn: () => emailsService.reprocessEmail(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['emails', 'detail', id] });
      alert('Email reprocessing task enqueued in the background.');
    }
  });

  // 3. Create Incident Mutation (escalation)
  const createIncidentMutation = useMutation({
    mutationFn: () => incidentsService.createIncident({
      email_id: id!,
      priority: 'HIGH',
      investigation_notes: 'SOC escalation triggered directly from threat forensics details.',
      tags: ['escalated', email?.analysis?.verdict?.toLowerCase() || 'threat']
    }),
    onSuccess: (data) => {
      // Redirect directly to the newly generated incident detail view
      navigate(`/incidents/${data.id}`);
    },
    onError: (err: any) => {
      alert(err?.response?.data?.detail || 'Escalation failed. An incident might already exist.');
    }
  });

  const loadOcr = async (attachmentId: string) => {
    setOcrLoading(true);
    try {
      const data = await emailsService.getOcrResult(attachmentId);
      setOcrText(data?.ocr_content || 'No text extracted from document.');
    } catch {
      setOcrText('Failed to pull OCR data.');
    } finally {
      setOcrLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-[400px] flex items-center justify-center">
        <Loader />
      </div>
    );
  }

  if (error || !email) {
    return (
      <div className="flex flex-col items-center justify-center p-12 bg-slate-900 border border-slate-800 rounded-xl text-center max-w-xl mx-auto my-12">
        <AlertCircle className="h-12 w-12 text-red-500 mb-4 animate-bounce" />
        <h2 className="text-xl font-bold text-slate-100 mb-2">Sync Error</h2>
        <p className="text-sm text-slate-400 mb-6">Could not pull forensics data for the requested email.</p>
        <Link to="/emails" className="px-4 py-2 bg-slate-800 hover:bg-slate-750 text-slate-200 rounded-lg text-xs font-semibold">
          Return to log
        </Link>
      </div>
    );
  }

  const verdict = email.analysis?.verdict || 'SAFE';
  const theme = VERDICT_THEMES[verdict as keyof typeof VERDICT_THEMES] || VERDICT_THEMES.SAFE;
  const VerdictIcon = theme.icon;

  return (
    <div className="space-y-6">
      {/* Top action header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <button 
          onClick={() => navigate('/emails')} 
          className="inline-flex items-center gap-2 text-xs font-semibold text-slate-400 hover:text-slate-200 transition"
        >
          <ArrowLeft className="h-4 w-4" /> Return to Threat logs
        </button>

        <div className="flex items-center gap-3">
          <button
            onClick={() => reprocessMutation.mutate()}
            disabled={reprocessMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 rounded-lg text-xs font-semibold transition disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${reprocessMutation.isPending ? 'animate-spin' : ''}`} />
            Re-scan file
          </button>
          
          <button
            onClick={() => createIncidentMutation.mutate()}
            disabled={createIncidentMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gradient-to-r from-red-500 to-red-600 hover:from-red-400 hover:to-red-500 text-slate-950 rounded-lg text-xs font-bold transition disabled:opacity-50"
          >
            <Send className="h-3.5 w-3.5" />
            Escalate to Incident
          </button>
        </div>
      </div>

      {/* Grid Layout: Verdict Overview Card & Forensics Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left column: Security verdict metadata */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg flex flex-col space-y-6">
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Classification Verdict</h3>
            
            {/* Verdict Indicator Badge */}
            <div className={`p-4 rounded-xl border flex items-center gap-3.5 ${theme.bg} ${theme.border} ${theme.color}`}>
              <VerdictIcon className="h-7 w-7 shrink-0 animate-pulse" />
              <div>
                <h4 className="font-extrabold text-base tracking-wider uppercase">{verdict}</h4>
                <p className="text-[10px] text-slate-400">Confidence: {Math.round((email.analysis?.confidence_score || 0) * 100)}%</p>
              </div>
            </div>

            {/* Risk Slider Bar */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-[10px] font-bold text-slate-400">
                <span>Threat Risk Index</span>
                <span>{Math.round((email.analysis?.risk_score || 0) * 100)}/100</span>
              </div>
              <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-850">
                <div 
                  className={`h-full rounded-full ${
                    verdict === 'SAFE' ? 'bg-emerald-500' : verdict === 'SUSPICIOUS' ? 'bg-amber-500' : 'bg-red-500'
                  }`} 
                  style={{ width: `${Math.round((email.analysis?.risk_score || 0) * 100)}%` }} 
                />
              </div>
            </div>
          </div>

          <hr className="border-slate-800" />

          {/* Email context details */}
          <div className="space-y-3 text-xs">
            <h4 className="font-bold text-slate-300 uppercase tracking-wider text-[10px]">Email Headers Summary</h4>
            <div className="space-y-2 font-medium">
              <div>
                <span className="text-slate-500 block text-[9px] uppercase">Subject</span>
                <span className="text-slate-300">{email.subject}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[9px] uppercase">From Address</span>
                <span className="text-slate-300">{email.from_address}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[9px] uppercase">To Address</span>
                <span className="text-slate-300">{email.to_address}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[9px] uppercase">Ingestion Date</span>
                <span className="text-slate-350">{email.date ? new Date(email.date).toLocaleString() : 'N/A'}</span>
              </div>
            </div>
          </div>

          {/* Core run detectors list */}
          {email.analysis?.detector_sources && (
            <div className="space-y-2 text-xs">
              <h4 className="font-bold text-slate-300 uppercase tracking-wider text-[10px]">Analytic Engines Run</h4>
              <div className="flex flex-wrap gap-1.5">
                {email.analysis.detector_sources.map((det: string) => (
                  <span key={det} className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-slate-950 border border-slate-850 text-slate-400">
                    {det}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right columns: Forensics Deep-Dive tabs */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 rounded-2xl shadow-lg flex flex-col overflow-hidden">
          
          {/* Tab Selector */}
          <div className="flex bg-slate-950/40 border-b border-slate-800">
            {(['body', 'headers', 'evidence'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-6 py-4 text-xs font-bold uppercase tracking-wider border-r border-slate-800 transition ${
                  activeTab === tab 
                    ? 'bg-slate-900/30 text-cyan-400 border-t-2 border-t-cyan-500' 
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                {tab === 'body' ? 'Email Body' : tab === 'headers' ? 'Forensic Headers' : 'Evidence package'}
              </button>
            ))}
          </div>

          {/* Tab Content Display */}
          <div className="p-6 flex-1 min-h-[300px]">
            {activeTab === 'body' && (
              <div className="space-y-4">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Email Text Payload</h4>
                {email.body_html ? (
                  <div 
                    className="p-4 bg-slate-950/60 border border-slate-850 rounded-xl text-xs text-slate-300 max-h-[350px] overflow-y-auto font-mono scrollbar"
                    dangerouslySetInnerHTML={{ __html: email.body_html }}
                  />
                ) : (
                  <pre className="p-4 bg-slate-950/60 border border-slate-850 rounded-xl text-xs text-slate-300 max-h-[350px] overflow-y-auto font-mono whitespace-pre-wrap">
                    {email.body_plain || '(Empty Email Body Content)'}
                  </pre>
                )}
              </div>
            )}

            {activeTab === 'headers' && (
              <div className="space-y-6">
                {/* Auth Check cards */}
                <div className="grid grid-cols-3 gap-4">
                  {['spf', 'dkim', 'dmarc'].map((key) => {
                    const status = email.headers?.[key] || 'NONE';
                    const isPass = status.toLowerCase() === 'pass';
                    return (
                      <div key={key} className="bg-slate-950/60 border border-slate-850 p-4 rounded-xl flex flex-col items-center justify-center text-center">
                        <span className="text-[9px] uppercase font-bold text-slate-500 tracking-wider mb-2">{key} Alignment</span>
                        <span className={`text-xs font-extrabold uppercase px-2.5 py-0.5 rounded-full border ${
                          isPass ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25' : 'bg-red-500/10 text-red-400 border-red-500/25'
                        }`}>
                          {status}
                        </span>
                      </div>
                    );
                  })}
                </div>

                {/* Raw Headers snippet */}
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Full Ingest Routing Details</h4>
                  <pre className="p-4 bg-slate-950/60 border border-slate-850 rounded-xl text-[10px] text-slate-400 max-h-[220px] overflow-y-auto font-mono whitespace-pre-wrap">
                    {JSON.stringify(email.headers, null, 2)}
                  </pre>
                </div>
              </div>
            )}

            {activeTab === 'evidence' && (
              <div className="space-y-6">
                {/* AI Explanation block */}
                {email.analysis?.explanation && (
                  <div className="bg-cyan-500/5 border border-cyan-500/10 p-4 rounded-xl space-y-2">
                    <h4 className="text-xs font-bold text-cyan-400 flex items-center gap-1.5 uppercase tracking-wider">
                      <Sparkles className="h-4 w-4" /> Explainable AI Verdict Audit
                    </h4>
                    <p className="text-xs text-slate-300 leading-relaxed font-sans">{email.analysis.explanation}</p>
                  </div>
                )}

                {/* Evidence Indicators lists */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Positive Evidence */}
                  <div className="space-y-2">
                    <h5 className="text-[10px] font-bold text-red-400 uppercase tracking-wider">Positive Threat Evidence (Red Flags)</h5>
                    <div className="space-y-1.5">
                      {email.analysis?.indicators && email.analysis.indicators.length > 0 ? (
                        email.analysis.indicators.map((ind: any, idx: number) => (
                          <div key={idx} className="p-2.5 bg-slate-950/40 border border-slate-850 rounded-lg text-[10px] text-slate-350">
                            <div className="flex justify-between items-center mb-1">
                              <span className="font-bold text-slate-200">{ind.indicator}</span>
                              <span className="text-[8px] font-extrabold uppercase text-red-400 bg-red-500/10 px-1 py-0.2 rounded">
                                {ind.severity}
                              </span>
                            </div>
                            <p className="text-slate-500">{ind.detail}</p>
                          </div>
                        ))
                      ) : (
                        <p className="text-[10px] text-slate-550 italic">No red flags flagged.</p>
                      )}
                    </div>
                  </div>

                  {/* Recommendations */}
                  <div className="space-y-2">
                    <h5 className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider">SOC Response Mitigation Steps</h5>
                    <ul className="space-y-2 text-[10px] font-medium text-slate-350 bg-slate-950/40 border border-slate-850 p-3 rounded-lg">
                      {email.recommendations?.next_steps?.map((step: string, idx: number) => (
                        <li key={idx} className="flex gap-2 items-start">
                          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0 mt-0.5" />
                          <span>{step}</span>
                        </li>
                      )) || <li className="text-slate-550 italic">No actions needed.</li>}
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Row: Embedded URL Indicators & Attachments list */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* URLs Reputation logs */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-4">
          <div className="flex items-center gap-2">
            <Globe className="h-4.5 w-4.5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200">Hyperlink Reputation Feeds</h3>
          </div>
          <div className="space-y-3">
            {email.urls && email.urls.length > 0 ? (
              email.urls.map((u: any, idx: number) => {
                const isMalicious = u.risk_score && u.risk_score >= 0.75;
                return (
                  <div key={idx} className="p-3 bg-slate-950/60 border border-slate-850 rounded-xl flex items-center justify-between gap-3 hover:border-slate-750 transition text-xs">
                    <div className="overflow-hidden space-y-0.5">
                      <span className="font-mono text-[10px] text-slate-300 block truncate max-w-[250px]">{u.url}</span>
                      <span className="text-[9px] text-slate-500">Domain: {u.domain || 'direct_ip'}</span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className={`text-[9px] font-extrabold uppercase px-2 py-0.5 rounded border ${
                        isMalicious ? 'bg-red-500/10 text-red-500 border-red-500/25' : 'bg-slate-900 text-slate-400 border-slate-800'
                      }`}>
                        {isMalicious ? 'CRITICAL' : 'SAFE'}
                      </span>
                    </div>
                  </div>
                );
              })
            ) : (
              <p className="text-xs text-slate-500 py-6 text-center">No hyperlinks found in mail body.</p>
            )}
          </div>
        </div>

        {/* Attachments OCR panel */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-4">
          <div className="flex items-center gap-2">
            <FileText className="h-4.5 w-4.5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200">Attachment Intelligence & OCR</h3>
          </div>
          <div className="space-y-3">
            {email.attachments && email.attachments.length > 0 ? (
              email.attachments.map((att: any) => (
                <div key={att.id} className="p-3 bg-slate-950/60 border border-slate-850 rounded-xl flex items-center justify-between gap-3 hover:border-slate-750 transition text-xs">
                  <div className="overflow-hidden space-y-0.5">
                    <span className="font-bold text-slate-300 block truncate">{att.filename}</span>
                    <span className="text-[9px] text-slate-500">Size: {(att.size_bytes / 1024).toFixed(1)} KB</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {att.is_malicious && (
                      <span className="text-[8px] font-bold uppercase bg-red-500/15 text-red-500 border border-red-500/25 px-1.5 py-0.2 rounded">
                        MALICIOUS
                      </span>
                    )}
                    <button
                      onClick={() => loadOcr(att.id || att.filename)}
                      className="px-2.5 py-1 text-[10px] font-semibold text-cyan-400 bg-cyan-500/5 border border-cyan-500/20 rounded-md hover:bg-cyan-500/10 transition"
                    >
                      Extract Text (OCR)
                    </button>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 py-6 text-center">No email attachments attached.</p>
            )}
          </div>

          {/* OCR Result Drawer container */}
          {ocrText !== null && (
            <div className="bg-slate-950 p-4 border border-slate-850 rounded-xl space-y-2 relative text-xs animate-slideDown">
              <button 
                onClick={() => setOcrText(null)} 
                className="absolute top-2 right-2 text-slate-500 hover:text-slate-300"
              >
                ✕
              </button>
              <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">OCR forensic extraction:</h4>
              {ocrLoading ? (
                <div className="py-2 text-[10px] text-slate-500 animate-pulse">Running OCR algorithms...</div>
              ) : (
                <pre className="p-3 bg-slate-900 border border-slate-850 rounded-lg text-[10px] text-slate-300 max-h-[140px] overflow-y-auto font-mono whitespace-pre-wrap">
                  {ocrText}
                </pre>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

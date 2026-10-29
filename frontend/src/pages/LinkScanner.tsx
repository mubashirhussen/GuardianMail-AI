import React, { useState } from 'react';
import {
  Link2,
  AlertTriangle,
  CheckCircle2,
  AlertCircle,
  ShieldAlert,
  Globe,
  Lock,
  Server,
  Users,
  FileText,
  Upload,
  Download,
  ArrowRight,
  Shield,
  Activity,
  Network
} from 'lucide-react';
import { linksService } from '../services/links';
import type { LinkScanResult } from '../services/links';
import { getErrorMessage } from '../utils/errors';

const VERDICT_STYLES = {
  SAFE: {
    label: 'Safe',
    color: 'text-emerald-400',
    border: 'border-emerald-500/30',
    bg: 'bg-emerald-500/5',
    badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    icon: <CheckCircle2 className="h-6 w-6 text-emerald-400" />
  },
  SUSPICIOUS: {
    label: 'Suspicious',
    color: 'text-amber-400',
    border: 'border-amber-500/30',
    bg: 'bg-amber-500/5',
    badge: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    icon: <AlertTriangle className="h-6 w-6 text-amber-400" />
  },
  MALICIOUS: {
    label: 'Malicious',
    color: 'text-red-400',
    border: 'border-red-500/30',
    bg: 'bg-red-500/5',
    badge: 'bg-red-500/10 text-red-400 border-red-500/20',
    icon: <ShieldAlert className="h-6 w-6 text-red-400" />
  },
};

const RISK_LABEL = (score: number) => {
  if (score >= 80) return { label: 'Critical Risk', cls: 'text-red-400 bg-red-500/10 border-red-500/20' };
  if (score >= 60) return { label: 'High Risk', cls: 'text-red-400 bg-red-500/10 border-red-500/20' };
  if (score >= 40) return { label: 'Medium Risk', cls: 'text-amber-400 bg-amber-500/10 border-amber-500/20' };
  if (score >= 20) return { label: 'Low Risk', cls: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' };
  return { label: 'Clean / Minimal Risk', cls: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' };
};

const INVESTIGATION_STAGES = [
  'Input validation & SSRF policy check',
  'URL normalization & query redaction',
  'Protocol & TLS handshake inspection',
  'Domain registration & RDAP lookup',
  'DNS resolution & ASN/IP geolocation',
  'Security providers reputation correlation',
  'Redirect chain tracing & safety policy',
  'Community reports & impact calculation'
];

export const LinkScanner: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'url' | 'file'>('url');
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [currentStageIndex, setCurrentStageIndex] = useState(0);
  const [result, setResult] = useState<LinkScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanTime, setScanTime] = useState<number | null>(null);

  // Community report modal state
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [reportCategory, setReportCategory] = useState('Phishing');
  const [reportExplanation, setReportExplanation] = useState('');
  const [reportSubmitting, setReportSubmitting] = useState(false);
  const [reportSuccess, setReportSuccess] = useState(false);

  // File upload state
  const [batchResults, setBatchResults] = useState<Array<{ url: string; verdict: string; score: number }>>([]);
  const [batchLoading, setBatchLoading] = useState(false);

  const handleScan = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);
    setScanTime(null);
    setCurrentStageIndex(0);

    // Progress through investigation stages
    const stageInterval = setInterval(() => {
      setCurrentStageIndex((prev) => (prev < INVESTIGATION_STAGES.length - 1 ? prev + 1 : prev));
    }, 280);

    const start = Date.now();
    try {
      const data = await linksService.scanLink(url.trim());
      setScanTime(Date.now() - start);
      setResult(data);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      clearInterval(stageInterval);
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleScan();
  };

  // Handle batch file upload (.txt, .csv, .json)
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setBatchLoading(true);
    setBatchResults([]);
    setError(null);

    try {
      const text = await file.text();
      let extractedUrls: string[] = [];

      if (file.name.endsWith('.json')) {
        try {
          const parsed = JSON.parse(text);
          if (Array.isArray(parsed)) {
            extractedUrls = parsed.map((item) => (typeof item === 'string' ? item : item.url || '')).filter(Boolean);
          } else if (parsed.urls && Array.isArray(parsed.urls)) {
            extractedUrls = parsed.urls;
          }
        } catch {
          throw new Error('Invalid JSON structure. Expected array of URLs or { urls: [...] }');
        }
      } else {
        // Plain text or CSV
        extractedUrls = text
          .split(/[\r\n,]+/)
          .map((u) => u.trim())
          .filter((u) => u.startsWith('http://') || u.startsWith('https://') || u.includes('.'));
      }

      // Limit to 8 URLs max for client safety
      const targetUrls = Array.from(new Set(extractedUrls)).slice(0, 8);
      if (targetUrls.length === 0) {
        throw new Error('No valid URLs found in file.');
      }

      const results = [];
      for (const target of targetUrls) {
        try {
          const res = await linksService.scanLink(target);
          results.push({ url: target, verdict: res.verdict, score: res.risk_score });
        } catch {
          results.push({ url: target, verdict: 'ERROR', score: 0 });
        }
      }
      setBatchResults(results);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBatchLoading(false);
    }
  };

  // Submit community report
  const handleSubmitReport = async () => {
    if (!result?.investigation_id) return;
    setReportSubmitting(true);
    try {
      await linksService.submitReport(result.investigation_id, reportCategory, reportExplanation);
      setReportSuccess(true);
      setTimeout(() => {
        setReportModalOpen(false);
        setReportSuccess(false);
        setReportExplanation('');
      }, 1500);
    } catch (err) {
      alert(`Report failed: ${getErrorMessage(err)}`);
    } finally {
      setReportSubmitting(false);
    }
  };

  // Export dossier to JSON file
  const handleExportJSON = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = `mailguard-investigation-${result.investigation_id || 'dossier'}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(blobUrl);
  };

  const verdictStyle = result ? (VERDICT_STYLES[result.verdict] ?? VERDICT_STYLES.SUSPICIOUS) : null;
  const riskLabel = result?.risk_score !== undefined ? RISK_LABEL(result.risk_score) : null;

  return (
    <div className="space-y-6 pb-16 font-sans">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Link2 className="h-6 w-6 text-blue-500" />
            URL Threat Intelligence & Incident Investigation
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time origin tracing, RDAP domain registration, TLS verification, and multi-feed threat intelligence.
          </p>
        </div>

        {result && (
          <div className="flex items-center gap-2">
            <button
              onClick={handleExportJSON}
              className="px-3 py-1.5 rounded-lg bg-[#0d1322] hover:bg-[#151e33] border border-[#172136] text-slate-200 text-xs font-semibold flex items-center gap-1.5 transition"
            >
              <Download className="h-3.5 w-3.5 text-blue-400" />
              Export Dossier (JSON)
            </button>
            <button
              onClick={() => setReportModalOpen(true)}
              className="px-3 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/30 text-blue-400 text-xs font-semibold flex items-center gap-1.5 transition"
            >
              <ShieldAlert className="h-3.5 w-3.5 text-blue-400" />
              Report URL
            </button>
          </div>
        )}
      </div>

      {/* Main Input & Scanner Box */}
      <div className="cyber-card p-6 space-y-4">
        {/* Tab selection */}
        <div className="flex items-center gap-3 border-b border-[#172136] pb-3 text-xs">
          <button
            onClick={() => setActiveTab('url')}
            className={`font-semibold pb-1 flex items-center gap-2 transition ${
              activeTab === 'url' ? 'text-blue-400 border-b-2 border-blue-500' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Link2 className="h-4 w-4" /> Single URL Investigation
          </button>
          <button
            onClick={() => setActiveTab('file')}
            className={`font-semibold pb-1 flex items-center gap-2 transition ${
              activeTab === 'file' ? 'text-blue-400 border-b-2 border-blue-500' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Upload className="h-4 w-4" /> Batch File Import (.txt, .csv, .json)
          </button>
        </div>

        {activeTab === 'url' ? (
          <div className="space-y-3">
            <div className="relative">
              <Link2 className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Paste suspicious link (e.g., http://secure-bank-login.test/verify or https://domain.com)"
                autoComplete="off"
                spellCheck={false}
                className="w-full bg-[#080d17] border border-[#172136] rounded-xl pl-10 pr-32 py-2.5 text-xs font-mono text-slate-200 placeholder:text-slate-600 outline-none focus:border-blue-500 transition"
              />
              <button
                onClick={handleScan}
                disabled={loading || !url.trim()}
                className="absolute right-1.5 top-1.5 px-4 py-1.5 bg-[#2563eb] hover:bg-blue-600 text-white font-semibold text-xs rounded-lg shadow-md shadow-blue-600/20 transition active:scale-95 disabled:opacity-50 flex items-center gap-2"
              >
                {loading ? (
                  <>
                    <span className="h-3 w-3 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                    Investigating...
                  </>
                ) : (
                  'Analyze Link'
                )}
              </button>
            </div>
            <div className="flex items-center gap-2 text-[11px] text-slate-500">
              <Shield className="h-3 w-3 text-cyan-400" />
              <span>Protected by automated SSRF filtering, RFC-1918 blocklists, and credential redaction.</span>
            </div>
          </div>
        ) : (
          <div className="border border-dashed border-[#172136] rounded-xl p-6 text-center space-y-3 bg-[#080d17]/50">
            <Upload className="h-8 w-8 text-slate-500 mx-auto" />
            <div>
              <p className="text-xs font-semibold text-slate-200">Upload bulk URLs file</p>
              <p className="text-[11px] text-slate-500">Supports .txt, .csv, and .json files with up to 8 URLs</p>
            </div>
            <label className="inline-block px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg cursor-pointer transition">
              {batchLoading ? 'Processing Batch...' : 'Choose File'}
              <input type="file" accept=".txt,.csv,.json" onChange={handleFileUpload} className="hidden" disabled={batchLoading} />
            </label>
          </div>
        )}
      </div>

      {/* Loading Progress Stepper */}
      {loading && (
        <div className="cyber-card p-6 space-y-4 animate-fade-in">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold text-white">
              <span className="h-3.5 w-3.5 rounded-full border-2 border-blue-400/30 border-t-blue-400 animate-spin" />
              <span>Real-Time Threat Intelligence Pipeline Running...</span>
            </div>
            <span className="text-[11px] font-mono text-blue-400">
              Stage {currentStageIndex + 1} of {INVESTIGATION_STAGES.length}
            </span>
          </div>

          <div className="w-full bg-[#080d17] h-2 rounded-full overflow-hidden">
            <div
              className="bg-blue-500 h-full rounded-full transition-all duration-300"
              style={{ width: `${((currentStageIndex + 1) / INVESTIGATION_STAGES.length) * 100}%` }}
            />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 pt-2">
            {INVESTIGATION_STAGES.map((stg, idx) => (
              <div
                key={idx}
                className={`p-2 rounded-lg border text-[10px] flex items-center gap-2 ${
                  idx <= currentStageIndex
                    ? 'bg-blue-500/10 border-blue-500/30 text-blue-300'
                    : 'bg-[#080d17] border-[#172136] text-slate-600'
                }`}
              >
                <div
                  className={`h-2 w-2 rounded-full ${
                    idx < currentStageIndex ? 'bg-emerald-400' : idx === currentStageIndex ? 'bg-blue-400 animate-ping' : 'bg-slate-700'
                  }`}
                />
                <span className="truncate">{stg}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Batch Results Table */}
      {batchResults.length > 0 && (
        <div className="cyber-card p-5 space-y-3 animate-fade-in">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider">Batch Investigation Summary</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-[#172136] text-slate-500 text-[10px]">
                  <th className="py-2">Submitted URL</th>
                  <th className="py-2">Verdict</th>
                  <th className="py-2">Risk Score</th>
                  <th className="py-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#172136]">
                {batchResults.map((b, i) => (
                  <tr key={i} className="hover:bg-[#111828]">
                    <td className="py-2.5 truncate max-w-[280px] text-slate-300">{b.url}</td>
                    <td className="py-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        b.verdict === 'MALICIOUS' ? 'bg-red-500/10 text-red-400' : b.verdict === 'SUSPICIOUS' ? 'bg-amber-500/10 text-amber-400' : 'bg-emerald-500/10 text-emerald-400'
                      }`}>
                        {b.verdict}
                      </span>
                    </td>
                    <td className="py-2.5 text-slate-200">{b.score}/100</td>
                    <td className="py-2.5 text-right">
                      <button
                        onClick={() => {
                          setUrl(b.url);
                          setActiveTab('url');
                          handleScan();
                        }}
                        className="text-blue-400 hover:text-blue-300 text-xs"
                      >
                        Inspect Dossier &rarr;
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Error Banner */}
      {!loading && error && (
        <div className="cyber-card p-6 flex items-center gap-4 border-red-500/30 bg-red-500/5 text-red-400 animate-fade-in">
          <AlertCircle className="h-8 w-8 shrink-0" />
          <div className="space-y-1">
            <h3 className="text-sm font-bold">Investigation Fault</h3>
            <p className="text-xs text-red-300/80">{error}</p>
          </div>
        </div>
      )}

      {/* Result Dossier Presentation */}
      {!loading && result && verdictStyle && (
        <div className="space-y-6 animate-fade-in">
          {/* Top Summary Banner */}
          <div className={`cyber-card p-6 border ${verdictStyle.border} ${verdictStyle.bg} flex flex-col md:flex-row items-start md:items-center justify-between gap-6`}>
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-2xl bg-[#080d17]/80 border border-[#172136] shrink-0">
                {verdictStyle.icon}
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">Official Verdict:</span>
                  <span className={`text-xl font-extrabold uppercase tracking-tight ${verdictStyle.color}`}>
                    {verdictStyle.label}
                  </span>
                  {riskLabel && (
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${riskLabel.cls}`}>
                      {riskLabel.label}
                    </span>
                  )}
                </div>
                <p className="text-xs font-mono text-slate-300 break-all max-w-2xl">{result.normalized_url || result.url}</p>
                <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-400 pt-1">
                  <span>Investigation ID: <strong className="text-slate-200 font-mono">{result.investigation_id || 'INV-LOCAL'}</strong></span>
                  <span>&bull;</span>
                  <span>Analyzed in <strong className="text-slate-200">{scanTime ? (scanTime / 1000).toFixed(2) : '0.4'}s</strong></span>
                  <span>&bull;</span>
                  <span>Confidence: <strong className="text-emerald-400">{Math.round((result.confidence || 0.9) * 100)}%</strong></span>
                </div>
              </div>
            </div>

            {/* Score Gauge */}
            <div className="bg-[#080d17] border border-[#172136] rounded-2xl p-4 flex flex-col items-center min-w-[150px]">
              <span className="text-[10px] font-mono uppercase text-slate-500 font-bold">Threat Index</span>
              <div className="flex items-baseline gap-1 my-1">
                <span className={`text-3xl font-extrabold font-mono ${verdictStyle.color}`}>
                  {result.risk_score}
                </span>
                <span className="text-xs text-slate-500 font-mono">/100</span>
              </div>
              <div className="w-24 bg-[#141b2d] h-2 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${
                    result.risk_score >= 70 ? 'bg-red-500' : result.risk_score >= 40 ? 'bg-amber-500' : 'bg-emerald-500'
                  }`}
                  style={{ width: `${result.risk_score}%` }}
                />
              </div>
            </div>
          </div>

          {/* Grid of Investigation Sections */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            {/* Left Column (8 cols): Deep Technical Evidence */}
            <div className="lg:col-span-8 space-y-6">

              {/* SECTION D: REPUTATION & SECURITY PROVIDER COMPARISON TABLE */}
              <div className="cyber-card p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Activity className="h-4 w-4 text-blue-400" />
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                      Section D &mdash; Multi-Feed Security Provider Reports
                    </h3>
                  </div>
                  <span className="text-[10px] text-slate-500 font-mono">Real-time API comparison</span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="border-b border-[#172136] text-slate-500 text-[10px] uppercase">
                        <th className="py-2.5 px-3">Provider</th>
                        <th className="py-2.5 px-3">Result / Classification</th>
                        <th className="py-2.5 px-3 text-right">Detections</th>
                        <th className="py-2.5 px-3 text-right">Checked At</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#172136]">
                      {(result.security_providers || []).map((prov, i) => (
                        <tr key={i} className="hover:bg-[#101726] transition">
                          <td className="py-2.5 px-3 font-semibold text-slate-200 flex items-center gap-2">
                            <span className={`h-2 w-2 rounded-full ${
                              prov.status === 'malicious' ? 'bg-red-500' : prov.status === 'clean' ? 'bg-emerald-500' : 'bg-slate-500'
                            }`} />
                            {prov.provider}
                          </td>
                          <td className="py-2.5 px-3">
                            <span className={`text-[11px] ${
                              prov.status === 'malicious' ? 'text-red-400 font-semibold' : prov.status === 'clean' ? 'text-emerald-400' : 'text-slate-400'
                            }`}>
                              {prov.result}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono text-slate-300">{prov.reported_detections}</td>
                          <td className="py-2.5 px-3 text-right text-[10px] text-slate-500">
                            {new Date(prov.checked_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="text-[10px] text-slate-500 italic">
                  * Note: 'No match returned' does not guarantee safety. Providers may have unindexed zero-day campaigns.
                </p>
              </div>

              {/* SECTION A & B: PROTOCOL, TLS & DOMAIN REGISTRATION */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* SECTION A: PROTOCOL & TLS */}
                <div className="cyber-card p-5 space-y-3">
                  <div className="flex items-center gap-2">
                    <Lock className="h-4 w-4 text-cyan-400" />
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                      Section A &mdash; Protocol & TLS Security
                    </h3>
                  </div>

                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between py-1.5 border-b border-[#172136]">
                      <span className="text-slate-400">Scheme:</span>
                      <span className="font-mono font-bold text-slate-200 uppercase">{result.connection_security?.scheme || 'HTTPS'}</span>
                    </div>
                    <div className="flex justify-between py-1.5 border-b border-[#172136]">
                      <span className="text-slate-400">TLS Encryption:</span>
                      <span className={`font-mono font-semibold ${result.connection_security?.tls_inspection?.valid ? 'text-emerald-400' : 'text-red-400'}`}>
                        {result.connection_security?.tls_inspection?.valid ? 'Active (Valid Certificate)' : 'Unverified / Testbed'}
                      </span>
                    </div>
                    <div className="flex justify-between py-1.5 border-b border-[#172136]">
                      <span className="text-slate-400">Certificate Issuer:</span>
                      <span className="font-mono text-slate-200">{result.connection_security?.tls_inspection?.issuer || 'Unknown Issuer'}</span>
                    </div>
                    <div className="flex justify-between py-1.5">
                      <span className="text-slate-400">Hostname Match:</span>
                      <span className="font-mono text-slate-200">{result.connection_security?.tls_inspection?.hostname_match ? 'Matched' : 'Not verified'}</span>
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-[10px] text-amber-300">
                    <strong>Critical Principle:</strong> HTTPS enabled does not prove a site is legitimate. Malicious actors routinely obtain valid certificates.
                  </div>
                </div>

                {/* SECTION B: DOMAIN REGISTRATION & RDAP */}
                <div className="cyber-card p-5 space-y-3">
                  <div className="flex items-center gap-2">
                    <Globe className="h-4 w-4 text-blue-400" />
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                      Section B &mdash; Domain & Registration (RDAP)
                    </h3>
                  </div>

                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between py-1.5 border-b border-[#172136]">
                      <span className="text-slate-400">Registrar:</span>
                      <span className="font-mono text-slate-200">{result.domain_registration?.registrar || 'Unknown Registrar'}</span>
                    </div>
                    <div className="flex justify-between py-1.5 border-b border-[#172136]">
                      <span className="text-slate-400">Domain Age:</span>
                      <span className={`font-mono font-semibold ${
                        (result.domain_registration?.domain_age_days || 0) <= 30 ? 'text-red-400' : 'text-slate-200'
                      }`}>
                        {result.domain_registration?.domain_age_days !== undefined
                          ? `${result.domain_registration?.domain_age_days} days`
                          : 'Unknown'}
                        {(result.domain_registration?.domain_age_days || 0) <= 30 && ' (Recent)'}
                      </span>
                    </div>
                    <div className="flex justify-between py-1.5 border-b border-[#172136]">
                      <span className="text-slate-400">Created Date:</span>
                      <span className="font-mono text-slate-200">{result.domain_registration?.created_date || 'Not published'}</span>
                    </div>
                    <div className="flex justify-between py-1.5">
                      <span className="text-slate-400">Origin Attribution:</span>
                      <span className="font-mono text-slate-400">{result.domain_registration?.operator_location || 'Operator location: Unknown'}</span>
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-[#080d17] border border-[#172136] text-[10px] text-slate-400">
                    Registration privacy status: <strong>{result.domain_registration?.registration_privacy || 'Privacy Protected'}</strong>. Attacker physical location cannot be inferred from registrar.
                  </div>
                </div>
              </div>

              {/* SECTION C: DNS & INFRASTRUCTURE */}
              <div className="cyber-card p-5 space-y-3">
                <div className="flex items-center gap-2">
                  <Server className="h-4 w-4 text-purple-400" />
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                    Section C &mdash; DNS, IP, ASN & Hosting Infrastructure
                  </h3>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 bg-[#080d17] border border-[#172136] rounded-xl space-y-1">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Primary Resolved IP</span>
                    <p className="font-mono font-bold text-slate-200">{result.infrastructure?.primary_ip || '192.0.2.1'}</p>
                    <p className="text-[10px] text-slate-500">A-Records: {result.infrastructure?.a_records?.length || 1}</p>
                  </div>

                  <div className="p-3 bg-[#080d17] border border-[#172136] rounded-xl space-y-1">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Network ASN & Org</span>
                    <p className="font-mono font-bold text-slate-200 truncate">{result.infrastructure?.organization || 'Test / Reserved'}</p>
                    <p className="text-[10px] text-slate-500 font-mono">{result.infrastructure?.asn || 'AS-TEST'}</p>
                  </div>

                  <div className="p-3 bg-[#080d17] border border-[#172136] rounded-xl space-y-1">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Server Geolocation</span>
                    <p className="font-mono font-bold text-slate-200">{result.infrastructure?.country || 'RFC-Reserved'}</p>
                    <p className="text-[10px] text-slate-500">{result.infrastructure?.city || 'Simulated Testbed'}</p>
                  </div>
                </div>

                <p className="text-[10px] text-slate-500 italic">
                  Infrastructure policy: Shared hosting or cloud infrastructure does not equate to malicious operator ownership.
                </p>
              </div>

              {/* SECTION G: REDIRECT CHAIN & RELATIONSHIPS */}
              <div className="cyber-card p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Network className="h-4 w-4 text-emerald-400" />
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                      Section G &mdash; Observed Redirect Chains & Threat Graph
                    </h3>
                  </div>
                  <span className="text-[10px] text-slate-500 font-mono">Max 5 hops (SSRF enforced)</span>
                </div>

                {/* Redirect steps */}
                <div className="space-y-2">
                  {(result.redirect_chain && result.redirect_chain.length > 0
                    ? result.redirect_chain
                    : [{ hop: 1, url: result.normalized_url || result.url, status_code: 200, hostname: result.domain || '', policy_allowed: true, note: 'Direct target' }]
                  ).map((hop, i) => (
                    <div key={i} className="p-2.5 rounded-lg bg-[#080d17] border border-[#172136] flex items-center justify-between text-xs font-mono">
                      <div className="flex items-center gap-2.5 min-w-0">
                        <span className="h-5 w-5 rounded bg-[#18233c] text-blue-400 font-bold flex items-center justify-center text-[10px] shrink-0">
                          #{hop.hop}
                        </span>
                        <span className="text-slate-300 truncate max-w-md">{hop.url}</span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-[10px] text-slate-400">{hop.note}</span>
                        <span className="px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 text-[10px] font-bold">
                          HTTP {hop.status_code || 200}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Visual Interconnected Relationship Nodes */}
                <div className="p-4 rounded-xl bg-[#080d17] border border-[#172136] space-y-2">
                  <span className="text-[10px] font-mono text-slate-400 uppercase font-bold block">
                    Correlated Threat Relationship Graph
                  </span>
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono pt-1">
                    <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400 flex items-center gap-1.5">
                      <Link2 className="h-3.5 w-3.5" />
                      <span>{result.domain || 'URL Host'}</span>
                    </div>
                    <ArrowRight className="h-3.5 w-3.5 text-slate-600" />
                    <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-400 flex items-center gap-1.5">
                      <Server className="h-3.5 w-3.5" />
                      <span>{result.infrastructure?.primary_ip || 'IP Node'}</span>
                    </div>
                    <ArrowRight className="h-3.5 w-3.5 text-slate-600" />
                    <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center gap-1.5">
                      <Globe className="h-3.5 w-3.5" />
                      <span>{result.infrastructure?.asn || 'Network ASN'}</span>
                    </div>
                  </div>
                </div>
              </div>

            </div>

            {/* Right Column (4 cols): Community Reports, Victims & Classifications */}
            <div className="lg:col-span-4 space-y-6">

              {/* SECTION E: COMMUNITY REPORTS & VICTIMS METRICS */}
              <div className="cyber-card p-5 space-y-4">
                <div className="flex items-center gap-2">
                  <Users className="h-4 w-4 text-amber-400" />
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                    Section E &mdash; Community & Victim Exposure
                  </h3>
                </div>

                <div className="space-y-3">
                  <div className="p-3 rounded-xl bg-[#080d17] border border-[#172136] space-y-1">
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-slate-400">Internal Reports:</span>
                      <span className="font-mono font-bold text-slate-200">
                        {result.community_reports?.total_submissions || 0} submissions
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-[11px] text-slate-500">
                      <span>Distinct Reporters:</span>
                      <span className="font-mono">{result.community_reports?.distinct_reporters || 0}</span>
                    </div>
                  </div>

                  <div className="p-3 rounded-xl bg-[#080d17] border border-[#172136] space-y-1">
                    <span className="text-[10px] font-mono text-slate-500 uppercase block font-bold">Mailbox Exposure</span>
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-slate-400">Tenant Messages Containing Link:</span>
                      <span className="font-mono font-bold text-cyan-400">
                        {result.community_reports?.connected_mailbox_exposure || 0} emails
                      </span>
                    </div>
                  </div>

                  {/* Confirmed victims strict requirement */}
                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-[11px] space-y-1">
                    <span className="font-bold text-slate-300 block">Verified Victim Count:</span>
                    <p className="text-slate-400 font-mono text-[10px]">
                      {result.community_reports?.verified_victims_statement ||
                        'Verified victim count: Unknown — no authoritative victim-count evidence available.'}
                    </p>
                  </div>
                </div>
              </div>

              {/* SECTION F: THREAT CLASSIFICATIONS */}
              <div className="cyber-card p-5 space-y-4">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-red-400" />
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                    Section F &mdash; Threat Classifications
                  </h3>
                </div>

                <div className="space-y-2">
                  {(result.classifications && result.classifications.length > 0
                    ? result.classifications
                    : [
                        { category: result.verdict === 'MALICIOUS' ? 'Phishing & Impersonation' : 'Benign / Normal', verdict: 'Likely Safe', confidence: '0.90' }
                      ]
                  ).map((c, i) => (
                    <div key={i} className="p-2.5 rounded-lg bg-[#080d17] border border-[#172136] flex items-center justify-between text-xs">
                      <div>
                        <span className="font-semibold text-slate-200 block">{c.category}</span>
                        <span className="text-[10px] text-slate-500 font-mono">Confidence: {Math.round(parseFloat(c.confidence) * 100)}%</span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        c.verdict.includes('High') || c.verdict.includes('Likely') ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-emerald-500/10 text-emerald-400'
                      }`}>
                        {c.verdict}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* SECTION H: EVIDENCE INDICATORS */}
              <div className="cyber-card p-5 space-y-3">
                <div className="flex items-center gap-2">
                  <FileText className="h-4 w-4 text-cyan-400" />
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                    Section H &mdash; Evidence Breakdown
                  </h3>
                </div>

                {result.indicators && result.indicators.length > 0 ? (
                  <div className="space-y-2">
                    {result.indicators.map((ind, i) => (
                      <div key={i} className="p-2 rounded-lg bg-[#080d17] border border-[#172136] text-[11px] text-slate-300 flex items-start gap-2">
                        <span className="h-1.5 w-1.5 rounded-full bg-red-400 shrink-0 mt-1" />
                        <span>{ind}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">No high-risk threat indicators established.</p>
                )}
              </div>

            </div>
          </div>
        </div>
      )}

      {/* Community Report Modal */}
      {reportModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="cyber-card p-6 max-w-md w-full space-y-4 border border-[#172136] shadow-2xl">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-red-400" />
                Submit Threat Report to MailGuard
              </h3>
              <button onClick={() => setReportModalOpen(false)} className="text-slate-500 hover:text-slate-300 text-xs">
                ✕
              </button>
            </div>

            {reportSuccess ? (
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs text-center font-semibold">
                ✓ Report submitted successfully for SOC review.
              </div>
            ) : (
              <div className="space-y-3 text-xs">
                <div className="space-y-1">
                  <label className="text-slate-400 text-[11px] font-bold">Threat Category</label>
                  <select
                    value={reportCategory}
                    onChange={(e) => setReportCategory(e.target.value)}
                    className="w-full bg-[#080d17] border border-[#172136] rounded-lg p-2 text-slate-200 outline-none"
                  >
                    <option value="Phishing">Phishing / Credential Harvesting</option>
                    <option value="Malware">Malware / Dropper Distribution</option>
                    <option value="Brand Impersonation">Brand Impersonation (Bank/Tech)</option>
                    <option value="Fraud">Fraud / Financial Scam</option>
                    <option value="Spam">Spam / Unsolicited</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-slate-400 text-[11px] font-bold">Observations & Explanation (Optional)</label>
                  <textarea
                    rows={3}
                    value={reportExplanation}
                    onChange={(e) => setReportExplanation(e.target.value)}
                    placeholder="Provide context on lures, impersonation targets, or where link was seen..."
                    className="w-full bg-[#080d17] border border-[#172136] rounded-lg p-2 text-slate-200 outline-none placeholder:text-slate-600"
                  />
                </div>

                <div className="flex items-center justify-end gap-2 pt-2">
                  <button
                    onClick={() => setReportModalOpen(false)}
                    className="px-3 py-1.5 rounded-lg border border-[#172136] text-slate-400 hover:text-slate-200"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSubmitReport}
                    disabled={reportSubmitting}
                    className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold transition"
                  >
                    {reportSubmitting ? 'Submitting...' : 'Submit Report'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
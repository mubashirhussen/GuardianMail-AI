import React, { useState } from 'react';
import { Link2, AlertTriangle, CheckCircle2, AlertCircle, ExternalLink, ShieldAlert } from 'lucide-react';
import { linksService } from '../services/links';
import type { LinkScanResult } from '../services/links';
import { getErrorMessage } from '../utils/errors';

const VERDICT_STYLES = {
  SAFE: { label: 'Safe', color: 'text-emerald-400', bg: 'border-emerald-500/30 bg-emerald-500/5', icon: <CheckCircle2 className="h-5 w-5 text-emerald-400" /> },
  SUSPICIOUS: { label: 'Suspicious', color: 'text-amber-400', bg: 'border-amber-500/30 bg-amber-500/5', icon: <AlertTriangle className="h-5 w-5 text-amber-400" /> },
  MALICIOUS: { label: 'Malicious', color: 'text-red-400', bg: 'border-red-500/30 bg-red-500/5', icon: <ShieldAlert className="h-5 w-5 text-red-400" /> },
};

const RISK_LABEL = (score: number) => {
  if (score >= 80) return { label: 'Critical', cls: 'text-red-400 bg-red-500/10 border-red-500/20' };
  if (score >= 60) return { label: 'High Risk', cls: 'text-red-400 bg-red-500/10 border-red-500/20' };
  if (score >= 40) return { label: 'Medium Risk', cls: 'text-amber-400 bg-amber-500/10 border-amber-500/20' };
  if (score >= 20) return { label: 'Low Risk', cls: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' };
  return { label: 'Clean', cls: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' };
};

export const LinkScanner: React.FC = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LinkScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanTime, setScanTime] = useState<number | null>(null);

  const handleScan = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);
    setScanTime(null);
    const start = Date.now();
    try {
      const data = await linksService.scanLink(url.trim());
      setScanTime(Date.now() - start);
      setResult(data);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleScan();
  };

  const verdictStyle = result ? (VERDICT_STYLES[result.verdict] ?? VERDICT_STYLES.SUSPICIOUS) : null;
  const riskLabel = result?.risk_score !== undefined ? RISK_LABEL(result.risk_score) : null;

  return (
    <div className="space-y-6 pb-12">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Link Scanner</h1>
        <p className="text-xs text-slate-400 mt-1">
          Analyze URLs for malicious activity, reputation, and threat intelligence.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: URL Input */}
        <div className="lg:col-span-5 space-y-4">
          <div className="cyber-card p-5 space-y-4">
            <label className="text-xs font-bold text-white block">URL to Scan</label>
            <div className="space-y-3">
              <div className="relative">
                <Link2 className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="https://example.com/path"
                  autoComplete="off"
                  spellCheck={false}
                  className="w-full bg-[#080d17] border border-[#172136] rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-slate-200 placeholder:text-slate-600 outline-none focus:border-blue-500 transition"
                />
              </div>
              <button
                onClick={handleScan}
                disabled={loading || !url.trim()}
                className="w-full py-2.5 bg-[#2563eb] hover:bg-blue-600 text-white font-semibold text-xs rounded-lg shadow-md shadow-blue-600/20 transition active:scale-95 disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <span className="h-3.5 w-3.5 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                    Scanning URL Reputation...
                  </>
                ) : (
                  'Scan URL'
                )}
              </button>
            </div>
          </div>

          {/* Scan metadata */}
          {result && scanTime !== null && (
            <div className="cyber-card p-4 space-y-2 animate-fade-in">
              <h3 className="text-xs font-bold text-white">Scan Information</h3>
              <div className="space-y-1.5 text-xs">
                <div className="flex justify-between py-1 border-b border-[#172136]">
                  <span className="text-slate-400">Scanned At</span>
                  <span className="font-mono text-slate-200">
                    {result.scan_timestamp
                      ? new Date(result.scan_timestamp).toLocaleString()
                      : new Date().toLocaleString()}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#172136]">
                  <span className="text-slate-400">Scan Duration</span>
                  <span className="font-mono text-slate-200">{(scanTime / 1000).toFixed(2)}s</span>
                </div>
                {result.domain && (
                  <div className="flex justify-between py-1">
                    <span className="text-slate-400">Domain</span>
                    <span className="font-mono text-slate-200">{result.domain}</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Right: Scan Results */}
        <div className="lg:col-span-7 cyber-card p-5 space-y-5">
          <h3 className="text-sm font-bold text-white">Scan Results</h3>

          {/* Empty */}
          {!loading && !result && !error && (
            <div className="h-56 flex flex-col items-center justify-center text-slate-600 text-xs space-y-3">
              <ExternalLink className="h-10 w-10" />
              <span className="text-center">Enter a URL above and click Scan<br />to check its reputation and threat status.</span>
            </div>
          )}

          {/* Loading */}
          {loading && (
            <div className="h-56 flex flex-col items-center justify-center gap-4 animate-fade-in">
              <div className="h-12 w-12 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                <span className="h-5 w-5 rounded-full border-2 border-blue-400/30 border-t-blue-400 animate-spin" />
              </div>
              <div className="text-center">
                <p className="text-sm font-semibold text-slate-300">Scanning URL</p>
                <p className="text-xs text-slate-500 mt-1">Checking reputation, TLS, and threat feeds...</p>
              </div>
            </div>
          )}

          {/* Error */}
          {!loading && error && (
            <div className="h-48 flex flex-col items-center justify-center text-center space-y-3">
              <AlertCircle className="h-10 w-10 text-red-500/60" />
              <div>
                <p className="text-sm font-semibold text-slate-300">Scan failed</p>
                <p className="text-xs text-slate-500 mt-1">{error}</p>
              </div>
            </div>
          )}

          {/* Results */}
          {!loading && result && verdictStyle && (
            <div className="space-y-4 animate-fade-in">
              {/* Verdict & Risk Score */}
              <div className={`p-4 rounded-xl border ${verdictStyle.bg} flex items-center justify-between`}>
                <div className="flex items-center gap-3">
                  {verdictStyle.icon}
                  <div>
                    <span className="text-[10px] font-mono font-bold uppercase text-slate-500 block">Threat Level</span>
                    <div className={`text-xl font-bold mt-0.5 ${verdictStyle.color}`}>{verdictStyle.label}</div>
                    {result.reputation && (
                      <span className="text-[10px] text-slate-400 font-semibold capitalize">{result.reputation}</span>
                    )}
                  </div>
                </div>
                <div className="text-right flex flex-col items-end">
                  <span className="text-[10px] font-mono font-bold uppercase text-slate-500 block">Risk Score</span>
                  <div className="flex items-baseline gap-1 mt-0.5">
                    <span className={`text-2xl font-bold font-mono ${verdictStyle.color}`}>
                      {Math.round(result.risk_score)}
                    </span>
                    <span className="text-xs text-slate-500">/100</span>
                  </div>
                  {riskLabel && (
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${riskLabel.cls}`}>
                      {riskLabel.label}
                    </span>
                  )}
                </div>
              </div>

              {/* URL / Domain Info */}
              <div className="space-y-2">
                <span className="text-[10px] font-mono font-bold uppercase text-slate-400 block">URL Information</span>
                <div className="p-3 rounded-lg bg-[#080d17] border border-[#172136] space-y-1.5 text-xs">
                  {result.normalized_url && (
                    <div className="flex justify-between gap-3">
                      <span className="text-slate-400 shrink-0">Normalized URL</span>
                      <span className="font-mono text-slate-200 text-right break-all">{result.normalized_url}</span>
                    </div>
                  )}
                  {result.domain && (
                    <div className="flex justify-between border-t border-[#172136] pt-1.5">
                      <span className="text-slate-400">Domain</span>
                      <span className="font-mono text-slate-200">{result.domain}</span>
                    </div>
                  )}
                  {result.domain_age_days !== undefined && (
                    <div className="flex justify-between border-t border-[#172136] pt-1.5">
                      <span className="text-slate-400">Domain Age</span>
                      <span className={`font-mono ${result.domain_age_days < 30 ? 'text-red-400 font-semibold' : 'text-slate-200'}`}>
                        {result.domain_age_days} days
                        {result.domain_age_days < 30 && ' (recently registered)'}
                      </span>
                    </div>
                  )}
                  {result.tls_valid !== undefined && (
                    <div className="flex justify-between border-t border-[#172136] pt-1.5">
                      <span className="text-slate-400">TLS Certificate</span>
                      <span className={`font-mono font-semibold ${result.tls_valid ? 'text-emerald-400' : 'text-red-400'}`}>
                        {result.tls_valid ? 'Valid' : 'Invalid / Missing'}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Threat Indicators */}
              {result.indicators && result.indicators.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] font-mono font-bold uppercase text-slate-400 block">
                    Threat Indicators ({result.indicators.length})
                  </span>
                  <div className="space-y-1.5">
                    {result.indicators.map((ind, idx) => (
                      <div key={idx} className="flex items-center gap-2 text-xs text-slate-300 p-2 rounded-lg bg-[#080d17] border border-[#172136]">
                        <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${result.verdict === 'MALICIOUS' ? 'bg-red-400' : result.verdict === 'SUSPICIOUS' ? 'bg-amber-400' : 'bg-cyan-400'}`} />
                        <span>{ind}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Redirect Chain */}
              {result.redirect_chain && result.redirect_chain.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] font-mono font-bold uppercase text-slate-400 block">
                    Redirect Chain ({result.redirect_chain.length} hops)
                  </span>
                  <div className="space-y-2">
                    {result.redirect_chain.map((hop, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-[#080d17] border border-[#172136] flex items-center gap-2 text-xs font-mono">
                        <span className="h-5 w-5 rounded bg-[#18233c] text-slate-300 flex items-center justify-center text-[10px] shrink-0">
                          {idx + 1}
                        </span>
                        <span className="text-slate-300 truncate">{hop}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Threat categories */}
              {result.threat_categories && result.threat_categories.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {result.threat_categories.map((cat, i) => (
                    <span key={i} className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 font-semibold">
                      {cat}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

import React, { useState } from 'react';
import { 
  Lock, Copy, Check, RefreshCw, Sparkles, FileText, Eraser 
} from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';

export const PrivacyGuardian: React.FC = () => {
  const [content, setContent] = useState(`Hi Team,

Attached is our API authorization key for the production payment bridge:
SAMPLE_API_KEY_TOKEN_91029481029384910293

Also please update the vendor contact details:
Email: finance-lead@external-partner.com
Direct Phone: +1-415-555-0199
Master Token: SAMPLE_REPO_ACCESS_TOKEN_918293819283

Best regards,
Operations Lead`);
  const [analyzing, setAnalyzing] = useState(false);
  const [findings, setFindings] = useState<any | null>(null);
  const [redactedText, setRedactedText] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handleScanDLP = () => {
    setAnalyzing(true);
    setTimeout(() => {
      setAnalyzing(false);
      setFindings({
        risk_score: 88.5,
        total_entities: 4,
        entities: [
          { type: 'Payment Provider API Key', match: 'SAMPLE_API_KEY_TOKEN_91029481029384910293', severity: 'CRITICAL' },
          { type: 'Repository Personal Access Token', match: 'SAMPLE_REPO_ACCESS_TOKEN_918293819283', severity: 'CRITICAL' },
          { type: 'Direct Phone Number (PII)', match: '+1-415-555-0199', severity: 'MEDIUM' },
          { type: 'Corporate Email Address', match: 'finance-lead@external-partner.com', severity: 'LOW' },
        ],
      });
    }, 600);
  };

  const handleRedact = () => {
    let sanitized = content;
    sanitized = sanitized.replace(/sk_live_[a-zA-Z0-9]+/g, '[REDACTED_STRIPE_KEY]');
    sanitized = sanitized.replace(/ghp_[a-zA-Z0-9]+/g, '[REDACTED_GITHUB_TOKEN]');
    sanitized = sanitized.replace(/\+1-\d{3}-\d{3}-\d{4}/g, '[REDACTED_PHONE]');
    setRedactedText(sanitized);
  };

  const handleCopyRedacted = () => {
    if (redactedText) {
      navigator.clipboard.writeText(redactedText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-8 pb-12">
      {/* Header Banner */}
      <div className="relative p-6 md:p-8 rounded-3xl cyber-card overflow-hidden">
        <div className="space-y-2 relative z-10">
          <div className="flex items-center gap-2 text-xs font-bold text-cyan-400 uppercase tracking-wider font-mono">
            <Lock className="h-4 w-4" />
            <span>Outbound Data Leakage Prevention (DLP)</span>
          </div>
          <h1 className="text-3xl font-extrabold text-slate-100 tracking-tight">
            Privacy Guardian &amp; DLP Inspector
          </h1>
          <p className="text-xs text-slate-400 max-w-2xl">
            Inspect outbound drafts, email bodies, and configuration snippets for exposed API secrets, private keys, payment credentials, and personally identifiable information (PII).
          </p>
        </div>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left: Input Textarea */}
        <div className="lg:col-span-6 space-y-4">
          <div className="p-6 md:p-8 rounded-3xl cyber-card space-y-4">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <FileText className="h-4 w-4 text-cyan-400" />
              <span>Draft Message / Content Snippet</span>
            </h3>

            <textarea
              rows={10}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste email draft or message to scan for secrets..."
              className="w-full bg-slate-950/70 border border-slate-800 rounded-2xl p-4 text-xs font-mono text-slate-200 focus:border-cyan-500/80 outline-none"
            />

            <button
              onClick={handleScanDLP}
              disabled={analyzing || !content}
              className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs tracking-wider uppercase transition shadow-[0_0_15px_rgba(6,182,212,0.25)] flex items-center justify-center gap-2 active:scale-95 disabled:opacity-50"
            >
              {analyzing ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin" />
                  <span>Scanning for Sensitive Identifiers...</span>
                </>
              ) : (
                <>
                  <Sparkles className="h-4 w-4" />
                  <span>Scan Content for Leakage</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right: DLP Findings & Redaction */}
        <div className="lg:col-span-6 space-y-6">
          {findings ? (
            <div className="p-6 md:p-8 rounded-3xl cyber-card space-y-6 animate-fade-in">
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div>
                  <span className="text-[10px] uppercase font-bold text-slate-500 font-mono block">DLP Exposure Rating</span>
                  <div className="mt-1">
                    <RiskBadge score={findings.risk_score} />
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-[10px] uppercase font-bold text-slate-500 font-mono block">Detected Secrets</span>
                  <span className="text-sm font-mono font-bold text-rose-400">{findings.total_entities} Entities</span>
                </div>
              </div>

              {/* Detected Entities */}
              <div className="space-y-2">
                {findings.entities.map((item: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start justify-between gap-3"
                  >
                    <div className="min-w-0">
                      <span className="text-xs font-bold text-slate-200 block">{item.type}</span>
                      <p className="text-[11px] font-mono text-rose-300 mt-0.5 truncate">{item.match}</p>
                    </div>
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 shrink-0">
                      {item.severity}
                    </span>
                  </div>
                ))}
              </div>

              {/* Redaction Action */}
              <div className="pt-2 border-t border-slate-800 space-y-4">
                <button
                  onClick={handleRedact}
                  className="w-full py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-cyan-500/30 text-cyan-300 text-xs font-bold transition flex items-center justify-center gap-2 active:scale-95"
                >
                  <Eraser className="h-4 w-4" />
                  <span>Generate Safe Redacted Preview</span>
                </button>

                {redactedText && (
                  <div className="space-y-2 animate-fade-in">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase font-bold text-emerald-400 font-mono">Sanitized Body</span>
                      <button
                        onClick={handleCopyRedacted}
                        className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold"
                      >
                        {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                        <span>{copied ? 'Copied' : 'Copy Sanitized'}</span>
                      </button>
                    </div>
                    <div className="p-4 rounded-2xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 whitespace-pre-wrap max-h-48 overflow-y-auto">
                      {redactedText}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="h-full min-h-80 p-12 rounded-3xl cyber-card border-dashed border-slate-800 flex flex-col items-center justify-center text-center space-y-3">
              <Lock className="h-10 w-10 text-slate-600" />
              <h3 className="text-base font-bold text-slate-300">Privacy Scan Idle</h3>
              <p className="text-xs text-slate-500 max-w-sm">
                Paste an email draft or code snippet on the left to verify zero sensitive tokens or personal credentials are exposed.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

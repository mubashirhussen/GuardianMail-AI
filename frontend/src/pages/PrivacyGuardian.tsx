import React, { useState } from 'react';
import { 
  Lock, Copy, Check, RefreshCw, Sparkles, FileText, Eraser, ShieldCheck
} from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';

interface DLPFinding {
  type: string;
  match: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
}

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

  const analyzeContentDLP = (text: string) => {
    const list: DLPFinding[] = [];

    // 1. Payment Keys & Gateway Secrets
    const paymentRegex = /\b(?:SAMPLE_API_KEY_TOKEN_[A-Za-z0-9]+|sk_live_[A-Za-z0-9]{24,}|pk_live_[A-Za-z0-9]{24,}|sq0csp-[0-9A-Za-z\-_]{22,}|access_token\$[a-zA-Z0-9_$]{16,})\b/g;
    let match;
    while ((match = paymentRegex.exec(text)) !== null) {
      list.push({ type: 'Payment Provider API Key', match: match[0], severity: 'CRITICAL', category: 'Payment Secrets' });
    }

    // 2. Repository & Cloud Access Tokens
    const repoTokenRegex = /\b(?:SAMPLE_REPO_ACCESS_TOKEN_[A-Za-z0-9]+|ghp_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9\-_]{20,}|AKIA[0-9A-Z]{16})\b/g;
    while ((match = repoTokenRegex.exec(text)) !== null) {
      list.push({ type: 'Repository Personal Access Token', match: match[0], severity: 'CRITICAL', category: 'Cloud Secrets' });
    }

    // 3. Private Keys
    const privateKeyRegex = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g;
    while ((match = privateKeyRegex.exec(text)) !== null) {
      list.push({ type: 'Private Cryptographic Key', match: match[0].slice(0, 36) + '...', severity: 'CRITICAL', category: 'Cryptography' });
    }

    // 4. JWT Bearer Tokens
    const jwtRegex = /\bey[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b/g;
    while ((match = jwtRegex.exec(text)) !== null) {
      list.push({ type: 'JSON Web Token (JWT)', match: match[0].slice(0, 28) + '...', severity: 'HIGH', category: 'Authentication Tokens' });
    }

    // 5. Direct Phone Numbers (PII)
    const phoneRegex = /(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
    while ((match = phoneRegex.exec(text)) !== null) {
      list.push({ type: 'Direct Phone Number (PII)', match: match[0], severity: 'MEDIUM', category: 'Personal Data' });
    }

    // 6. Corporate / Personal Email Addresses
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
    while ((match = emailRegex.exec(text)) !== null) {
      list.push({ type: 'Corporate Email Address', match: match[0], severity: 'LOW', category: 'Personal Data' });
    }

    // 7. Social Security Numbers (SSN)
    const ssnRegex = /\b\d{3}-\d{2}-\d{4}\b/g;
    while ((match = ssnRegex.exec(text)) !== null) {
      list.push({ type: 'Social Security Number (SSN)', match: match[0], severity: 'HIGH', category: 'Identity PII' });
    }

    // 8. Credit Card Numbers
    const ccRegex = /\b(?:\d{4}[ -]?){3}\d{4}\b/g;
    while ((match = ccRegex.exec(text)) !== null) {
      list.push({ type: 'Credit Card Number (PCI-DSS)', match: match[0], severity: 'CRITICAL', category: 'Financial Secrets' });
    }

    let rawScore = 0;
    list.forEach(item => {
      if (item.severity === 'CRITICAL') rawScore += 35;
      else if (item.severity === 'HIGH') rawScore += 20;
      else if (item.severity === 'MEDIUM') rawScore += 12;
      else rawScore += 5;
    });

    const score = Math.min(99.0, Math.max(list.length > 0 ? 18.5 : 0.0, rawScore));

    return {
      risk_score: parseFloat(score.toFixed(1)),
      total_entities: list.length,
      entities: list
    };
  };

  const handleScanDLP = () => {
    setAnalyzing(true);
    setRedactedText(null);
    setTimeout(() => {
      setAnalyzing(false);
      const res = analyzeContentDLP(content);
      setFindings(res);
    }, 400);
  };

  const handleRedact = () => {
    let sanitized = content;
    if (findings && findings.entities) {
      findings.entities.forEach((item: DLPFinding) => {
        if (item.match && !item.match.endsWith('...')) {
          sanitized = sanitized.split(item.match).join(`[REDACTED_${item.type.toUpperCase().replace(/[^A-Z]/g, '_')}]`);
        }
      });
    }
    // Universal regex passes
    sanitized = sanitized.replace(/(?:SAMPLE_API_KEY_TOKEN|sk_live_|pk_live_)[A-Za-z0-9_]+/g, '[REDACTED_API_KEY]');
    sanitized = sanitized.replace(/(?:SAMPLE_REPO_ACCESS_TOKEN|ghp_|glpat-)[A-Za-z0-9_]+/g, '[REDACTED_REPO_TOKEN]');
    sanitized = sanitized.replace(/(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, '[REDACTED_PHONE]');
    sanitized = sanitized.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[REDACTED_EMAIL]');
    sanitized = sanitized.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]');
    sanitized = sanitized.replace(/\b(?:\d{4}[ -]?){3}\d{4}\b/g, '[REDACTED_CARD_NUMBER]');
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
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <FileText className="h-4 w-4 text-cyan-400" />
                <span>Draft Message / Content Snippet</span>
              </h3>
              <div className="flex items-center gap-1.5 text-[11px]">
                <button
                  type="button"
                  onClick={() => {
                    setContent(`Hi Team,\n\nAttached is our API authorization key for the production payment bridge:\nSAMPLE_API_KEY_TOKEN_91029481029384910293\n\nAlso please update the vendor contact details:\nEmail: finance-lead@external-partner.com\nDirect Phone: +1-415-555-0199\nMaster Token: SAMPLE_REPO_ACCESS_TOKEN_918293819283\n\nBest regards,\nOperations Lead`);
                    setFindings(null);
                    setRedactedText(null);
                  }}
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-[10px]"
                >
                  Preset 1
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setContent(`Confidential HR Record:\nEmployee: Jane Doe\nSSN: 489-12-8821\nCorporate Card: 4532-8901-2384-9102\nDirect: +1-206-555-0144\nEmail: jane.doe@corporate-hr.net\nNotice: Please do not forward outside company perimeter.`);
                    setFindings(null);
                    setRedactedText(null);
                  }}
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-[10px]"
                >
                  Preset 2 (PII)
                </button>
              </div>
            </div>

            <textarea
              rows={10}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste email draft, config, or message to scan for secrets..."
              className="w-full bg-slate-950/70 border border-slate-800 rounded-2xl p-4 text-xs font-mono text-slate-200 focus:border-cyan-500/80 outline-none"
            />

            <button
              onClick={handleScanDLP}
              disabled={analyzing || !content.trim()}
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
                {findings.entities.length > 0 ? (
                  findings.entities.map((item: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start justify-between gap-3"
                    >
                      <div className="min-w-0">
                        <span className="text-xs font-bold text-slate-200 block">{item.type}</span>
                        <p className="text-[11px] font-mono text-rose-300 mt-0.5 truncate">{item.match}</p>
                      </div>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border shrink-0 ${
                        item.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' :
                        item.severity === 'HIGH' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                        item.severity === 'MEDIUM' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30' :
                        'bg-blue-500/10 text-blue-400 border-blue-500/30'
                      }`}>
                        {item.severity}
                      </span>
                    </div>
                  ))
                ) : (
                  <div className="p-6 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center gap-3 text-emerald-400">
                    <ShieldCheck className="h-6 w-6 shrink-0" />
                    <div>
                      <h4 className="text-sm font-bold">Zero Data Leakage Detected</h4>
                      <p className="text-xs text-emerald-300/80">No credentials, keys, or sensitive PII found in this message body.</p>
                    </div>
                  </div>
                )}
              </div>

              {/* Redaction Action */}
              {findings.entities.length > 0 && (
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
              )}
            </div>
          ) : (
            <div className="h-full min-h-80 p-12 rounded-3xl cyber-card border-dashed border-slate-800 flex flex-col items-center justify-center text-center space-y-3">
              <Lock className="h-10 w-10 text-slate-600" />
              <h3 className="text-base font-bold text-slate-300">Privacy Scan Ready</h3>
              <p className="text-xs text-slate-500 max-w-sm">
                Paste an email draft, code snippet, or configuration file on the left and click &quot;Scan Content for Leakage&quot; to test.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

import React, { useState } from 'react';
import { Sparkles, Mail, AlertTriangle, CheckCircle2, AlertCircle, ShieldAlert } from 'lucide-react';
import { threatsService } from '../services/threats';
import type { DetectThreatResponse } from '../services/threats';
import { getErrorMessage } from '../utils/errors';

// Severity color mapping from backend indicator severity
const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/20',
  HIGH: 'text-red-400 bg-red-500/10 border-red-500/20',
  MEDIUM: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  LOW: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
};

// Map verdict to display config
const VERDICT_CONFIG: Record<string, { label: string; color: string; icon: React.ReactNode; bg: string }> = {
  PHISHING: {
    label: 'Phishing',
    color: 'text-red-400',
    bg: 'border-red-500/30 bg-red-500/5',
    icon: <ShieldAlert className="h-5 w-5 text-red-400" />,
  },
  MALWARE: {
    label: 'Malware',
    color: 'text-red-500',
    bg: 'border-red-500/30 bg-red-500/5',
    icon: <AlertTriangle className="h-5 w-5 text-red-500" />,
  },
  BEC: {
    label: 'Business Email Compromise',
    color: 'text-orange-400',
    bg: 'border-orange-500/30 bg-orange-500/5',
    icon: <AlertTriangle className="h-5 w-5 text-orange-400" />,
  },
  SPAM: {
    label: 'Spam',
    color: 'text-amber-400',
    bg: 'border-amber-500/30 bg-amber-500/5',
    icon: <AlertCircle className="h-5 w-5 text-amber-400" />,
  },
  SUSPICIOUS: {
    label: 'Suspicious',
    color: 'text-amber-400',
    bg: 'border-amber-500/30 bg-amber-500/5',
    icon: <AlertCircle className="h-5 w-5 text-amber-400" />,
  },
  SAFE: {
    label: 'Safe',
    color: 'text-emerald-400',
    bg: 'border-emerald-500/30 bg-emerald-500/5',
    icon: <CheckCircle2 className="h-5 w-5 text-emerald-400" />,
  },
};

const RISK_LABEL = (score: number) => {
  if (score >= 80) return { label: 'Critical Risk', cls: 'text-red-400 bg-red-500/10 border-red-500/20' };
  if (score >= 60) return { label: 'High Risk', cls: 'text-red-400 bg-red-500/10 border-red-500/20' };
  if (score >= 40) return { label: 'Medium Risk', cls: 'text-amber-400 bg-amber-500/10 border-amber-500/20' };
  if (score >= 20) return { label: 'Low Risk', cls: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' };
  return { label: 'Safe', cls: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' };
};

// Step progress indicator shown during analysis
const ANALYSIS_STEPS = [
  'Parsing email structure',
  'Extracting indicators of compromise',
  'Checking sender reputation',
  'Scanning embedded URLs',
  'Detecting intent & manipulation',
  'Correlating threat intelligence',
  'Calculating risk score',
  'Generating AI explanation',
];

export const PhishingDetection: React.FC = () => {
  const [fromAddress, setFromAddress] = useState('');
  const [subject, setSubject] = useState('');
  const [emailContent, setEmailContent] = useState('');

  const [loading, setLoading] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [result, setResult] = useState<DetectThreatResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!emailContent.trim()) return;

    setLoading(true);
    setResult(null);
    setError(null);
    setCurrentStep(0);

    // Animate through analysis steps while waiting for backend
    const stepInterval = setInterval(() => {
      setCurrentStep((prev) => {
        if (prev < ANALYSIS_STEPS.length - 2) return prev + 1;
        clearInterval(stepInterval);
        return prev;
      });
    }, 350);

    try {
      const data = await threatsService.detectThreat({
        sender: fromAddress,
        subject,
        body: emailContent,
      });
      clearInterval(stepInterval);
      setCurrentStep(ANALYSIS_STEPS.length - 1);
      // Brief pause on final step before showing results
      await new Promise((r) => setTimeout(r, 300));
      setResult(data);
    } catch (err) {
      clearInterval(stepInterval);
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const verdictConfig = result ? (VERDICT_CONFIG[result.verdict] ?? VERDICT_CONFIG.SUSPICIOUS) : null;
  const riskLabel = result ? RISK_LABEL(result.risk_score) : null;

  return (
    <div className="space-y-6 pb-12">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Phishing Detection</h1>
        <p className="text-xs text-slate-400 mt-1">
          AI-powered email threat analysis. Detection is advisory — containment requires human authorization.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Email Input Form */}
        <div className="lg:col-span-6 cyber-card p-5 space-y-4">
          <h3 className="text-sm font-bold text-white">Email Input</h3>

          <div className="space-y-3">
            <div>
              <label className="text-[11px] font-semibold text-slate-400 block mb-1">
                From <span className="text-slate-600">(sender address)</span>
              </label>
              <input
                type="text"
                value={fromAddress}
                onChange={(e) => setFromAddress(e.target.value)}
                placeholder="sender@example.com"
                autoComplete="off"
                className="w-full bg-[#080d17] border border-[#172136] rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder:text-slate-600 outline-none focus:border-blue-500 transition"
              />
            </div>

            <div>
              <label className="text-[11px] font-semibold text-slate-400 block mb-1">Subject</label>
              <input
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="Email subject line"
                autoComplete="off"
                className="w-full bg-[#080d17] border border-[#172136] rounded-lg px-3 py-2 text-xs text-slate-200 placeholder:text-slate-600 outline-none focus:border-blue-500 transition"
              />
            </div>

            <div>
              <label className="text-[11px] font-semibold text-slate-400 block mb-1">
                Email Body <span className="text-red-400">*</span>
              </label>
              <textarea
                rows={10}
                value={emailContent}
                onChange={(e) => setEmailContent(e.target.value)}
                placeholder="Paste the full email body text here for analysis..."
                className="w-full bg-[#080d17] border border-[#172136] rounded-lg p-3 text-xs font-mono text-slate-200 placeholder:text-slate-600 outline-none focus:border-blue-500 transition resize-none"
              />
            </div>

            {error && (
              <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-xs flex items-center gap-2">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <button
              onClick={handleAnalyze}
              disabled={loading || !emailContent.trim()}
              className="w-full py-2.5 bg-[#2563eb] hover:bg-blue-600 text-white font-semibold text-xs rounded-lg shadow-md shadow-blue-600/20 transition active:scale-95 disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <span className="h-3.5 w-3.5 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  Analyzing with Neural Engine...
                </>
              ) : (
                <>
                  <Sparkles className="h-3.5 w-3.5" />
                  Analyze Email
                </>
              )}
            </button>

            {/* Security note */}
            <p className="text-[10px] text-slate-500 text-center leading-relaxed">
              AI detection identifies threats and generates recommendations.{' '}
              <strong className="text-slate-400">Containment actions require human authorization.</strong>
            </p>
          </div>
        </div>

        {/* Right: Analysis Results */}
        <div className="lg:col-span-6 cyber-card p-5 space-y-5">
          <h3 className="text-sm font-bold text-white">Analysis Results</h3>

          {/* Loading: step progress */}
          {loading && (
            <div className="space-y-4 animate-fade-in">
              <div className="flex items-center gap-3 p-4 rounded-xl bg-[#080d17] border border-[#172136]">
                <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center shrink-0">
                  <span className="h-4 w-4 rounded-full border-2 border-blue-400/30 border-t-blue-400 animate-spin" />
                </div>
                <div>
                  <span className="text-xs font-semibold text-slate-200 block">Neural Engine Processing</span>
                  <span className="text-[11px] text-blue-400 font-mono">{ANALYSIS_STEPS[currentStep]}</span>
                </div>
              </div>
              <div className="space-y-2 px-1">
                {ANALYSIS_STEPS.map((step, i) => (
                  <div key={i} className="flex items-center gap-2.5">
                    <div className={`h-1.5 w-1.5 rounded-full shrink-0 ${i <= currentStep ? 'bg-blue-400' : 'bg-[#172136]'}`} />
                    <span className={`text-[11px] font-mono ${i <= currentStep ? 'text-slate-300' : 'text-slate-600'}`}>{step}</span>
                    {i === currentStep && (
                      <span className="text-[10px] text-blue-400 font-mono animate-pulse">...</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Error state */}
          {!loading && error && !result && (
            <div className="h-48 flex flex-col items-center justify-center text-center space-y-3">
              <AlertCircle className="h-10 w-10 text-red-500/60" />
              <div>
                <p className="text-sm font-semibold text-slate-300">Analysis failed</p>
                <p className="text-xs text-slate-500 mt-1 max-w-xs">{error}</p>
              </div>
            </div>
          )}

          {/* Empty: no scan yet */}
          {!loading && !result && !error && (
            <div className="h-64 flex flex-col items-center justify-center text-slate-600 text-xs space-y-3">
              <Mail className="h-10 w-10" />
              <span className="text-center">Paste email content and click Analyze<br />to run the threat detection engine.</span>
            </div>
          )}

          {/* Results */}
          {!loading && result && verdictConfig && riskLabel && (
            <div className="space-y-4 animate-fade-in">
              {/* Verdict & Score */}
              <div className={`p-4 rounded-xl border ${verdictConfig.bg} flex items-center justify-between`}>
                <div className="flex items-center gap-3">
                  {verdictConfig.icon}
                  <div>
                    <span className="text-[10px] font-mono font-bold uppercase text-slate-500 block">Verdict</span>
                    <div className={`text-xl font-bold mt-0.5 ${verdictConfig.color}`}>{verdictConfig.label}</div>
                    <span className="text-[10px] text-slate-400 font-semibold">
                      {result.confidence_score ? `${Math.round(result.confidence_score)}% confidence` : 'AI analyzed'}
                    </span>
                  </div>
                </div>

                <div className="text-right flex flex-col items-end">
                  <span className="text-[10px] font-mono font-bold uppercase text-slate-500 block">Risk Score</span>
                  <div className="flex items-baseline gap-1 mt-0.5">
                    <span className={`text-2xl font-bold font-mono ${verdictConfig.color}`}>
                      {Math.round(result.risk_score)}
                    </span>
                    <span className="text-xs text-slate-500">/100</span>
                  </div>
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${riskLabel.cls}`}>
                    {riskLabel.label}
                  </span>
                </div>
              </div>

              {/* Indicators */}
              {result.indicators && result.indicators.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] font-mono font-bold uppercase text-slate-400 block">
                    Detection Indicators ({result.indicators.length})
                  </span>
                  <div className="space-y-1.5">
                    {result.indicators.map((ind, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-lg bg-[#080d17] border border-[#172136] flex items-center justify-between gap-3 text-xs"
                      >
                        <div className="min-w-0">
                          <span className="font-semibold text-slate-200 block">{ind.indicator}</span>
                          {ind.detail && (
                            <span className="text-[11px] font-mono text-slate-400 block truncate">{ind.detail}</span>
                          )}
                        </div>
                        <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border shrink-0 ${SEVERITY_COLORS[ind.severity] ?? SEVERITY_COLORS.MEDIUM}`}>
                          {ind.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* AI Explanation */}
              {result.explanation && (
                <div className="space-y-1.5 p-3 rounded-lg bg-[#080d17] border border-[#172136]">
                  <span className="text-[11px] font-bold text-white flex items-center gap-1.5">
                    <Sparkles className="h-3.5 w-3.5 text-blue-400" /> AI Explanation
                  </span>
                  <p className="text-xs text-slate-400 leading-relaxed">{result.explanation}</p>
                </div>
              )}

              {/* Recommendations */}
              {result.recommendations?.next_steps && result.recommendations.next_steps.length > 0 && (
                <div className="space-y-1.5 p-3 rounded-lg bg-[#080d17] border border-[#172136]">
                  <span className="text-[11px] font-bold text-white block">Recommended Actions</span>
                  <ul className="text-xs text-slate-400 space-y-1">
                    {result.recommendations.next_steps.map((step, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="h-1.5 w-1.5 rounded-full bg-blue-400 shrink-0 mt-1.5" />
                        {step}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Human authorization reminder */}
              <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/20 text-[11px] text-amber-300 flex items-start gap-2">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                <span>
                  AI detection is advisory. Sensitive containment actions (quarantine, block) require human authorization through Response Operations.
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

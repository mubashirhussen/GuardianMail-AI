import React, { useState } from 'react';
import { ShieldAlert, Clock, Lock, ShieldCheck } from 'lucide-react';

interface ApprovalModalProps {
  isOpen: boolean;
  onClose: () => void;
  onApprove: (tokenId: string, reason: string) => Promise<void>;
  onReject: (tokenId: string, reason: string) => Promise<void>;
  requestData: {
    decisionId: string;
    tokenId: string;
    action: string;
    targetResource: string;
    riskScore: number;
    indicators: string[];
    policyName: string;
    expiresInMinutes?: number;
  };
}

export const ApprovalModal: React.FC<ApprovalModalProps> = ({
  isOpen,
  onClose,
  onApprove,
  onReject,
  requestData,
}) => {
  const [justification, setJustification] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleAction = async (isApproved: boolean) => {
    if (!justification.trim()) {
      setError('Analyst operational justification is required for the immutable GRC audit chain.');
      return;
    }
    setError(null);
    setLoading(true);
    try {
      if (isApproved) {
        await onApprove(requestData.tokenId, justification);
      } else {
        await onReject(requestData.tokenId, justification);
      }
      onClose();
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Authorization request failed. Token may have expired or been invalidated.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-xl bg-slate-900 border border-slate-700/80 rounded-3xl shadow-2xl overflow-hidden space-y-6 p-6 sm:p-8">
        
        {/* Header Alert */}
        <div className="flex items-start gap-4">
          <div className="h-12 w-12 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0 shadow-[0_0_15px_rgba(245,158,11,0.2)]">
            <Lock className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center gap-2 text-[10px] font-bold text-amber-400 uppercase tracking-wider font-mono">
              <span>HUMAN-IN-THE-LOOP AUTHORIZATION GATE</span>
            </div>
            <h3 className="text-xl font-bold text-slate-100 mt-0.5">
              Authorize Sensitive Response Containment
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              AI has evaluated high threat risk. Execution is currently held in a <strong>fail-closed state</strong> awaiting human authorization.
            </p>
          </div>
        </div>

        {/* Error Notification */}
        {error && (
          <div className="flex items-center gap-2 p-3 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs rounded-xl">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Action Specification Table */}
        <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800/80 space-y-3 text-xs">
          <div className="flex justify-between items-center pb-2 border-b border-slate-800">
            <span className="text-slate-400 font-medium">Recommended Action:</span>
            <span className="font-mono font-bold text-rose-400">{requestData.action}</span>
          </div>
          <div className="flex justify-between items-center pb-2 border-b border-slate-800">
            <span className="text-slate-400 font-medium">Target Entity / Mailbox:</span>
            <span className="font-mono font-semibold text-slate-200">{requestData.targetResource}</span>
          </div>
          <div className="flex justify-between items-center pb-2 border-b border-slate-800">
            <span className="text-slate-400 font-medium">Risk Score &amp; Policy:</span>
            <span className="font-mono font-bold text-amber-400">
              {requestData.riskScore}/100 ({requestData.policyName})
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-slate-400 font-medium">Single-Use Token ID:</span>
            <span className="font-mono text-cyan-400 text-[11px] font-bold">{requestData.tokenId}</span>
          </div>
        </div>

        {/* Justification Field */}
        <div className="space-y-1.5">
          <label className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block">
            Analyst Operational Justification (Logged to SHA-256 Ledger)
          </label>
          <textarea
            required
            rows={2}
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
            placeholder="Verified typosquatting credential harvester targeting finance payroll..."
            className="w-full bg-slate-950/70 border border-slate-800 rounded-xl p-3 text-xs text-slate-200 focus:border-cyan-500/80 focus:ring-1 focus:ring-cyan-500/50 outline-none transition placeholder:text-slate-600"
          />
        </div>

        {/* Safety Warning */}
        <div className="p-3 rounded-xl bg-slate-950/40 border border-slate-800 text-[11px] text-slate-400 flex items-center gap-2">
          <Clock className="h-4 w-4 text-cyan-400 shrink-0" />
          <span>Token valid for single execution under strict tenant isolation. Replays will be rejected.</span>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-end gap-3 pt-2">
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            className="px-4 py-2.5 rounded-xl border border-slate-700 text-slate-300 hover:bg-slate-800 text-xs font-semibold transition"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => handleAction(false)}
            disabled={loading}
            className="px-4 py-2.5 rounded-xl border border-rose-500/40 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 text-xs font-bold transition"
          >
            Reject Action
          </button>
          <button
            type="button"
            onClick={() => handleAction(true)}
            disabled={loading}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 text-xs font-bold shadow-[0_0_20px_rgba(16,185,129,0.3)] transition transform active:scale-95 disabled:opacity-50"
          >
            <ShieldCheck className="h-4 w-4" />
            <span>{loading ? 'Authorizing...' : 'Authorize Sandbox Execution'}</span>
          </button>
        </div>

      </div>
    </div>
  );
};

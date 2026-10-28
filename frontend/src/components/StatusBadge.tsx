import React from 'react';
import { Clock, CheckCircle2, XCircle, AlertCircle, RefreshCw, Lock } from 'lucide-react';

interface StatusBadgeProps {
  status: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const normalized = status?.toUpperCase() || 'UNKNOWN';

  const config = {
    QUEUED: {
      bg: 'bg-slate-800/60 text-slate-300 border-slate-700',
      icon: Clock,
      label: 'QUEUED',
    },
    PENDING: {
      bg: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
      icon: Clock,
      label: 'PENDING',
    },
    PENDING_APPROVAL: {
      bg: 'bg-purple-500/15 text-purple-300 border-purple-500/30 shadow-[0_0_10px_rgba(168,85,247,0.15)]',
      icon: Lock,
      label: 'APPROVAL REQUIRED',
    },
    RUNNING: {
      bg: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
      icon: RefreshCw,
      label: 'RUNNING',
    },
    SUCCESS: {
      bg: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
      icon: CheckCircle2,
      label: 'SUCCESS',
    },
    CONTAINED: {
      bg: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
      icon: CheckCircle2,
      label: 'CONTAINED',
    },
    FAILED: {
      bg: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
      icon: XCircle,
      label: 'FAILED',
    },
    CANCELLED: {
      bg: 'bg-slate-800/40 text-slate-500 border-slate-700',
      icon: AlertCircle,
      label: 'CANCELLED',
    },
  }[normalized] || {
    bg: 'bg-slate-800 text-slate-300 border-slate-700',
    icon: AlertCircle,
    label: normalized,
  };

  const Icon = config.icon;

  return (
    <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border font-mono text-[11px] font-bold uppercase tracking-wider ${config.bg}`}>
      <Icon className={`h-3 w-3 shrink-0 ${normalized === 'RUNNING' ? 'animate-spin' : ''}`} />
      <span>{config.label}</span>
    </div>
  );
};

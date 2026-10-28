import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Laptop,
  Smartphone,
  Globe,
  MapPin,
  Clock,
  ShieldCheck,
  ShieldX,
  LogOut,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
} from 'lucide-react';
import { sessionsService } from '../services/sessions';
import type { SessionDevice } from '../services/sessions';
import { getErrorMessage } from '../utils/errors';
import { SkeletonRow } from '../components/ui/Skeleton';
import { EmptyState } from '../components/ui/EmptyState';
import { ErrorState } from '../components/ui/ErrorState';

const DEVICE_ICON = (os?: string, browser?: string) => {
  const lower = `${os ?? ''} ${browser ?? ''}`.toLowerCase();
  if (lower.includes('mobile') || lower.includes('android') || lower.includes('ios')) {
    return <Smartphone className="h-5 w-5 text-slate-400" />;
  }
  if (lower.includes('windows') || lower.includes('mac') || lower.includes('linux')) {
    return <Laptop className="h-5 w-5 text-slate-400" />;
  }
  return <Globe className="h-5 w-5 text-slate-400" />;
};

const RISK_BADGE = (level?: string) => {
  if (level === 'HIGH') return 'text-red-400 bg-red-500/10 border-red-500/20';
  if (level === 'MEDIUM') return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
  return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
};

const formatRelative = (ts?: string) => {
  if (!ts) return '—';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
};

export const Sessions: React.FC = () => {
  const queryClient = useQueryClient();
  const [confirmRevokeAll, setConfirmRevokeAll] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const {
    data: sessions,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => sessionsService.listSessions(),
    staleTime: 30_000,
  });

  const revokeMutation = useMutation({
    mutationFn: (sessionId: string) => sessionsService.revokeSession(sessionId),
    onMutate: (sessionId) => setRevokingId(sessionId),
    onSuccess: () => {
      setRevokingId(null);
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      setSuccessMsg('Session revoked successfully.');
      setTimeout(() => setSuccessMsg(null), 3000);
    },
    onError: () => setRevokingId(null),
  });

  const revokeAllMutation = useMutation({
    mutationFn: () => sessionsService.revokeAllOtherSessions(),
    onSuccess: (data) => {
      setConfirmRevokeAll(false);
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      setSuccessMsg(data.detail || `${data.revoked_count ?? 'Other'} sessions revoked.`);
      setTimeout(() => setSuccessMsg(null), 4000);
    },
  });

  const currentSession = sessions?.find((s) => s.is_current);
  const otherSessions = sessions?.filter((s) => !s.is_current) ?? [];

  const renderSessionCard = (session: SessionDevice) => (
    <div
      key={session.session_id}
      className={`p-4 rounded-xl border flex items-start gap-4 transition ${
        session.is_current
          ? 'bg-[#0d1929] border-blue-500/30'
          : 'bg-[#080d17] border-[#172136] hover:border-[#243556]'
      }`}
    >
      {/* Device icon */}
      <div className={`h-10 w-10 rounded-xl flex items-center justify-center shrink-0 ${
        session.is_current ? 'bg-blue-500/10 border border-blue-500/20' : 'bg-[#0d1322] border border-[#172136]'
      }`}>
        {DEVICE_ICON(session.os, session.browser)}
      </div>

      {/* Details */}
      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold text-slate-200">
            {session.browser || 'Unknown Browser'} • {session.os || 'Unknown OS'}
          </span>
          {session.is_current && (
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-blue-500/15 border border-blue-500/30 text-blue-400">
              Current Device
            </span>
          )}
          {session.is_trusted && (
            <span className="flex items-center gap-1 text-[10px] text-emerald-400 font-mono font-semibold">
              <ShieldCheck className="h-3 w-3" /> Trusted
            </span>
          )}
          {!session.is_trusted && !session.is_current && (
            <span className="flex items-center gap-1 text-[10px] text-amber-400 font-mono font-semibold">
              <ShieldX className="h-3 w-3" /> Unverified
            </span>
          )}
        </div>

        <div className="flex items-center flex-wrap gap-3 text-[11px] text-slate-400">
          {session.location && (
            <span className="flex items-center gap-1">
              <MapPin className="h-3 w-3" /> {session.location}
            </span>
          )}
          {session.ip_address && (
            <span className="font-mono">{session.ip_address}</span>
          )}
          {session.last_active_at && (
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" /> Active {formatRelative(session.last_active_at)}
            </span>
          )}
        </div>

        {session.risk_level && session.risk_level !== 'LOW' && (
          <span className={`inline-block text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${RISK_BADGE(session.risk_level)}`}>
            {session.risk_level} RISK
          </span>
        )}
      </div>

      {/* Action */}
      {!session.is_current && (
        <button
          onClick={() => revokeMutation.mutate(session.session_id)}
          disabled={revokingId === session.session_id}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#172136] hover:border-red-500/30 hover:bg-red-500/5 text-slate-400 hover:text-red-400 text-[11px] font-semibold transition shrink-0 disabled:opacity-50"
          title="Revoke this session"
        >
          {revokingId === session.session_id ? (
            <span className="h-3 w-3 rounded-full border-2 border-red-400/30 border-t-red-400 animate-spin" />
          ) : (
            <LogOut className="h-3 w-3" />
          )}
          Sign out
        </button>
      )}
    </div>
  );

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Devices & Sessions</h1>
          <p className="text-xs text-slate-400 mt-1">
            Manage active sessions across your devices. Revoke any session you don't recognize.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-2 px-3 py-2 bg-[#0d1322] hover:bg-[#121929] border border-[#172136] rounded-lg text-xs text-slate-300 font-semibold transition"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </button>
          {otherSessions.length > 0 && (
            <button
              onClick={() => setConfirmRevokeAll(true)}
              className="flex items-center gap-2 px-3 py-2 bg-red-500/10 hover:bg-red-500/15 border border-red-500/30 rounded-lg text-xs text-red-400 font-semibold transition"
            >
              <LogOut className="h-3.5 w-3.5" />
              Sign out all other devices
            </button>
          )}
        </div>
      </div>

      {/* Success banner */}
      {successMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-emerald-400 text-xs flex items-center gap-2 animate-fade-in">
          <CheckCircle2 className="h-4 w-4 shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Error */}
      {error && (
        <ErrorState
          message={getErrorMessage(error)}
          onRetry={() => refetch()}
        />
      )}

      {/* Loading */}
      {isLoading && (
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="cyber-card p-4">
              <SkeletonRow />
            </div>
          ))}
        </div>
      )}

      {/* No sessions */}
      {!isLoading && !error && sessions?.length === 0 && (
        <EmptyState variant="sessions" />
      )}

      {/* Current session */}
      {!isLoading && currentSession && (
        <div className="space-y-3">
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
            Current Session
          </h2>
          {renderSessionCard(currentSession)}
        </div>
      )}

      {/* Other sessions */}
      {!isLoading && otherSessions.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
            Other Active Sessions ({otherSessions.length})
          </h2>
          <div className="space-y-2">
            {otherSessions.map((session) => renderSessionCard(session))}
          </div>
        </div>
      )}

      {/* Revoke all confirm dialog */}
      {confirmRevokeAll && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="max-w-sm w-full bg-[#0d1322] border border-[#172136] rounded-2xl p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
                <AlertTriangle className="h-5 w-5 text-red-400" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white">Sign out all other devices?</h3>
                <p className="text-xs text-slate-400 mt-0.5">This will revoke {otherSessions.length} active session(s).</p>
              </div>
            </div>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setConfirmRevokeAll(false)}
                className="px-4 py-2 text-xs text-slate-300 border border-[#172136] rounded-xl hover:bg-[#121929] transition"
              >
                Cancel
              </button>
              <button
                onClick={() => revokeAllMutation.mutate()}
                disabled={revokeAllMutation.isPending}
                className="px-4 py-2 text-xs font-semibold text-white bg-red-600 hover:bg-red-700 rounded-xl transition disabled:opacity-50"
              >
                {revokeAllMutation.isPending ? 'Signing out...' : 'Sign out all'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Laptop,
  Smartphone,
  Globe,
  MapPin,
  Clock,
  ShieldCheck,
  ShieldAlert,
  Shield,
  LogOut,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { sessionsService } from '../services/sessions';
import type { SessionDevice } from '../services/sessions';
import { getErrorMessage } from '../utils/errors';
import { SkeletonRow } from '../components/ui/Skeleton';
import { EmptyState } from '../components/ui/EmptyState';

const DEVICE_ICON = (os?: string, browser?: string) => {
  const lower = `${os ?? ''} ${browser ?? ''}`.toLowerCase();
  if (lower.includes('mobile') || lower.includes('android') || lower.includes('ios')) {
    return <Smartphone className="h-5 w-5 text-blue-500 dark:text-blue-400" />;
  }
  if (lower.includes('windows') || lower.includes('mac') || lower.includes('linux')) {
    return <Laptop className="h-5 w-5 text-blue-500 dark:text-blue-400" />;
  }
  return <Globe className="h-5 w-5 text-blue-500 dark:text-blue-400" />;
};

const formatRelative = (ts?: string) => {
  if (!ts) return 'Just now';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
};

const formatTime = (d: Date) => {
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
};

export const Sessions: React.FC = () => {
  const queryClient = useQueryClient();
  const [confirmRevokeAll, setConfirmRevokeAll] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());
  const [refreshError, setRefreshError] = useState<string | null>(null);

  const {
    data: sessions,
    isLoading,
    isFetching,
    error,
    refetch,
  } = useQuery({
    queryKey: ['sessions'],
    queryFn: async () => {
      setRefreshError(null);
      const res = await sessionsService.listSessions();
      setLastRefreshed(new Date());
      return res;
    },
    staleTime: 30_000,
  });

  const handleRefresh = async () => {
    try {
      setRefreshError(null);
      await refetch();
      setSuccessMsg('Sessions refreshed from security backend.');
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: any) {
      setRefreshError('Unable to refresh session telemetry. Showing cached session records.');
    }
  };

  const revokeMutation = useMutation({
    mutationFn: (sessionId: string) => sessionsService.revokeSession(sessionId),
    onMutate: (sessionId) => setRevokingId(sessionId),
    onSuccess: () => {
      setRevokingId(null);
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      setSuccessMsg('Session revoked successfully.');
      setTimeout(() => setSuccessMsg(null), 3500);
    },
    onError: (err: any) => {
      setRevokingId(null);
      setRefreshError(getErrorMessage(err) || 'Failed to revoke session.');
    },
  });

  const revokeAllMutation = useMutation({
    mutationFn: () => sessionsService.revokeAllOtherSessions(),
    onSuccess: (data) => {
      setConfirmRevokeAll(false);
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      setSuccessMsg(data.detail || `${data.revoked_count ?? 'All other'} sessions revoked.`);
      setTimeout(() => setSuccessMsg(null), 4000);
    },
    onError: (err: any) => {
      setConfirmRevokeAll(false);
      setRefreshError(getErrorMessage(err) || 'Failed to sign out other sessions.');
    },
  });

  const currentSession = sessions?.find((s) => s.is_current);
  const otherSessions = sessions?.filter((s) => !s.is_current) ?? [];

  const renderRiskBadge = (risk?: string) => {
    if (risk === 'HIGH') {
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-0.5 rounded border text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/20">
          <AlertTriangle className="h-2.5 w-2.5" /> High Risk
        </span>
      );
    }
    if (risk === 'MEDIUM') {
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-0.5 rounded border text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-500/10 border-amber-200 dark:border-amber-500/20">
          <ShieldAlert className="h-2.5 w-2.5" /> Medium Risk
        </span>
      );
    }
    if (risk === 'LOW') {
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-0.5 rounded border text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/20">
          <ShieldCheck className="h-2.5 w-2.5" /> Low Risk
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 text-[10px] font-mono font-medium px-2 py-0.5 rounded border text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-500/10 border-slate-200 dark:border-slate-500/20">
        <Shield className="h-2.5 w-2.5" /> Not assessed
      </span>
    );
  };

  const renderIpDisplay = (ip?: string) => {
    if (!ip) return null;
    if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
      return (
        <span className="font-mono text-slate-600 dark:text-slate-400 flex items-center gap-1">
          <span className="h-1.5 w-1.5 rounded-full bg-slate-400 dark:bg-slate-500" />
          {ip} <span className="text-[10px] text-slate-400 dark:text-slate-500">(Local / Dev Session)</span>
        </span>
      );
    }
    return (
      <span className="font-mono text-slate-600 dark:text-slate-400 flex items-center gap-1">
        <span className="h-1.5 w-1.5 rounded-full bg-blue-500" />
        {ip}
      </span>
    );
  };

  const renderSessionCard = (session: SessionDevice) => {
    const isCurrent = session.is_current;
    return (
      <div
        key={session.session_id}
        className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 transition shadow-xs ${
          isCurrent
            ? 'session-card-current bg-blue-50/70 border-blue-200 dark:bg-[#0c1626] dark:border-blue-500/30'
            : 'session-card-other bg-white border-slate-200 hover:border-slate-300 dark:bg-[#0a101d] dark:border-[#182338] dark:hover:border-[#22314d]'
        }`}
      >
        <div className="flex items-start gap-3.5 min-w-0">
          <div
            className={`h-10 w-10 rounded-xl flex items-center justify-center shrink-0 ${
              isCurrent
                ? 'bg-blue-100 border border-blue-300 dark:bg-blue-500/15 dark:border-blue-500/30'
                : 'bg-slate-100 border border-slate-200 dark:bg-[#121927] dark:border-[#1d293d]'
            }`}
          >
            {DEVICE_ICON(session.os, session.browser)}
          </div>

          <div className="space-y-1.5 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {session.browser || 'Browser Session'} • {session.os || 'Desktop OS'}
              </span>

              {isCurrent && (
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-blue-500 text-white dark:bg-blue-500/20 dark:border dark:border-blue-400/40 dark:text-blue-300">
                  Current Device
                </span>
              )}

              {session.is_trusted ? (
                <span className="flex items-center gap-1 text-[10px] text-emerald-600 dark:text-emerald-400 font-mono font-semibold">
                  <ShieldCheck className="h-3 w-3" /> Trusted Device
                </span>
              ) : !isCurrent ? (
                <span className="flex items-center gap-1 text-[10px] text-slate-500 dark:text-slate-400 font-mono">
                  Standard Session
                </span>
              ) : null}
            </div>

            <div className="flex items-center flex-wrap gap-x-4 gap-y-1 text-xs text-slate-600 dark:text-slate-400">
              {session.location && (
                <span className="flex items-center gap-1">
                  <MapPin className="h-3 w-3 text-slate-400" /> {session.location}
                </span>
              )}
              {renderIpDisplay(session.ip_address)}
              {session.last_active_at && (
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3 text-slate-400" /> Active {formatRelative(session.last_active_at)}
                </span>
              )}
            </div>

            <div className="pt-0.5">
              {renderRiskBadge(session.risk_level)}
            </div>
          </div>
        </div>

        {!isCurrent && (
          <button
            onClick={() => revokeMutation.mutate(session.session_id)}
            disabled={revokingId === session.session_id}
            className="self-end sm:self-center flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-[#223049] hover:border-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 text-slate-600 hover:text-red-600 dark:text-slate-400 dark:hover:text-red-400 text-xs font-semibold transition shrink-0 disabled:opacity-50"
            title="Sign out of this session"
          >
            {revokingId === session.session_id ? (
              <span className="h-3 w-3 rounded-full border-2 border-red-500/30 border-t-red-500 animate-spin" />
            ) : (
              <LogOut className="h-3.5 w-3.5" />
            )}
            <span>Sign out</span>
          </button>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-6 max-w-5xl pb-16">
      {/* Header matching Phase 5 */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 dark:border-[#16233a] pb-5">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">Devices & Sessions</h1>
          <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
            Manage active sessions across your devices. Revoke any session you don't recognize.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 hidden sm:inline-block">
            Last checked: {formatTime(lastRefreshed)}
          </span>

          <button
            onClick={handleRefresh}
            disabled={isFetching}
            className="flex items-center gap-2 px-3 py-2 bg-white dark:bg-[#0c1424] hover:bg-slate-50 dark:hover:bg-[#131f38] border border-slate-200 dark:border-[#1e2d48] rounded-xl text-xs text-slate-700 dark:text-slate-200 font-semibold transition shadow-xs disabled:opacity-50"
            aria-label="Refresh active sessions"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? 'animate-spin text-blue-500' : 'text-slate-500'}`} />
            <span>{isFetching ? 'Refreshing...' : 'Refresh'}</span>
          </button>

          {otherSessions.length > 0 && (
            <button
              onClick={() => setConfirmRevokeAll(true)}
              disabled={revokeAllMutation.isPending}
              className="flex items-center gap-2 px-3.5 py-2 bg-red-50 dark:bg-red-500/10 hover:bg-red-100 dark:hover:bg-red-500/20 border border-red-200 dark:border-red-500/30 rounded-xl text-xs text-red-600 dark:text-red-400 font-semibold transition shadow-xs disabled:opacity-50"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span>Sign out all other devices</span>
            </button>
          )}
        </div>
      </div>

      {/* Notifications */}
      {successMsg && (
        <div className="p-3 bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-500/30 rounded-xl text-emerald-700 dark:text-emerald-400 text-xs flex items-center justify-between animate-fade-in shadow-xs">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>{successMsg}</span>
          </div>
          <button onClick={() => setSuccessMsg(null)} className="text-slate-400 hover:text-slate-600 dark:hover:text-white font-bold ml-2">×</button>
        </div>
      )}

      {refreshError && (
        <div className="p-3 bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-500/30 rounded-xl text-amber-800 dark:text-amber-400 text-xs flex items-center justify-between animate-fade-in shadow-xs">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{refreshError}</span>
          </div>
          <button onClick={() => setRefreshError(null)} className="text-slate-400 hover:text-slate-600 dark:hover:text-white font-bold ml-2">×</button>
        </div>
      )}

      {/* Skeleton Loading */}
      {isLoading && (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="p-4 rounded-xl border border-slate-200 dark:border-[#182338] bg-white dark:bg-[#0a101d]">
              <SkeletonRow />
            </div>
          ))}
        </div>
      )}

      {/* No Sessions Empty State */}
      {!isLoading && !error && sessions?.length === 0 && (
        <EmptyState variant="sessions" />
      )}

      {/* Current Session */}
      {!isLoading && currentSession && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400 font-semibold">
              CURRENT SESSION
            </h2>
          </div>
          {renderSessionCard(currentSession)}
        </div>
      )}

      {/* Other Active Sessions */}
      {!isLoading && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400 font-semibold">
              OTHER ACTIVE SESSIONS ({otherSessions.length})
            </h2>
          </div>

          {otherSessions.length > 0 ? (
            <div className="space-y-2.5">
              {otherSessions.map((session) => renderSessionCard(session))}
            </div>
          ) : (
            <div className="p-6 rounded-xl border border-dashed border-slate-200 dark:border-[#1b273d] bg-slate-50/50 dark:bg-[#080d17]/50 text-center space-y-1">
              <p className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                No other active sessions detected
              </p>
              <p className="text-[11px] text-slate-500 dark:text-slate-500">
                You are currently signed in only on this authorized device.
              </p>
            </div>
          )}
        </div>
      )}

      {/* Sign Out All Other Devices Modal */}
      {confirmRevokeAll && (
        <div className="fixed inset-0 bg-slate-900/60 dark:bg-black/80 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="max-w-md w-full bg-white dark:bg-[#0d1424] border border-slate-200 dark:border-[#1a263d] rounded-2xl p-6 space-y-4 shadow-2xl animate-fade-in">
            <div className="flex items-start gap-3.5">
              <div className="h-10 w-10 rounded-xl bg-red-100 dark:bg-red-500/15 border border-red-200 dark:border-red-500/30 flex items-center justify-center shrink-0">
                <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400" />
              </div>
              <div className="space-y-1">
                <h3 className="text-base font-bold text-slate-900 dark:text-white">
                  Sign out all other devices?
                </h3>
                <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                  This will revoke credentials and terminate {otherSessions.length} active session{otherSessions.length === 1 ? '' : 's'} across all other browsers and devices. Your current device will remain signed in.
                </p>
              </div>
            </div>

            <div className="flex gap-2.5 justify-end pt-2">
              <button
                type="button"
                onClick={() => setConfirmRevokeAll(false)}
                disabled={revokeAllMutation.isPending}
                className="px-4 py-2 text-xs font-semibold text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-[#1e2d48] rounded-xl hover:bg-slate-50 dark:hover:bg-[#131f38] transition disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => revokeAllMutation.mutate()}
                disabled={revokeAllMutation.isPending}
                className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-red-600 hover:bg-red-700 active:bg-red-800 rounded-xl transition shadow-md shadow-red-500/20 disabled:opacity-50"
              >
                {revokeAllMutation.isPending && (
                  <RefreshCw className="h-3 w-3 animate-spin" />
                )}
                <span>{revokeAllMutation.isPending ? 'Signing out...' : 'Confirm Sign Out All'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

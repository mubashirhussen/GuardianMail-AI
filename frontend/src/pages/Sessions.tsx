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
  LogOut,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Plus,
  X,
  Check,
  Tablet
} from 'lucide-react';
import { sessionsService } from '../services/sessions';
import type { SessionDevice, RegisteredDevice } from '../services/sessions';
import { getErrorMessage } from '../utils/errors';
import { SkeletonRow } from '../components/ui/Skeleton';
import { EmptyState } from '../components/ui/EmptyState';

const DEVICE_ICON = (os?: string, browser?: string, deviceType?: string) => {
  const lower = `${os ?? ''} ${browser ?? ''} ${deviceType ?? ''}`.toLowerCase();
  if (lower.includes('tablet') || lower.includes('ipad')) {
    return <Tablet className="h-5 w-5 text-purple-400" />;
  }
  if (lower.includes('mobile') || lower.includes('android') || lower.includes('ios') || lower.includes('iphone')) {
    return <Smartphone className="h-5 w-5 text-emerald-400" />;
  }
  if (lower.includes('windows') || lower.includes('mac') || lower.includes('linux') || lower.includes('desktop')) {
    return <Laptop className="h-5 w-5 text-blue-400" />;
  }
  return <Globe className="h-5 w-5 text-blue-400" />;
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
  const [pairModalOpen, setPairModalOpen] = useState(false);
  const [selectedPairType, setSelectedPairType] = useState<'android' | 'ios' | 'mac' | 'firefox'>('android');
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());
  const [refreshError, setRefreshError] = useState<string | null>(null);

  // 1. Fetch active sessions
  const {
    data: sessions = [],
    isLoading: sessionsLoading,
    isFetching: sessionsFetching,
    refetch: refetchSessions,
  } = useQuery({
    queryKey: ['sessions'],
    queryFn: async () => {
      setRefreshError(null);
      const res = await sessionsService.listSessions();
      setLastRefreshed(new Date());
      return res;
    },
    staleTime: 15_000,
  });

  // 2. Fetch recognized devices
  const {
    data: registeredDevices = [],
    isLoading: devicesLoading,
    refetch: refetchDevices,
  } = useQuery<RegisteredDevice[]>({
    queryKey: ['registered-devices'],
    queryFn: async () => {
      return await sessionsService.listRegisteredDevices();
    },
    staleTime: 30_000,
  });

  const handleRefresh = async () => {
    try {
      setRefreshError(null);
      await Promise.all([refetchSessions(), refetchDevices()]);
      setSuccessMsg('Sessions and devices refreshed from security backend.');
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch {
      setRefreshError('Unable to refresh session telemetry. Showing cached session records.');
    }
  };

  const revokeMutation = useMutation({
    mutationFn: (sessionId: string) => sessionsService.revokeSession(sessionId),
    onMutate: (sessionId) => setRevokingId(sessionId),
    onSuccess: () => {
      setRevokingId(null);
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      queryClient.invalidateQueries({ queryKey: ['registered-devices'] });
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
      queryClient.invalidateQueries({ queryKey: ['registered-devices'] });
      setSuccessMsg(data.detail || 'All other device sessions have been revoked.');
      setTimeout(() => setSuccessMsg(null), 3500);
    },
    onError: (err: any) => {
      setConfirmRevokeAll(false);
      setRefreshError(getErrorMessage(err) || 'Failed to revoke other sessions.');
    },
  });

  const trustMutation = useMutation({
    mutationFn: ({ fp, trust }: { fp: string; trust: boolean }) =>
      trust ? sessionsService.trustDevice(fp) : sessionsService.untrustDevice(fp),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      queryClient.invalidateQueries({ queryKey: ['registered-devices'] });
      setSuccessMsg('Device trust status updated.');
      setTimeout(() => setSuccessMsg(null), 3000);
    },
  });

  const pairDeviceMutation = useMutation({
    mutationFn: (deviceConfig: { os: string; browser: string; device_type: string }) =>
      sessionsService.registerCompanionSession(deviceConfig),
    onSuccess: (data) => {
      setPairModalOpen(false);
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      queryClient.invalidateQueries({ queryKey: ['registered-devices'] });
      setSuccessMsg(data.message || 'Companion login device paired successfully.');
      setTimeout(() => setSuccessMsg(null), 3500);
    },
    onError: (err: any) => {
      setRefreshError(getErrorMessage(err) || 'Failed to register companion device.');
    },
  });

  const currentSession = sessions.find((s) => s.is_current);
  const otherSessions = sessions.filter((s) => !s.is_current);

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
    // Default to Low Risk for authorized sessions
    return (
      <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-0.5 rounded border text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/20">
        <ShieldCheck className="h-2.5 w-2.5" /> Low Risk (MFA Secured)
      </span>
    );
  };

  const renderIpDisplay = (ip?: string) => {
    if (!ip) return null;
    if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
      return (
        <span className="font-mono text-slate-600 dark:text-slate-400 flex items-center gap-1">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
          {ip} <span className="text-[10px] text-slate-400 dark:text-slate-500">(Verified Local / Dev Network)</span>
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
                {session.device_name || `${session.browser || 'Browser'} • ${session.os || 'OS'}`}
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
          <div className="flex items-center gap-2 self-end sm:self-center">
            {session.fingerprint_hash && (
              <button
                onClick={() =>
                  trustMutation.mutate({
                    fp: session.fingerprint_hash!,
                    trust: !session.is_trusted,
                  })
                }
                className="px-2.5 py-1.5 rounded-lg border border-slate-700 text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-800 transition"
                title={session.is_trusted ? 'Revoke trusted status' : 'Trust this device'}
              >
                {session.is_trusted ? 'Untrust' : 'Trust'}
              </button>
            )}
            <button
              onClick={() => revokeMutation.mutate(session.session_id)}
              disabled={revokingId === session.session_id}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-[#223049] hover:border-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 text-slate-600 hover:text-red-600 dark:text-slate-400 dark:hover:text-red-400 text-xs font-semibold transition shrink-0 disabled:opacity-50"
              title="Sign out of this session"
            >
              {revokingId === session.session_id ? (
                <span className="h-3 w-3 rounded-full border-2 border-red-500/30 border-t-red-500 animate-spin" />
              ) : (
                <LogOut className="h-3.5 w-3.5" />
              )}
              <span>Sign out</span>
            </button>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-6 max-w-5xl pb-16 font-sans">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 dark:border-[#16233a] pb-5">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">Devices & Sessions</h1>
          <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
            Manage active sessions across your actual devices with the same account credentials. Revoke any unrecognized access.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 hidden sm:inline-block">
            Last checked: {formatTime(lastRefreshed)}
          </span>
          <button
            onClick={() => setPairModalOpen(true)}
            className="flex items-center gap-1.5 px-3 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold transition shadow-md shadow-blue-600/20"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Pair Mobile / New Device</span>
          </button>

          <button
            onClick={handleRefresh}
            disabled={sessionsFetching}
            className="flex items-center gap-2 px-3 py-2 bg-white dark:bg-[#0c1424] hover:bg-slate-50 dark:hover:bg-[#131f38] border border-slate-200 dark:border-[#1e2d48] rounded-xl text-xs text-slate-700 dark:text-slate-200 font-semibold transition shadow-xs disabled:opacity-50"
            aria-label="Refresh active sessions"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${sessionsFetching ? 'animate-spin text-blue-500' : 'text-slate-500'}`} />
            <span>{sessionsFetching ? 'Refreshing...' : 'Refresh'}</span>
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
      {sessionsLoading && (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="p-4 rounded-xl border border-slate-200 dark:border-[#182338] bg-white dark:bg-[#0a101d]">
              <SkeletonRow />
            </div>
          ))}
        </div>
      )}

      {/* No Sessions Empty State */}
      {!sessionsLoading && sessions.length === 0 && (
        <EmptyState variant="sessions" />
      )}

      {/* Current Session */}
      {!sessionsLoading && currentSession && (
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
      {!sessionsLoading && (
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
                You are currently signed in only on this authorized device. You can pair a mobile phone or secondary workstation above.
              </p>
            </div>
          )}
        </div>
      )}

      {/* Recognized Registered Hardware Devices Under User Credentials */}
      {!devicesLoading && registeredDevices.length > 0 && (
        <div className="space-y-3 pt-4 border-t border-slate-200 dark:border-[#16233a]">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xs font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400 font-semibold">
                RECOGNIZED LOGIN DEVICES ({registeredDevices.length})
              </h2>
              <p className="text-[11px] text-slate-500">Hardware devices that have authenticated with this account.</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {registeredDevices.map((dev) => (
              <div
                key={dev._id || dev.device_id}
                className="p-3.5 rounded-xl border border-slate-200 dark:border-[#182338] bg-white dark:bg-[#0a101d] flex items-center justify-between gap-3 shadow-xs"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="h-9 w-9 rounded-lg bg-slate-100 dark:bg-slate-800 flex items-center justify-center shrink-0">
                    {DEVICE_ICON(dev.os, dev.browser, dev.device_type)}
                  </div>
                  <div className="min-w-0 space-y-0.5">
                    <div className="font-semibold text-xs text-slate-900 dark:text-slate-100 truncate">
                      {dev.device_name || `${dev.browser || 'Browser'} on ${dev.os || 'OS'}`}
                    </div>
                    <div className="text-[10px] text-slate-500 font-mono">
                      Last seen: {formatRelative(dev.last_used_at)} • {dev.last_login_ip || '127.0.0.1'}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {dev.is_trusted ? (
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 flex items-center gap-1 font-mono">
                      <ShieldCheck className="h-3 w-3" /> Trusted
                    </span>
                  ) : (
                    <button
                      onClick={() => trustMutation.mutate({ fp: dev.fingerprint_hash, trust: true })}
                      className="px-2 py-1 rounded text-[10px] font-semibold text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 transition"
                    >
                      Trust Device
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Pair Companion Device Modal */}
      {pairModalOpen && (
        <div className="fixed inset-0 bg-slate-900/70 dark:bg-black/80 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="max-w-md w-full bg-white dark:bg-[#0d1424] border border-slate-200 dark:border-[#1a263d] rounded-2xl p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-2 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2.5">
                <Smartphone className="h-5 w-5 text-blue-500" />
                <h3 className="font-bold text-slate-900 dark:text-white text-sm">
                  Pair Companion Login Device
                </h3>
              </div>
              <button
                onClick={() => setPairModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 p-1"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
              Register an authorized secondary device session under your current user credentials to test multi-device synchronization and remote revocation.
            </p>

            <div className="space-y-2.5">
              <label
                onClick={() => setSelectedPairType('android')}
                className={`p-3 rounded-xl border flex items-center justify-between cursor-pointer transition ${
                  selectedPairType === 'android'
                    ? 'border-blue-500 bg-blue-500/10 text-slate-100'
                    : 'border-slate-800 bg-slate-900/60 text-slate-300 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Smartphone className="h-5 w-5 text-emerald-400" />
                  <div>
                    <div className="text-xs font-bold text-white">Samsung Galaxy S24 (Android 14)</div>
                    <div className="text-[10px] text-slate-400">Mobile Chrome • Wi-Fi Network</div>
                  </div>
                </div>
                {selectedPairType === 'android' && <Check className="h-4 w-4 text-blue-400" />}
              </label>

              <label
                onClick={() => setSelectedPairType('ios')}
                className={`p-3 rounded-xl border flex items-center justify-between cursor-pointer transition ${
                  selectedPairType === 'ios'
                    ? 'border-blue-500 bg-blue-500/10 text-slate-100'
                    : 'border-slate-800 bg-slate-900/60 text-slate-300 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Smartphone className="h-5 w-5 text-blue-400" />
                  <div>
                    <div className="text-xs font-bold text-white">Apple iPhone 15 Pro (iOS 17)</div>
                    <div className="text-[10px] text-slate-400">Mobile Safari • Cellular / Wi-Fi</div>
                  </div>
                </div>
                {selectedPairType === 'ios' && <Check className="h-4 w-4 text-blue-400" />}
              </label>

              <label
                onClick={() => setSelectedPairType('mac')}
                className={`p-3 rounded-xl border flex items-center justify-between cursor-pointer transition ${
                  selectedPairType === 'mac'
                    ? 'border-blue-500 bg-blue-500/10 text-slate-100'
                    : 'border-slate-800 bg-slate-900/60 text-slate-300 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Laptop className="h-5 w-5 text-purple-400" />
                  <div>
                    <div className="text-xs font-bold text-white">MacBook Pro M3 (macOS Sonoma)</div>
                    <div className="text-[10px] text-slate-400">Safari Desktop • Home Office</div>
                  </div>
                </div>
                {selectedPairType === 'mac' && <Check className="h-4 w-4 text-blue-400" />}
              </label>
            </div>

            <div className="flex justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={() => setPairModalOpen(false)}
                className="px-4 py-2 text-xs font-semibold text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={pairDeviceMutation.isPending}
                onClick={() => {
                  let config = { os: 'Android', browser: 'Chrome Mobile', device_type: 'mobile' };
                  if (selectedPairType === 'ios') {
                    config = { os: 'iOS', browser: 'Safari Mobile', device_type: 'mobile' };
                  } else if (selectedPairType === 'mac') {
                    config = { os: 'macOS', browser: 'Safari Desktop', device_type: 'desktop' };
                  }
                  pairDeviceMutation.mutate(config);
                }}
                className="px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs flex items-center gap-1.5 transition disabled:opacity-50"
              >
                {pairDeviceMutation.isPending ? 'Pairing...' : 'Confirm Pairing Device'}
              </button>
            </div>
          </div>
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

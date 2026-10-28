import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { 
  Eye, EyeOff, Lock, Trash2, RefreshCw 
} from 'lucide-react';
import { apiClient } from '../api/client';

export const PrivacyScore: React.FC = () => {
  const [revoking, setRevoking] = useState<string | null>(null);

  const { refetch, isFetching } = useQuery({
    queryKey: ['privacy', 'exposure'],
    queryFn: async () => {
      try {
        const res = await apiClient.get('/exposure/summary');
        return res.data;
      } catch {
        return null;
      }
    },
  });

  const oauthApps = [
    {
      id: 'app-gmail',
      name: 'Google Workspace Mail Sync',
      vendor: 'Google LLC',
      scopes: ['gmail.readonly', 'userinfo.email'],
      risk: 'LOW',
      lastUsed: '2 minutes ago',
    },
    {
      id: 'app-slack',
      name: 'SOC Escalation Slack Bot',
      vendor: 'Slack Technologies',
      scopes: ['chat:write', 'channels:read'],
      risk: 'LOW',
      lastUsed: '1 hour ago',
    },
    {
      id: 'app-unverified',
      name: 'Legacy Analytics Extractor',
      vendor: 'Third-party Analytics Corp',
      scopes: ['mail.send', 'contacts.read'],
      risk: 'HIGH',
      lastUsed: '14 days ago',
    },
  ];

  const trackersBlocked = [
    { name: 'HubSpot Tracking Pixel', domain: 'track.hubspot.com', type: 'Email Read Beacon', count: 142 },
    { name: 'Mailchimp Open Tracker', domain: 'list-manage.com', type: '1x1 Invisible GIF', count: 89 },
    { name: 'Mixpanel Fingerprint Script', domain: 'api.mixpanel.com', type: 'Telemetry Collector', count: 34 },
  ];

  const handleRevokeApp = async (appId: string) => {
    setRevoking(appId);
    try {
      await new Promise((r) => setTimeout(r, 800));
      await refetch();
    } finally {
      setRevoking(null);
    }
  };

  const privacyScore = 89.2;

  return (
    <div className="space-y-8 pb-12">
      {/* Header Banner */}
      <div className="relative p-6 md:p-8 rounded-3xl cyber-card overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs font-bold text-cyan-400 uppercase tracking-wider font-mono">
              <Eye className="h-4 w-4" />
              <span>Data Leakage Prevention &amp; Privacy Telemetry</span>
            </div>
            <h1 className="text-3xl font-extrabold text-slate-100 tracking-tight">
              Enterprise Privacy Score
            </h1>
            <p className="text-xs text-slate-400 max-w-2xl">
              Real-time inspection of tracking pixels, OAuth scopes, third-party data access, and outbound sensitive identifier leakage across email channels.
            </p>
          </div>

          <div className="flex items-center gap-4 shrink-0">
            <div className="px-6 py-4 rounded-2xl bg-slate-950/80 border border-slate-800 text-center">
              <span className="text-[10px] uppercase font-bold text-slate-400 font-mono tracking-wider block">Privacy Rating</span>
              <div className="flex items-baseline justify-center gap-1 mt-1">
                <span className="text-4xl font-black text-cyan-400 font-mono">{privacyScore}</span>
                <span className="text-xs text-slate-400 font-bold">/100</span>
              </div>
              <span className="text-[10px] font-bold text-cyan-400 font-mono">ENHANCED PRIVACY</span>
            </div>
          </div>
        </div>
      </div>

      {/* Grid: Trackers and OAuth Apps */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Blocked Trackers Panel */}
        <div className="p-6 md:p-8 rounded-3xl cyber-card space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <EyeOff className="h-5 w-5 text-cyan-400" />
                <span>Blocked Email Trackers &amp; Beacons</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Neutralized 1x1 tracking pixels and telemetry beacons</p>
            </div>
            <span className="text-xs font-mono font-bold px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-cyan-400">
              265 Total Blocked
            </span>
          </div>

          <div className="space-y-3">
            {trackersBlocked.map((tracker) => (
              <div
                key={tracker.domain}
                className="p-4 rounded-2xl bg-slate-950/60 border border-slate-800 flex items-center justify-between gap-4"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-slate-200 truncate">{tracker.name}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400">
                      {tracker.type}
                    </span>
                  </div>
                  <p className="text-[11px] font-mono text-cyan-400 mt-0.5 truncate">{tracker.domain}</p>
                </div>
                <div className="text-right shrink-0">
                  <span className="text-xs font-mono font-bold text-emerald-400">{tracker.count}</span>
                  <span className="text-[10px] text-slate-500 block">Stripped</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* OAuth Apps Audit Panel */}
        <div className="p-6 md:p-8 rounded-3xl cyber-card space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Lock className="h-5 w-5 text-purple-400" />
                <span>Connected OAuth Applications</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Third-party integrations with mailbox access grants</p>
            </div>
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-400 hover:text-slate-200 transition"
              title="Refresh grants"
            >
              <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="space-y-3">
            {oauthApps.map((app) => (
              <div
                key={app.id}
                className="p-4 rounded-2xl bg-slate-950/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-slate-200 truncate">{app.name}</span>
                    <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                      app.risk === 'HIGH'
                        ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                        : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                    }`}>
                      {app.risk} RISK
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {app.scopes.map((scope) => (
                      <span key={scope} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                        {scope}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="flex items-center justify-between sm:justify-end gap-3 pt-2 sm:pt-0 border-t sm:border-t-0 border-slate-800 shrink-0">
                  <span className="text-[10px] text-slate-500">{app.lastUsed}</span>
                  {app.risk === 'HIGH' ? (
                    <button
                      onClick={() => handleRevokeApp(app.id)}
                      disabled={revoking === app.id}
                      className="px-2.5 py-1 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-300 text-[11px] font-bold transition flex items-center gap-1"
                    >
                      <Trash2 className="h-3 w-3" />
                      <span>{revoking === app.id ? 'Revoking...' : 'Revoke'}</span>
                    </button>
                  ) : (
                    <div className="text-[11px] font-semibold text-slate-500">Authorized</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

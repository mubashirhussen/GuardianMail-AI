import React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { authService } from '../services/auth';
import { 
  Laptop, Smartphone, Globe, ShieldAlert, KeyRound, 
  Trash2, ShieldCheck
} from 'lucide-react';
import { Loader } from '../components/Loader';

export const Devices: React.FC = () => {
  const queryClient = useQueryClient();

  // 1. Fetch Sessions
  const { data: sessions, isLoading, error } = useQuery({
    queryKey: ['auth', 'sessions'],
    queryFn: () => authService.getSessions()
  });

  // 2. Revoke Session Mutation
  const revokeMutation = useMutation({
    mutationFn: (sessionId: string) => authService.revokeSession(sessionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auth', 'sessions'] });
      alert('Security session revoked successfully.');
    },
    onError: (err: any) => {
      alert(err?.response?.data?.detail || 'Failed to revoke session.');
    }
  });

  return (
    <div className="space-y-6 font-sans">
      {/* Title Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-50 tracking-tight">Devices & Sessions Security</h1>
        <p className="text-xs text-slate-400">Review currently authenticated browser sessions and trusted hardware access logs</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Columns: Devices lists */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-4">
          <div className="flex items-center gap-2">
            <KeyRound className="h-4.5 w-4.5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200">Active Authentication Sessions</h3>
          </div>

          <div className="space-y-3">
            {isLoading ? (
              <Loader />
            ) : error ? (
              <p className="text-xs text-red-400 text-center py-6">Could not pull active session logs.</p>
            ) : sessions && sessions.length > 0 ? (
              sessions.map((sess) => {
                const isCurrent = sess.is_current || false;
                const isMobile = /mobile|android|iphone/i.test(sess.user_agent || '');
                const Icon = isMobile ? Smartphone : Laptop;

                return (
                  <div key={sess.session_id} className="p-4 bg-slate-950/60 border border-slate-850 rounded-xl flex items-center justify-between gap-4 hover:border-slate-750 transition text-xs">
                    <div className="flex gap-4 items-start">
                      <div className="h-10 w-10 bg-slate-900 rounded-lg flex items-center justify-center border border-slate-800 text-cyan-400 shrink-0">
                        <Icon className="h-5 w-5" />
                      </div>
                      <div className="space-y-1 overflow-hidden">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-bold text-slate-200 truncate">{sess.device_name || 'Generic Web Portal Client'}</span>
                          {isCurrent && (
                            <span className="text-[8px] font-extrabold uppercase bg-cyan-500/10 text-cyan-400 border border-cyan-500/25 px-2 py-0.2 rounded-full">
                              Current Session
                            </span>
                          )}
                        </div>
                        <p className="text-[10px] text-slate-500 font-mono truncate max-w-[300px]">Agent: {sess.user_agent}</p>
                        <div className="flex gap-4 text-[9px] text-slate-500 font-bold flex-wrap">
                          <span className="flex items-center gap-1"><Globe className="h-3 w-3" /> IP: {sess.ip_address}</span>
                          <span>Logged: {new Date(sess.created_at).toLocaleString()}</span>
                        </div>
                      </div>
                    </div>
                    
                    {!isCurrent && (
                      <button
                        onClick={() => revokeMutation.mutate(sess.session_id)}
                        className="p-2 text-red-500 hover:text-red-400 bg-red-500/5 hover:bg-red-500/10 border border-red-500/20 hover:border-red-500/40 rounded-lg transition"
                        title="Revoke session session"
                      >
                        <Trash2 className="h-4.5 w-4.5" />
                      </button>
                    )}
                  </div>
                );
              })
            ) : (
              <p className="text-xs text-slate-500 text-center py-6">No authenticated sessions registered.</p>
            )}
          </div>
        </div>

        {/* Right Column: Security compliance checklist */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4.5 w-4.5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Device Hygiene Guidelines</h3>
          </div>
          <div className="space-y-4 text-xs leading-relaxed text-slate-400 font-medium">
            <div className="p-3 bg-slate-950/40 border border-slate-850 rounded-xl flex gap-3">
              <ShieldAlert className="h-5 w-5 text-amber-500 shrink-0" />
              <p className="text-[11px]">
                Revoke any active session with an unknown IP or user agent immediately to prevent identity hijacking.
              </p>
            </div>
            <p>
              Your corporate workspace profile strictly audits hardware identifiers. If you access the SOC Command console from a public machine, make sure to explicitly sign out to invalidate stored JWT credentials tokens in the browser database.
            </p>
          </div>
        </div>

      </div>
    </div>
  );
};

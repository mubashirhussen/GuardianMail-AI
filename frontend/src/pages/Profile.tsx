import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { authService } from '../services/auth';
import { gmailService } from '../services/gmail';
import { useAuth } from '../contexts/AuthContext';
import { 
  User, Mail, Shield, Trash2, Link2, Sparkles, CheckCircle2, X, Lock
} from 'lucide-react';
import { Loader } from '../components/Loader';

export const Profile: React.FC = () => {
  const queryClient = useQueryClient();
  const { user, refreshUser } = useAuth();
  
  // Local state for profile form
  const [fullName, setFullName] = useState(user?.full_name || '');
  const [username, setUsername] = useState(user?.username || '');
  const [googleCode, setGoogleCode] = useState('');
  const [mfaEnabled, setMfaEnabled] = useState(user?.mfa_enabled || false);
  const [connectModalOpen, setConnectModalOpen] = useState(false);
  const [connecting, setConnecting] = useState(false);

  // 1. Query: Fetch connected Gmail accounts
  const { data: gmailAccounts, isLoading: gmailLoading } = useQuery({
    queryKey: ['gmail', 'accounts'],
    queryFn: () => gmailService.listAccounts()
  });

  // Query: Fetch permissions disclosure
  const { data: permissionsInfo } = useQuery({
    queryKey: ['gmail', 'permissions'],
    queryFn: () => gmailService.getPermissions(),
    staleTime: 1000 * 60 * 60
  });

  // Mutations
  const updateProfileMutation = useMutation({
    mutationFn: (payload: any) => authService.updateProfile(payload),
    onSuccess: () => {
      refreshUser();
      alert('Profile details updated successfully.');
    },
    onError: (err: any) => {
      alert(err?.response?.data?.detail || 'Failed to update profile.');
    }
  });

  const connectGmailMutation = useMutation({
    mutationFn: (code: string) => gmailService.connectAccount(code),
    onSuccess: () => {
      setGoogleCode('');
      setConnectModalOpen(false);
      queryClient.invalidateQueries({ queryKey: ['gmail', 'accounts'] });
      alert('Gmail account connected successfully for real-time email defense.');
    },
    onError: (err: any) => {
      alert(err?.response?.data?.detail || 'Failed to link Google mailbox. Verify API OAuth tokens.');
    }
  });

  const disconnectGmailMutation = useMutation({
    mutationFn: (email: string) => gmailService.disconnectAccount(email),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gmail', 'accounts'] });
      alert('Gmail account sync disconnected. Tokens revoked.');
    }
  });

  const triggerSyncMutation = useMutation({
    mutationFn: (email: string) => gmailService.triggerSync(email),
    onSuccess: () => {
      alert('Sync task dispatched to Celery background workers.');
    }
  });

  const handleLaunchGoogleConsent = async () => {
    setConnecting(true);
    try {
      const data = await gmailService.getAuthUrl();
      if (data?.auth_url) {
        window.location.href = data.auth_url;
      }
    } catch (e: any) {
      alert(e?.message || 'Failed to generate Gmail consent link.');
      setConnecting(false);
    }
  };

  const handleProfileSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    updateProfileMutation.mutate({ full_name: fullName, username });
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Title Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-50 tracking-tight">Identity & Profile Settings</h1>
        <p className="text-xs text-slate-400">Manage account privileges, security credentials, and email sync integrations</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Columns: Profile details form */}
        <div className="lg:col-span-2 space-y-6">
          {/* Profile details */}
          <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg">
            <form onSubmit={handleProfileSubmit} className="space-y-4 text-xs">
              <div className="flex items-center gap-2">
                <User className="h-4.5 w-4.5 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-200">Account Details</h3>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Full Name</label>
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 outline-none focus:border-cyan-500/50"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Username</label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 outline-none focus:border-cyan-500/50"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Email Address</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-650" />
                  <input
                    type="email"
                    disabled
                    value={user?.email || ''}
                    className="w-full bg-slate-950/20 border border-slate-850 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-500 outline-none cursor-not-allowed"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={updateProfileMutation.isPending}
                className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold rounded-lg transition active:scale-[0.98]"
              >
                {updateProfileMutation.isPending ? 'Saving changes...' : 'Save Profile Changes'}
              </button>
            </form>
          </div>

          {/* Connected Mailboxes integration console */}
          <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-4 text-xs">
            <div className="flex items-center gap-2">
              <Link2 className="h-4.5 w-4.5 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200">Connected Gmail Accounts</h3>
            </div>

            <div className="space-y-3">
              {gmailLoading ? (
                <Loader />
              ) : gmailAccounts && gmailAccounts.length > 0 ? (
                gmailAccounts.map((acc: any) => (
                  <div key={acc.email} className="p-3 bg-slate-950/60 border border-slate-850 rounded-xl flex items-center justify-between gap-3 hover:border-slate-750 transition text-xs">
                    <div className="overflow-hidden space-y-0.5">
                      <span className="font-bold text-slate-250 block truncate">{acc.email}</span>
                      <span className="text-[9px] text-slate-500">Auto synchronization status: Active</span>
                    </div>
                    
                    <div className="flex gap-2">
                      <button
                        onClick={() => triggerSyncMutation.mutate(acc.email)}
                        className="px-2.5 py-1 text-[10px] font-semibold bg-slate-900 hover:bg-slate-850 border border-slate-800 text-slate-300 rounded-md transition"
                      >
                        Sync Now
                      </button>
                      <button
                        onClick={() => disconnectGmailMutation.mutate(acc.email)}
                        className="p-1.5 bg-red-500/5 hover:bg-red-500/10 border border-red-500/20 text-red-500 rounded-md transition"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-slate-500 text-center py-6">No Google mailboxes connected.</p>
              )}
            </div>

            {/* Ingestion authorization trigger */}
            <div className="p-4 bg-slate-950/40 border border-slate-850 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-bold text-slate-200">Connect Gmail for Threat Analysis</h4>
                  <p className="text-[11px] text-slate-400">
                    Separate from sign-in. Enables real-time AI scanning for phishing and malicious attachments.
                  </p>
                </div>
                <button
                  onClick={() => setConnectModalOpen(true)}
                  className="px-3.5 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-blue-500/20 flex items-center gap-1.5 transition active:scale-95"
                >
                  <Mail className="h-3.5 w-3.5" />
                  <span>Connect Gmail</span>
                </button>
              </div>

              {/* Developer Sandbox Code Linking Fallback */}
              <div className="pt-2 border-t border-slate-850/60">
                <span className="text-[10px] text-slate-500 block mb-1.5">Developer Sandbox / Manual Code:</span>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={googleCode}
                    onChange={(e) => setGoogleCode(e.target.value)}
                    placeholder="Paste Google Authorization Code..."
                    className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500/50"
                  />
                  <button
                    onClick={() => connectGmailMutation.mutate(googleCode)}
                    disabled={!googleCode || connectGmailMutation.isPending}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded-lg text-xs font-semibold transition disabled:opacity-50"
                  >
                    {connectGmailMutation.isPending ? 'Linking...' : 'Link Code'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: MFA & role credentials */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-5 text-xs font-medium">
          <div className="flex items-center gap-2">
            <Shield className="h-4.5 w-4.5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200">Security Clearance</h3>
          </div>

          <div className="p-3 bg-slate-950/40 border border-slate-850 rounded-xl flex items-center justify-between">
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-500 block mb-0.5">Authorization Role</span>
              <span className="font-bold text-slate-200 uppercase">{user?.role}</span>
            </div>
            <Sparkles className="h-6 w-6 text-cyan-400 animate-pulse" />
          </div>

          <hr className="border-slate-800" />

          {/* MFA Checkbox mock toggle */}
          <div className="flex items-center justify-between p-3 bg-slate-950/40 border border-slate-850 rounded-xl">
            <div className="space-y-0.5 pr-2">
              <span className="text-slate-300 block font-semibold text-xs">MFA Multi-Factor Auth</span>
              <span className="text-[9px] text-slate-500 block">Enforce authentication security</span>
            </div>
            <input
              type="checkbox"
              checked={mfaEnabled}
              onChange={() => setMfaEnabled(!mfaEnabled)}
              className="h-4 w-4 bg-slate-950 border border-slate-800 rounded text-cyan-500 focus:ring-cyan-500 focus:ring-opacity-25"
            />
          </div>
        </div>

      </div>

      {/* Gmail Authorization & Permissions Disclosure Modal */}
      {connectModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-fade-in">
          <div className="max-w-lg w-full bg-[#0d1424] border border-[#1b273d] rounded-2xl p-6 space-y-5 relative text-slate-200">
            <button
              onClick={() => setConnectModalOpen(false)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white"
            >
              <X className="h-5 w-5" />
            </button>

            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-xl bg-blue-600/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                <Mail className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Connect Gmail to GuardianMail AI</h3>
                <span className="text-[11px] text-cyan-400 font-mono">Explicit Authorization Disclosure</span>
              </div>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3 bg-blue-500/10 border border-blue-500/20 rounded-xl text-slate-300">
                <p className="font-semibold text-white mb-1">
                  Why connect Gmail?
                </p>
                <p className="text-[11px] text-slate-400">
                  {permissionsInfo?.purpose ||
                    'GuardianMail AI analyzes incoming emails in real-time to alert security operations against phishing, weaponized attachments, malicious URLs, and threat actors.'}
                </p>
              </div>

              <div>
                <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">
                  Permissions Requested:
                </h4>
                <div className="p-2.5 bg-slate-950/60 border border-slate-800 rounded-lg font-mono text-[11px] text-cyan-300 mb-2">
                  {permissionsInfo?.scope || 'https://www.googleapis.com/auth/gmail.readonly'}
                </div>
                <ul className="space-y-1.5 text-[11px] text-slate-300">
                  {(permissionsInfo?.data_accessed || [
                    'Inbound email headers (Sender, Recipient, Subject, Timestamps)',
                    'Email bodies (HTML/Text) for phishing, BEC, and impersonation detection',
                    'Message attachments for sandbox detonation and malware scanning'
                  ]).map((item: string, i: number) => (
                    <li key={i} className="flex items-start gap-2">
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0 mt-0.5" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl space-y-1 text-[11px]">
                <div className="flex items-center gap-1.5 text-slate-300 font-semibold">
                  <Lock className="h-3.5 w-3.5 text-blue-400" />
                  <span>Privacy &amp; Data Control</span>
                </div>
                <p className="text-slate-400">
                  {permissionsInfo?.user_control ||
                    'You may disconnect Gmail at any time. Revoking access immediately halts synchronization and wipes stored OAuth tokens.'}
                </p>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2 border-t border-[#1b273d]">
              <button
                type="button"
                onClick={() => setConnectModalOpen(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-xl transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleLaunchGoogleConsent}
                disabled={connecting}
                className="px-5 py-2 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-500 hover:to-blue-600 text-white text-xs font-semibold rounded-xl shadow-lg shadow-blue-600/30 flex items-center gap-2 transition disabled:opacity-50"
              >
                {connecting ? 'Redirecting to Google...' : 'Authorize Gmail Access →'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { authService } from '../services/auth';
import { gmailService } from '../services/gmail';
import { useAuth } from '../contexts/AuthContext';
import { 
  User, Mail, Shield, Trash2, Link2, Sparkles
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

  // 1. Query: Fetch connected Gmail accounts
  const { data: gmailAccounts, isLoading: gmailLoading } = useQuery({
    queryKey: ['gmail', 'accounts'],
    queryFn: () => gmailService.listAccounts()
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
      queryClient.invalidateQueries({ queryKey: ['gmail', 'accounts'] });
      alert('Gmail account connected successfully.');
    },
    onError: (err: any) => {
      alert(err?.response?.data?.detail || 'Failed to link Google mailbox. Verify API OAuth tokens.');
    }
  });

  const disconnectGmailMutation = useMutation({
    mutationFn: (email: string) => gmailService.disconnectAccount(email),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gmail', 'accounts'] });
      alert('Gmail account sync disconnected.');
    }
  });

  const triggerSyncMutation = useMutation({
    mutationFn: (email: string) => gmailService.triggerSync(email),
    onSuccess: () => {
      alert('Sync task dispatched to Celery background workers.');
    }
  });

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
              <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Connect Google Account (Developer Sandbox)</h4>
              <div className="flex gap-3">
                <input
                  type="text"
                  value={googleCode}
                  onChange={(e) => setGoogleCode(e.target.value)}
                  placeholder="Paste Google Authorization Code..."
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 outline-none placeholder:text-slate-600"
                />
                <button
                  onClick={() => connectGmailMutation.mutate(googleCode)}
                  disabled={!googleCode}
                  className="px-4 py-2 bg-slate-850 hover:bg-slate-750 text-slate-300 border border-slate-800 rounded-lg text-xs font-semibold transition"
                >
                  Link Account
                </button>
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
    </div>
  );
};

import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { authService } from '../services/auth';
import { ShieldCheck, User, Mail, Lock, FileSignature, ShieldAlert } from 'lucide-react';

export const Register: React.FC = () => {
  const navigate = useNavigate();
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('user');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password || !fullName || !username) {
      setError('Please fill in all details.');
      return;
    }
    setError(null);
    setLoading(true);

    try {
      await authService.register({
        email,
        username,
        password,
        full_name: fullName,
        role
      });
      // Redirect to login page on successful account creation
      navigate('/login');
    } catch (err: any) {
      const msg = err?.response?.data?.detail || 'Registration failed. Check password strength or username/email uniqueness.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 px-4 relative overflow-hidden font-sans">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-35" />
      <div className="absolute -top-40 -left-40 w-96 h-96 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 rounded-full bg-blue-600/10 blur-3xl" />

      <div className="relative w-full max-w-md bg-slate-900/60 backdrop-blur-xl border border-slate-800 p-8 rounded-2xl shadow-2xl space-y-5">
        
        {/* Header Branding */}
        <div className="flex flex-col items-center text-center space-y-2">
          <div className="h-11 w-11 rounded-xl bg-cyan-500/10 flex items-center justify-center border border-cyan-500/20 shadow-[0_0_15px_rgba(6,182,212,0.15)] animate-pulse">
            <ShieldCheck className="h-6 w-6 text-cyan-400" />
          </div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100">
            Create Security Account
          </h2>
          <p className="text-[11px] text-slate-500 max-w-[280px]">
            Join GuardianMail AI SOC & Forensic Analytics System
          </p>
        </div>

        {/* Error Notification */}
        {error && (
          <div className="flex items-center gap-3 p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-lg animate-shake">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Register Form */}
        <form onSubmit={handleSubmit} className="space-y-3.5">
          <div className="space-y-1">
            <label className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
              Full Name
            </label>
            <div className="relative">
              <User className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <input
                type="text"
                required
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Agent Smith"
                className="w-full bg-slate-950/60 border border-slate-800 rounded-lg pl-11 pr-4 py-2.5 text-xs text-slate-150 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 outline-none transition-all placeholder:text-slate-600"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
              Corporate Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="smith@guardianmail.ai"
                className="w-full bg-slate-950/60 border border-slate-800 rounded-lg pl-11 pr-4 py-2.5 text-xs text-slate-150 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 outline-none transition-all placeholder:text-slate-600"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
              Username
            </label>
            <div className="relative">
              <FileSignature className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="agentsmith"
                className="w-full bg-slate-950/60 border border-slate-800 rounded-lg pl-11 pr-4 py-2.5 text-xs text-slate-150 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 outline-none transition-all placeholder:text-slate-600"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
              Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-950/60 border border-slate-800 rounded-lg pl-11 pr-4 py-2.5 text-xs text-slate-150 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 outline-none transition-all placeholder:text-slate-600"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
              Security Account Clearance (Role)
            </label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-2.5 text-xs text-slate-300 focus:border-cyan-500/50 outline-none"
            >
              <option value="user">Standard User (Incident reporting & email viewer)</option>
              <option value="security_analyst">Security Analyst (L1 threat diagnostics)</option>
              <option value="soc_analyst">SOC Analyst (Forensics, incident checklists, templates)</option>
              <option value="admin">System Administrator (Full access clearance)</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold py-2.5 rounded-lg text-xs tracking-wider uppercase transition-all duration-150 active:scale-[0.98] shadow-[0_0_15px_rgba(6,182,212,0.15)] disabled:opacity-50"
          >
            {loading ? 'Registering Cleared Identity...' : 'Initialize Clearance'}
          </button>
        </form>

        <p className="text-center text-xs text-slate-500">
          Already cleared?{' '}
          <Link to="/login" className="text-cyan-400 hover:text-cyan-300 font-semibold transition">
            Sign in
          </Link>
        </p>

      </div>
    </div>
  );
};

import React, { useState } from 'react';
import { useNavigate, Link, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { ShieldCheck, Lock, Mail, Eye, EyeOff, ShieldAlert } from 'lucide-react';

export const Login: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Retrieve previous page context to redirect user after successful login
  const from = (location.state as any)?.from?.pathname || '/';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setError('Please provide both email and password.');
      return;
    }
    setError(null);
    setLoading(true);

    try {
      await login({ email, password });
      navigate(from, { replace: true });
    } catch (err: any) {
      const msg = err?.response?.data?.detail || 'Authentication failed. Please verify credentials.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 px-4 relative overflow-hidden font-sans">
      {/* Background cyber ambient grid lights */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-35" />
      <div className="absolute -top-40 -left-40 w-96 h-96 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 rounded-full bg-blue-600/10 blur-3xl" />

      {/* Main Login Card */}
      <div className="relative w-full max-w-md bg-slate-900/60 backdrop-blur-xl border border-slate-800 p-8 rounded-2xl shadow-2xl space-y-6">
        
        {/* Header Branding */}
        <div className="flex flex-col items-center text-center space-y-2">
          <div className="h-12 w-12 rounded-xl bg-cyan-500/10 flex items-center justify-center border border-cyan-500/20 shadow-[0_0_15px_rgba(6,182,212,0.15)] animate-pulse">
            <ShieldCheck className="h-6 w-6 text-cyan-400" />
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-slate-100">
            GuardianMail <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">AI</span>
          </h2>
          <p className="text-xs text-slate-500 max-w-[280px]">
            Enterprise AI-Powered Email Threat Forensics & Response Console
          </p>
        </div>

        {/* Error Notification */}
        {error && (
          <div className="flex items-center gap-3 p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-lg animate-shake">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Credentials Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1">
            <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Corporate Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@guardianmail.ai"
                className="w-full bg-slate-950/60 border border-slate-800 rounded-lg pl-11 pr-4 py-2.5 text-sm text-slate-150 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 outline-none transition-all placeholder:text-slate-600"
              />
            </div>
          </div>

          <div className="space-y-1">
            <div className="flex justify-between items-center">
              <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Password
              </label>
              <a href="#" className="text-[10px] text-cyan-500 hover:text-cyan-400 transition">
                Forgot password?
              </a>
            </div>
            <div className="relative">
              <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-950/60 border border-slate-800 rounded-lg pl-11 pr-11 py-2.5 text-sm text-slate-150 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 outline-none transition-all placeholder:text-slate-600"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-400 transition"
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold py-2.5 rounded-lg text-sm transition-all duration-150 active:scale-[0.98] shadow-[0_0_20px_rgba(6,182,212,0.15)] hover:shadow-[0_0_25px_rgba(6,182,212,0.3)] disabled:opacity-50 disabled:pointer-events-none"
          >
            {loading ? 'Authenticating...' : 'Establish Session'}
          </button>
        </form>

        <div className="relative flex py-2 items-center">
          <div className="flex-grow border-t border-slate-800"></div>
          <span className="flex-shrink mx-4 text-[10px] uppercase text-slate-600 tracking-wider font-semibold">Or authentication portals</span>
          <div className="flex-grow border-t border-slate-800"></div>
        </div>

        {/* Alternative Auth Triggers */}
        <div className="grid grid-cols-1 gap-3">
          <button
            type="button"
            className="w-full bg-slate-950/40 border border-slate-800 hover:bg-slate-800/30 text-slate-300 font-medium py-2 rounded-lg text-xs flex items-center justify-center gap-2 transition"
            onClick={() => {
              // Trigger redirect to Google Auth callback
              window.location.href = '/api/v1/auth/google/login';
            }}
          >
            <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12.24 10.285V14.4h6.887c-.648 2.41-2.519 4.114-5.136 4.114-3.568 0-6.46-2.892-6.46-6.46 0-3.567 2.892-6.459 6.46-6.459 1.54 0 2.943.543 4.053 1.44l3.153-3.153C19.167 2.012 15.938 1 12.24 1a11 11 0 0 0-11 11 11 11 0 0 0 11 11c5.96 0 10.973-4.28 10.973-11 0-.743-.075-1.44-.22-2.115H12.24Z" />
            </svg>
            Continue with Google Single Sign-On
          </button>
        </div>

        {/* Navigation Footer */}
        <p className="text-center text-xs text-slate-500">
          Need an analyst account?{' '}
          <Link to="/register" className="text-cyan-500 hover:text-cyan-400 font-semibold transition">
            Register here
          </Link>
        </p>

      </div>
    </div>
  );
};

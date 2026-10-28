import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { GoogleSignInButton } from '../components/GoogleSignInButton';
import { ForgotPasswordModal } from '../components/ForgotPasswordModal';
import { OTPInput } from '../components/OTPInput';
import { authService } from '../services/auth';
import {
  Shield,
  Mail,
  UserCheck,
  Loader2
} from 'lucide-react';

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { login, loginWithGoogle } = useAuth();

  // Active Tab matching the reference: 'gmail' | 'signin' | 'new'
  const [activeTab, setActiveTab] = useState<'gmail' | 'signin' | 'new'>('signin');

  // Sign In & Registration form states
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  // Gmail Verify (OTP Challenge) state
  const [verifyEmail, setVerifyEmail] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [maskedDest, setMaskedDest] = useState('');

  // UI status
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Forgot password modal
  const [forgotModalOpen, setForgotModalOpen] = useState(false);

  // Handle URL banner parameters (session_expired, logged_out, oauth errors)
  useEffect(() => {
    const reason = searchParams.get('reason');
    const oauthError = searchParams.get('error');

    if (reason === 'session_expired') {
      setError('Your session has expired for security. Please sign in again.');
    } else if (reason === 'logged_out') {
      setSuccessMsg('You have been securely signed out.');
    } else if (oauthError) {
      setError(`Authentication provider error: ${oauthError.replace(/_/g, ' ')}`);
    }
  }, [searchParams]);

  const extractErrorMessage = (err: any, fallbackMessage: string): string => {
    if (err?.code === 'ERR_NETWORK' || err?.message === 'Network Error' || (!err?.response && err?.request)) {
      return 'Cannot connect to MailGuard authentication server. Please ensure the backend is running on port 8000.';
    }
    const detail = err?.response?.data?.detail;
    if (detail) {
      if (typeof detail === 'string') return detail;
      if (Array.isArray(detail) && detail[0]?.msg) return detail[0].msg;
      return String(detail);
    }
    return err?.message || fallbackMessage;
  };

  // Handle standard password sign-in
  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password) {
      setError('Please enter your email and password.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      await login({ identifier: email.trim(), password });
      navigate('/');
    } catch (err: any) {
      setError(extractErrorMessage(err, 'Incorrect email or password.'));
    } finally {
      setLoading(false);
    }
  };

  // Handle new account registration
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!fullName.trim() || !email.trim() || !password) {
      setError('Please fill in all required fields.');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      await authService.register({
        full_name: fullName.trim(),
        email: email.trim(),
        password,
      });
      // Move to verification tab
      setVerifyEmail(email.trim());
      setOtpSent(true);
      setActiveTab('gmail');
      setSuccessMsg(`Verification code sent to ${email.trim()}`);
    } catch (err: any) {
      if (err?.code === 'ERR_NETWORK' || err?.message === 'Network Error' || (!err?.response && err?.request)) {
        setError('Cannot connect to MailGuard authentication server. Please ensure the backend is running on port 8000.');
      } else if (err?.response?.status === 400 && String(err?.response?.data?.detail).toLowerCase().includes('already exists')) {
        setError('This email is already registered. Please sign in or use password recovery.');
      } else {
        setError(extractErrorMessage(err, 'Registration could not be completed. Please try again.'));
      }
    } finally {
      setLoading(false);
    }
  };

  // Handle Gmail Verify code dispatch
  const handleSendGmailCode = async (e: React.FormEvent) => {
    e.preventDefault();
    const targetEmail = (verifyEmail || email).trim();
    if (!targetEmail) {
      setError('Please enter your email address to receive a verification code.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const res = await authService.sendEmailCode(targetEmail, 'login_step_up');
      setMaskedDest(res.destination);
      setOtpSent(true);
      setSuccessMsg(`6-digit code dispatched to ${res.destination}`);
    } catch (err: any) {
      setError(extractErrorMessage(err, 'Failed to send verification code. Please check server configuration.'));
    } finally {
      setLoading(false);
    }
  };

  // Handle OTP verification completion
  const handleVerifyOtpComplete = async (code: string) => {
    const targetEmail = (verifyEmail || email).trim();
    setError(null);
    setLoading(true);

    try {
      await authService.verifyEmailCode(targetEmail, code, 'login_step_up');
      navigate('/');
    } catch (err: any) {
      setError(extractErrorMessage(err, 'Invalid or expired verification code.'));
    } finally {
      setLoading(false);
    }
  };

  // Handle Google Identity Services credential
  const handleGoogleSuccess = async (credential: string) => {
    setError(null);
    setLoading(true);
    try {
      await loginWithGoogle(credential);
      navigate('/');
    } catch (err: any) {
      setError(extractErrorMessage(err, 'Google sign-in failed. Please try again.'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full bg-[#070b14] flex items-center justify-center p-4 sm:p-6 font-sans antialiased text-slate-100 selection:bg-emerald-500 selection:text-slate-950">
      {/* Centered Structured Cybersecurity Card */}
      <div className="w-full max-w-[480px] bg-[#0c1424] border border-[#16233b] rounded-2xl p-7 sm:p-8 shadow-2xl relative">
        {/* 1. Header: Shield Icon + MailGuard Title */}
        <div className="flex items-center gap-3.5 mb-6">
          <div className="h-12 w-12 rounded-xl bg-[#082224] border border-[#0d4a4d] flex items-center justify-center text-[#10b981] shadow-lg shadow-emerald-950/40 shrink-0">
            <Shield className="h-6 w-6 stroke-[1.8]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white leading-tight">MailGuard</h1>
            <p className="text-xs font-mono text-slate-400 mt-0.5 tracking-wider">Sign in to your dashboard</p>
          </div>
        </div>

        {/* 2. Official Google Identity Services Button */}
        <div className="mb-6">
          <GoogleSignInButton
            onSuccess={handleGoogleSuccess}
            onError={(err) => setError(err || 'Google sign-in was cancelled or failed.')}
            text="continue_with"
          />
        </div>

        {/* 3. Divider: OR */}
        <div className="relative my-6 flex items-center justify-center">
          <div className="w-full border-t border-[#16233b]" />
          <span className="absolute px-3 bg-[#0c1424] text-[10px] font-mono tracking-widest text-slate-500 uppercase">
            OR
          </span>
        </div>

        {/* 4. Segmented Navigation Tabs */}
        <div className="bg-[#070d18] border border-[#162238] rounded-xl p-1 grid grid-cols-3 gap-1 mb-6">
          <button
            type="button"
            onClick={() => {
              setActiveTab('gmail');
              setError(null);
            }}
            className={`py-2 text-[11px] font-mono tracking-wider font-semibold rounded-lg transition-all text-center ${
              activeTab === 'gmail'
                ? 'bg-[#131d33] text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            GMAIL VERIFY
          </button>
          <button
            type="button"
            onClick={() => {
              setActiveTab('signin');
              setError(null);
            }}
            className={`py-2 text-[11px] font-mono tracking-wider font-semibold rounded-lg transition-all text-center ${
              activeTab === 'signin'
                ? 'bg-[#131d33] text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            SIGN IN
          </button>
          <button
            type="button"
            onClick={() => {
              setActiveTab('new');
              setError(null);
            }}
            className={`py-2 text-[11px] font-mono tracking-wider font-semibold rounded-lg transition-all text-center ${
              activeTab === 'new'
                ? 'bg-[#131d33] text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            NEW ACCOUNT
          </button>
        </div>

        {/* Success Message Banner */}
        {successMsg && (
          <div className="mb-4 p-3 rounded-xl border border-emerald-500/50 bg-emerald-950/20 text-emerald-400 font-mono text-xs flex items-center justify-between">
            <span>{successMsg}</span>
            <button onClick={() => setSuccessMsg(null)} className="text-slate-400 hover:text-white font-bold ml-2">×</button>
          </div>
        )}

        {/* Error Alert Box (matching Image 2 design) */}
        {error && (
          <div className="mb-4 p-3 rounded-xl border border-red-500/70 bg-red-950/20 text-red-400 font-mono text-xs flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => setError(null)} className="text-slate-400 hover:text-white font-bold ml-2">×</button>
          </div>
        )}

        {/* 5. TAB: SIGN IN (Matches Image 2 exactly) */}
        {activeTab === 'signin' && (
          <form onSubmit={handleSignIn} className="space-y-4">
            <div>
              <label htmlFor="login-email" className="block text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 font-semibold">
                EMAIL ADDRESS
              </label>
              <input
                id="login-email"
                type="text"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="mubashirsk381@gmail.com"
                required
                autoComplete="username"
                className="w-full px-4 py-3 bg-[#080d19] border border-[#162238] rounded-xl text-sm font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/60 transition"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <label htmlFor="login-password" className="block text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                  PASSWORD (MIN 8 CHARS)
                </label>
                <button
                  type="button"
                  onClick={() => setForgotModalOpen(true)}
                  className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono transition-colors"
                >
                  Forgot password?
                </button>
              </div>
              <input
                id="login-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                autoComplete="current-password"
                className="w-full px-4 py-3 bg-[#080d19] border border-[#162238] rounded-xl text-sm font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/60 transition"
              />
            </div>

            {/* Primary Sign In Button (Vibrant Emerald matching Image 2) */}
            <button
              id="signin-submit-btn"
              data-testid="signin-submit-btn"
              type="submit"
              disabled={loading}
              className="w-full mt-5 py-3.5 px-4 bg-[#10b981] hover:bg-[#059669] active:bg-[#047857] text-slate-950 font-bold text-sm rounded-xl flex items-center justify-center gap-2.5 shadow-lg shadow-emerald-500/20 transition cursor-pointer disabled:opacity-50"
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin text-slate-950" />
              ) : (
                <>
                  <Mail className="h-4 w-4 stroke-[2.2] text-slate-950" />
                  <span>Sign In</span>
                </>
              )}
            </button>
          </form>
        )}

        {/* 6. TAB: GMAIL VERIFY (Multi-channel OTP Verification) */}
        {activeTab === 'gmail' && (
          <div className="space-y-4">
            {!otpSent ? (
              <form onSubmit={handleSendGmailCode} className="space-y-4">
                <div>
                  <label htmlFor="verify-email" className="block text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 font-semibold">
                    EMAIL OR PHONE FOR VERIFICATION
                  </label>
                  <input
                    id="verify-email"
                    type="text"
                    value={verifyEmail || email}
                    onChange={(e) => setVerifyEmail(e.target.value)}
                    placeholder="analyst@guardianmail.ai"
                    required
                    className="w-full px-4 py-3 bg-[#080d19] border border-[#162238] rounded-xl text-sm font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/60 transition"
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-5 py-3.5 px-4 bg-[#10b981] hover:bg-[#059669] active:bg-[#047857] text-slate-950 font-bold text-sm rounded-xl flex items-center justify-center gap-2.5 shadow-lg shadow-emerald-500/20 transition cursor-pointer disabled:opacity-50"
                >
                  {loading ? (
                    <Loader2 className="h-4 w-4 animate-spin text-slate-950" />
                  ) : (
                    <>
                      <Mail className="h-4 w-4 stroke-[2.2] text-slate-950" />
                      <span>Send Verification Code</span>
                    </>
                  )}
                </button>
              </form>
            ) : (
              <div className="space-y-4 pt-1">
                <OTPInput
                  recipientText={maskedDest || verifyEmail || email}
                  onComplete={handleVerifyOtpComplete}
                  isLoading={loading}
                  error={error}
                  onResend={async () => {
                    const target = (verifyEmail || email).trim();
                    await authService.sendEmailCode(target, 'login_step_up');
                  }}
                />
                <div className="text-center pt-2">
                  <button
                    type="button"
                    onClick={() => setOtpSent(false)}
                    className="text-xs text-slate-400 hover:text-emerald-400 transition-colors font-mono"
                  >
                    ← Change destination address
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* 7. TAB: NEW ACCOUNT */}
        {activeTab === 'new' && (
          <form onSubmit={handleRegister} className="space-y-4">
            <div>
              <label htmlFor="reg-name" className="block text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 font-semibold">
                FULL NAME
              </label>
              <input
                id="reg-name"
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Jane Doe"
                required
                className="w-full px-4 py-3 bg-[#080d19] border border-[#162238] rounded-xl text-sm font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/60 transition"
              />
            </div>

            <div>
              <label htmlFor="reg-email" className="block text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 font-semibold">
                WORK EMAIL ADDRESS
              </label>
              <input
                id="reg-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="jane.doe@enterprise.com"
                required
                className="w-full px-4 py-3 bg-[#080d19] border border-[#162238] rounded-xl text-sm font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/60 transition"
              />
            </div>

            <div>
              <label htmlFor="reg-password" className="block text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 font-semibold">
                PASSWORD (MIN 8 CHARS)
              </label>
              <input
                id="reg-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                className="w-full px-4 py-3 bg-[#080d19] border border-[#162238] rounded-xl text-sm font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/60 transition"
              />
            </div>

            <div>
              <label htmlFor="reg-confirm-password" className="block text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 font-semibold">
                CONFIRM PASSWORD
              </label>
              <input
                id="reg-confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                className="w-full px-4 py-3 bg-[#080d19] border border-[#162238] rounded-xl text-sm font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/60 transition"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-5 py-3.5 px-4 bg-[#10b981] hover:bg-[#059669] active:bg-[#047857] text-slate-950 font-bold text-sm rounded-xl flex items-center justify-center gap-2.5 shadow-lg shadow-emerald-500/20 transition cursor-pointer disabled:opacity-50"
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin text-slate-950" />
              ) : (
                <>
                  <UserCheck className="h-4 w-4 stroke-[2.2] text-slate-950" />
                  <span>Create Account & Verify</span>
                </>
              )}
            </button>
          </form>
        )}

        {/* 8. Card Footer Note (Matches Image 2 exactly) */}
        <p className="mt-6 text-xs text-slate-500 leading-relaxed font-sans">
          Your account is stored securely in MailGuard Cloud. Mail scan history is cached on this device for fast access and is wiped when you sign out.
        </p>
      </div>

      {/* Forgot Password Modal */}
      <ForgotPasswordModal
        isOpen={forgotModalOpen}
        onClose={() => setForgotModalOpen(false)}
        initialEmail={email}
      />
    </div>
  );
};

import React, { useState } from 'react';
import { Mail, KeyRound, CheckCircle2, ArrowLeft, X, Loader2 } from 'lucide-react';
import { authService } from '../services/auth';
import { PasswordField } from './PasswordField';
import { AuthErrorMessage } from './AuthErrorMessage';
import { PasswordStrength } from './PasswordStrength';

interface ForgotPasswordModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialEmail?: string;
  onResetSuccess?: () => void;
}

export const ForgotPasswordModal: React.FC<ForgotPasswordModalProps> = ({
  isOpen,
  onClose,
  initialEmail = '',
  onResetSuccess
}) => {
  const [step, setStep] = useState<'request' | 'verify' | 'done'>('request');
  const [email, setEmail] = useState(initialEmail);
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleRequestCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) {
      setError('Please enter your account email address.');
      return;
    }
    setError(null);
    setLoading(true);

    try {
      const res = await authService.forgotPassword(email.trim());
      setSuccessMsg(res.message || 'If an account exists, a 6-digit verification code has been sent.');
      setStep('verify');
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to dispatch password recovery code. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!code.trim() || code.trim().length < 4) {
      setError('Please enter the 6-digit verification code.');
      return;
    }
    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const res = await authService.resetPassword({
        email: email.trim(),
        code: code.trim(),
        new_password: newPassword
      });
      setSuccessMsg(res.message || 'Password successfully reset.');
      setStep('done');
      if (onResetSuccess) {
        onResetSuccess();
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Invalid or expired verification code.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-md bg-[#091124] border border-[#1b2b4d] rounded-2xl p-6 sm:p-8 shadow-2xl shadow-blue-950/40 text-slate-100">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 text-slate-400 hover:text-white transition-colors p-1"
          aria-label="Close dialog"
        >
          <X className="h-5 w-5" />
        </button>

        {/* Step 1: Request Code */}
        {step === 'request' && (
          <div>
            <div className="h-10 w-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400 mb-4">
              <KeyRound className="h-5 w-5" />
            </div>
            <h3 className="text-xl font-bold text-white tracking-tight">Reset your password</h3>
            <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
              Enter your email address and we will dispatch a one-time cryptographic identity verification code.
            </p>

            <form onSubmit={handleRequestCode} className="mt-6 space-y-4">
              <AuthErrorMessage message={error} type="error" onDismiss={() => setError(null)} />

              <div className="space-y-1.5">
                <label htmlFor="recovery-email" className="block text-xs font-semibold text-slate-300">
                  Email Address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <Mail className="h-4 w-4" />
                  </div>
                  <input
                    id="recovery-email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@guardianmail.ai"
                    required
                    autoFocus
                    className="w-full pl-10 pr-4 py-2.5 bg-[#050a17] border border-[#1b2b4d] rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-all"
                  />
                </div>
              </div>

              <div className="pt-2 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-blue-600/20 disabled:opacity-50 transition-all flex items-center gap-2"
                >
                  {loading && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                  <span>{loading ? 'Sending Code...' : 'Send Verification Code'}</span>
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Step 2: Enter OTP & New Password */}
        {step === 'verify' && (
          <div>
            <div className="flex items-center gap-2 mb-4">
              <button
                type="button"
                onClick={() => setStep('request')}
                className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1 transition-colors"
              >
                <ArrowLeft className="h-3.5 w-3.5" /> Back
              </button>
            </div>

            <h3 className="text-xl font-bold text-white tracking-tight">Enter Verification Code</h3>
            <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
              We sent a 6-digit code to <span className="text-cyan-300 font-mono">{email}</span>.
            </p>

            <form onSubmit={handleResetPassword} className="mt-6 space-y-4">
              <AuthErrorMessage message={error} type="error" onDismiss={() => setError(null)} />
              {successMsg && <AuthErrorMessage message={successMsg} type="success" onDismiss={() => setSuccessMsg(null)} />}

              <div className="space-y-1.5">
                <label htmlFor="reset-code" className="block text-xs font-semibold text-slate-300">
                  6-Digit Verification Code
                </label>
                <input
                  id="reset-code"
                  type="text"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="123456"
                  required
                  autoFocus
                  className="w-full text-center tracking-[0.3em] font-mono text-lg py-2.5 bg-[#050a17] border border-[#1b2b4d] rounded-lg text-cyan-300 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500"
                />
              </div>

              <div className="space-y-1">
                <PasswordField
                  id="new-password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  label="New Password"
                  placeholder="Enter strong password (min 8 chars)"
                  autoComplete="new-password"
                />
                <PasswordStrength password={newPassword} />
              </div>

              <PasswordField
                id="confirm-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                label="Confirm New Password"
                placeholder="Re-enter new password"
                autoComplete="new-password"
              />

              <div className="pt-2 flex items-center justify-end gap-3">
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-blue-600/20 disabled:opacity-50 transition-all flex items-center justify-center gap-2"
                >
                  {loading && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                  <span>{loading ? 'Resetting Password...' : 'Reset Password & Revoke Sessions'}</span>
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Step 3: Success Screen */}
        {step === 'done' && (
          <div className="text-center py-4 space-y-4">
            <div className="h-14 w-14 rounded-full bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 mx-auto flex items-center justify-center">
              <CheckCircle2 className="h-8 w-8" />
            </div>
            <h3 className="text-xl font-bold text-white">Password Successfully Updated</h3>
            <p className="text-xs text-slate-400 max-w-sm mx-auto leading-relaxed">
              Your password has been securely reset and previous active sessions have been revoked. You can now sign in with your new credentials.
            </p>
            <div className="pt-4">
              <button
                type="button"
                onClick={onClose}
                className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition-all shadow-lg shadow-blue-600/20"
              >
                Sign In With New Password
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

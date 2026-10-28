import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { authService } from '../services/auth';
import { GoogleSignInButton } from '../components/GoogleSignInButton';
import { AuthLayout } from '../components/AuthLayout';
import { PasswordField } from '../components/PasswordField';
import { PasswordStrength } from '../components/PasswordStrength';
import { AuthErrorMessage } from '../components/AuthErrorMessage';
import { OTPInput } from '../components/OTPInput';
import {
  User,
  Mail,
  Phone,
  CheckCircle2,
  ArrowRight,
  ArrowLeft,
  Loader2
} from 'lucide-react';

const COUNTRY_CODES = [
  { code: '+1', country: 'US/CA', flag: '🇺🇸' },
  { code: '+44', country: 'UK', flag: '🇬🇧' },
  { code: '+91', country: 'IN', flag: '🇮🇳' },
  { code: '+49', country: 'DE', flag: '🇩🇪' },
  { code: '+33', country: 'FR', flag: '🇫🇷' },
  { code: '+61', country: 'AU', flag: '🇦🇺' },
  { code: '+81', country: 'JP', flag: '🇯🇵' },
  { code: '+41', country: 'CH', flag: '🇨🇭' }
];

export const Register: React.FC = () => {
  const navigate = useNavigate();
  const { login, loginWithGoogle } = useAuth();

  // Step 1: Info -> Step 2: Verification Challenge -> Step 3: Account Active
  const [step, setStep] = useState<1 | 2 | 3>(1);

  // Form Fields
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [countryCode, setCountryCode] = useState('+1');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [agreedToTerms, setAgreedToTerms] = useState(false);

  // UI state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successInfo, setSuccessInfo] = useState<string | null>(null);

  const handleStep1Submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!firstName.trim() || !lastName.trim() || !email.trim() || !password) {
      setError('Please complete all required fields.');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    if (!agreedToTerms) {
      setError('Please accept the Terms of Service & Privacy Policy to proceed.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const fullName = `${firstName.trim()} ${lastName.trim()}`;
      const payload: any = {
        full_name: fullName,
        email: email.trim(),
        password
      };
      if (phoneNumber.trim()) {
        payload.phone_number = `${countryCode}${phoneNumber.replace(/\D/g, '')}`;
      }

      await authService.register(payload);
      setSuccessInfo(`Verification code dispatched to ${email.trim()}`);
      setStep(2);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Registration failed. This email may already be registered.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (code: string) => {
    setError(null);
    setLoading(true);

    try {
      // Real backend challenge verification
      await authService.verifyEmailCode(email.trim(), code, 'registration');
      // Sign in user
      await login({ email: email.trim(), password });
      setStep(3);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Invalid or expired verification code.');
    } finally {
      setLoading(false);
    }
  };

  const handleResendOtp = async () => {
    try {
      await authService.sendEmailCode(email.trim(), 'registration');
      setSuccessInfo(`A fresh 6-digit code has been dispatched to ${email.trim()}`);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to resend code. Please wait for cooldown.');
    }
  };

  const handleGoogleSuccess = async (credential: string) => {
    setError(null);
    setLoading(true);
    try {
      await loginWithGoogle(credential);
      navigate('/');
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Google sign-in failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout
      title={step === 1 ? 'Create your enterprise account' : step === 2 ? 'Verify your identity' : 'Account activated'}
      subtitle={
        step === 1
          ? 'Deploy autonomous cybersecurity defense for your mailboxes'
          : step === 2
          ? 'Enter the 6-digit one-time code sent to your email'
          : 'Your account is verified and protected'
      }
    >
      <div className="space-y-5">
        <AuthErrorMessage message={error} type="error" onDismiss={() => setError(null)} />
        {successInfo && <AuthErrorMessage message={successInfo} type="success" onDismiss={() => setSuccessInfo(null)} />}

        {/* STEP 1: Registration Form */}
        {step === 1 && (
          <div className="space-y-5">
            {/* Google Fast Sign-Up */}
            <div>
              <GoogleSignInButton
                onSuccess={handleGoogleSuccess}
                onError={(err) => setError(err || 'Google registration was cancelled or failed.')}
                text="signup_with"
              />

              <div className="relative my-5">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-[#1b2b4d]" />
                </div>
                <div className="relative flex justify-center text-[11px] uppercase tracking-wider font-mono">
                  <span className="bg-[#040711] px-3 text-slate-500">or register with email</span>
                </div>
              </div>
            </div>

            <form onSubmit={handleStep1Submit} className="space-y-4">
              {/* Name Fields */}
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label htmlFor="reg-first" className="block text-xs font-semibold text-slate-300">
                    First Name
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                      <User className="h-4 w-4" />
                    </div>
                    <input
                      id="reg-first"
                      type="text"
                      value={firstName}
                      onChange={(e) => setFirstName(e.target.value)}
                      placeholder="Jane"
                      required
                      className="w-full pl-9 pr-3 py-2 bg-[#091124] border border-[#1b2b4d] rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500"
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label htmlFor="reg-last" className="block text-xs font-semibold text-slate-300">
                    Last Name
                  </label>
                  <input
                    id="reg-last"
                    type="text"
                    value={lastName}
                    onChange={(e) => setLastName(e.target.value)}
                    placeholder="Doe"
                    required
                    className="w-full px-3 py-2 bg-[#091124] border border-[#1b2b4d] rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500"
                  />
                </div>
              </div>

              {/* Email Address */}
              <div className="space-y-1.5">
                <label htmlFor="reg-email" className="block text-xs font-semibold text-slate-300">
                  Work Email Address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <Mail className="h-4 w-4" />
                  </div>
                  <input
                    id="reg-email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="jane.doe@enterprise.com"
                    required
                    autoComplete="email"
                    className="w-full pl-10 pr-4 py-2 bg-[#091124] border border-[#1b2b4d] rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500"
                  />
                </div>
              </div>

              {/* Optional Phone Number */}
              <div className="space-y-1.5">
                <label htmlFor="reg-phone" className="block text-xs font-semibold text-slate-300">
                  Mobile Number <span className="text-slate-500 font-normal">(Optional for SMS verification)</span>
                </label>
                <div className="flex gap-2">
                  <select
                    value={countryCode}
                    onChange={(e) => setCountryCode(e.target.value)}
                    aria-label="Country calling code"
                    className="w-24 px-2 py-2 bg-[#091124] border border-[#1b2b4d] rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500"
                  >
                    {COUNTRY_CODES.map((c) => (
                      <option key={c.code} value={c.code} className="bg-[#091124] text-slate-200">
                        {c.flag} {c.code}
                      </option>
                    ))}
                  </select>
                  <div className="relative flex-1">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                      <Phone className="h-4 w-4" />
                    </div>
                    <input
                      id="reg-phone"
                      type="tel"
                      value={phoneNumber}
                      onChange={(e) => setPhoneNumber(e.target.value)}
                      placeholder="(555) 019-2834"
                      autoComplete="tel"
                      className="w-full pl-9 pr-3 py-2 bg-[#091124] border border-[#1b2b4d] rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 font-mono"
                    />
                  </div>
                </div>
              </div>

              {/* Password & Strength */}
              <div className="space-y-1">
                <PasswordField
                  id="reg-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  label="Password"
                  placeholder="Create a strong password (min 8 chars)"
                  autoComplete="new-password"
                />
                <PasswordStrength password={password} />
              </div>

              {/* Confirm Password */}
              <PasswordField
                id="reg-confirm-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                label="Confirm Password"
                placeholder="Re-enter password"
                autoComplete="new-password"
              />

              {/* Terms Checkbox */}
              <div className="pt-1">
                <label className="flex items-start gap-2.5 text-xs text-slate-400 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={agreedToTerms}
                    onChange={(e) => setAgreedToTerms(e.target.checked)}
                    required
                    className="mt-0.5 rounded border-[#1b2b4d] bg-[#091124] text-blue-600 focus:ring-blue-500/30"
                  />
                  <span>
                    I agree to the GuardianMail AI Master Subscription Agreement, Acceptable Use Policy, and Privacy Policy.
                  </span>
                </label>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={loading}
                className="w-full mt-2 py-2.5 px-4 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-500 hover:to-blue-600 text-white font-semibold text-xs rounded-lg shadow-lg shadow-blue-600/25 transition-all disabled:opacity-50 flex items-center justify-center gap-2 cursor-pointer"
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <>
                    <span>Create Account & Send Verification Code</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                  </>
                )}
              </button>
            </form>
          </div>
        )}

        {/* STEP 2: Multi-channel Identity Verification OTP Challenge */}
        {step === 2 && (
          <div className="space-y-4 pt-2">
            <OTPInput
              recipientText={email.trim()}
              onComplete={handleVerifyOtp}
              isLoading={loading}
              error={error}
              onResend={handleResendOtp}
            />

            <div className="text-center pt-2">
              <button
                type="button"
                onClick={() => {
                  setStep(1);
                  setError(null);
                }}
                className="text-xs text-slate-400 hover:text-cyan-400 flex items-center justify-center gap-1 mx-auto transition-colors"
              >
                <ArrowLeft className="h-3.5 w-3.5" /> Change registration details
              </button>
            </div>
          </div>
        )}

        {/* STEP 3: Verified & Activated State */}
        {step === 3 && (
          <div className="text-center py-6 space-y-5">
            <div className="h-16 w-16 rounded-full bg-emerald-500/20 border-2 border-emerald-500/50 text-emerald-400 mx-auto flex items-center justify-center shadow-xl shadow-emerald-500/20">
              <CheckCircle2 className="h-9 w-9" />
            </div>

            <div>
              <h3 className="text-xl font-bold text-white tracking-tight">Identity Verified Successfully</h3>
              <p className="text-xs text-slate-400 max-w-sm mx-auto mt-2 leading-relaxed">
                Your enterprise account has been created and verified. You have full access to GuardianMail AI threat intelligence and mailbox protection.
              </p>
            </div>

            <div className="pt-2">
              <button
                type="button"
                onClick={() => navigate('/')}
                className="w-full py-2.5 px-4 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-500 hover:to-blue-600 text-white font-semibold text-xs rounded-lg shadow-lg shadow-blue-600/25 transition-all flex items-center justify-center gap-2 cursor-pointer"
              >
                <span>Launch Security Dashboard</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* Footer Link */}
        {step === 1 && (
          <div className="text-center pt-4 text-xs text-slate-400">
            <span>Already have an account? </span>
            <Link to="/login" className="text-cyan-400 hover:text-cyan-300 font-semibold hover:underline">
              Sign in
            </Link>
          </div>
        )}
      </div>
    </AuthLayout>
  );
};

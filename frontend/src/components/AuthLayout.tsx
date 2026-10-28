import React from 'react';
import { Shield, Mail, CheckCircle2, Lock } from 'lucide-react';

interface AuthLayoutProps {
  children: React.ReactNode;
  title?: string;
  subtitle?: string;
}

export const AuthLayout: React.FC<AuthLayoutProps> = ({
  children,
  title = "Sign in to GuardianMail AI",
  subtitle = "Enterprise Email Threat Defense & Identity Protection"
}) => {
  return (
    <div className="min-h-screen flex bg-[#040711] text-slate-100 font-sans antialiased selection:bg-blue-600 selection:text-white">
      {/* Left / Primary Security Showcase Panel (Hidden on mobile) */}
      <div className="hidden lg:flex lg:w-1/2 relative flex-col justify-between p-12 bg-gradient-to-br from-[#060b19] via-[#09132c] to-[#030611] border-r border-[#15223c] overflow-hidden">
        {/* Ambient atmospheric glows */}
        <div className="absolute -top-28 -left-28 w-96 h-96 bg-blue-600/15 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-cyan-500/10 rounded-full blur-[140px] pointer-events-none" />

        {/* Brand Header */}
        <div className="flex items-center gap-3 relative z-10">
          <div className="h-10 w-10 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-lg shadow-blue-600/30">
            <Shield className="h-6 w-6 fill-white stroke-blue-600" />
          </div>
          <div>
            <span className="font-bold text-base text-white tracking-tight block">
              GuardianMail <span className="text-[#38bdf8]">AI</span>
            </span>
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
              SECURE EMAIL DEFENSE
            </span>
          </div>
        </div>

        {/* Center Cybersecurity Visual & Messaging */}
        <div className="relative z-10 flex flex-col items-center justify-center my-auto py-8 text-center max-w-md mx-auto">
          {/* Abstract Cyber Shield Visual */}
          <div className="relative w-64 h-64 flex items-center justify-center mb-8">
            <div className="absolute inset-0 rounded-full border border-blue-500/20 animate-pulse" />
            <div className="absolute inset-4 rounded-full border border-cyan-500/25" />
            <div className="absolute inset-10 rounded-full border border-blue-400/15" />

            {/* Glowing Center Shield Badge */}
            <div className="relative h-36 w-32 rounded-2xl bg-gradient-to-b from-[#1e40af] to-[#0b1329] border-2 border-cyan-400/50 flex flex-col items-center justify-center shadow-2xl shadow-cyan-500/20">
              <Mail className="h-12 w-12 text-cyan-300 drop-shadow-[0_0_12px_rgba(6,182,212,0.6)]" />
              <span className="text-[9px] font-mono uppercase tracking-widest text-cyan-300 font-bold mt-2">
                ACTIVE DEFENSE
              </span>
            </div>
          </div>

          <h1 className="text-2xl font-bold tracking-tight text-white mb-3">
            Your inbox. Better protected.
          </h1>
          <p className="text-sm text-slate-400 leading-relaxed mb-6">
            Real-time phishing interception, behavioral detonation sandbox, and automated identity threat defense.
          </p>

          {/* Security Status Badges */}
          <div className="grid grid-cols-2 gap-3 w-full text-left">
            <div className="bg-[#091530]/80 border border-[#1b2b4d] rounded-lg p-3">
              <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold mb-1">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                <span>OIDC Verified</span>
              </div>
              <p className="text-[11px] text-slate-400">Cryptographic token validation</p>
            </div>
            <div className="bg-[#091530]/80 border border-[#1b2b4d] rounded-lg p-3">
              <div className="flex items-center gap-2 text-blue-400 text-xs font-semibold mb-1">
                <Lock className="h-4 w-4 shrink-0" />
                <span>Zero-Trust MFA</span>
              </div>
              <p className="text-[11px] text-slate-400">Multi-channel OTP challenge</p>
            </div>
          </div>
        </div>

        {/* Concise Privacy Statement */}
        <div className="relative z-10 text-xs text-slate-500 border-t border-[#132039] pt-4 flex flex-col sm:flex-row justify-between items-center gap-2">
          <span>Your account is protected with secure authentication and verified access.</span>
          <span className="font-mono text-[11px] text-slate-600">v2.4.0-SEC</span>
        </div>
      </div>

      {/* Right / Authentication Panel */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-4 sm:p-8 lg:p-12 overflow-y-auto">
        <div className="w-full max-w-md">
          {/* Mobile brand header */}
          <div className="lg:hidden flex items-center justify-center gap-3 mb-8">
            <div className="h-10 w-10 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-lg shadow-blue-600/30">
              <Shield className="h-6 w-6 fill-white stroke-blue-600" />
            </div>
            <div>
              <span className="font-bold text-base text-white tracking-tight block">
                GuardianMail <span className="text-[#38bdf8]">AI</span>
              </span>
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                SECURE EMAIL DEFENSE
              </span>
            </div>
          </div>

          {/* Form Header */}
          <div className="mb-6 text-center lg:text-left">
            <h2 className="text-2xl font-bold tracking-tight text-white">{title}</h2>
            <p className="text-xs text-slate-400 mt-1">{subtitle}</p>
          </div>

          {/* Form Content */}
          {children}

          {/* Footer Terms & Privacy */}
          <div className="mt-8 pt-6 border-t border-[#18233c] text-center text-xs text-slate-500">
            <span>By continuing, you agree to our </span>
            <a href="#" className="text-slate-400 hover:text-cyan-400 underline transition-colors">
              Terms of Service
            </a>
            <span> and </span>
            <a href="#" className="text-slate-400 hover:text-cyan-400 underline transition-colors">
              Privacy Policy
            </a>
            .
          </div>
        </div>
      </div>
    </div>
  );
};

import React, { useState, useEffect } from 'react';
import { Smartphone, QrCode, CheckCircle2, X, Loader2, Copy, Check, ExternalLink } from 'lucide-react';
import { authService } from '../services/auth';

interface TOTPModalProps {
  isOpen: boolean;
  onClose: () => void;
  email: string;
  onSuccess?: () => void;
}

export const TOTPModal: React.FC<TOTPModalProps> = ({
  isOpen,
  onClose,
  email,
  onSuccess
}) => {
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [secret, setSecret] = useState('');
  const [qrBase64, setQrBase64] = useState('');
  const [code, setCode] = useState('');
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (isOpen && email) {
      loadSetupData();
    }
  }, [isOpen, email]);

  const loadSetupData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await authService.getTOTPSetup(email);
      setSecret(data.secret);
      setQrBase64(data.qr_code_base64);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to initialize authenticator setup.');
    } finally {
      setLoading(false);
    }
  };

  const handleCopySecret = () => {
    if (secret) {
      navigator.clipboard.writeText(secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleVerifyAndEnable = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!code || code.trim().length < 6) {
      setError('Please enter the 6-digit code displayed in your authenticator app.');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      await authService.enableTOTP({
        email: email.trim(),
        secret,
        code: code.trim()
      });
      setSuccess(true);
      setTimeout(() => {
        onSuccess?.();
        onClose();
      }, 1500);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Invalid verification code. Please check your authenticator app.');
    } finally {
      setSubmitting(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-md bg-[#0c1424] border border-[#16233b] rounded-2xl p-6 sm:p-7 shadow-2xl relative text-slate-100">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white transition-colors p-1 rounded-lg hover:bg-[#131d33]"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center gap-3 mb-5">
          <div className="w-10 h-10 rounded-xl bg-emerald-950/60 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
            <Smartphone className="w-5 h-5 stroke-[2]" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white tracking-tight">Authenticator Setup</h2>
            <p className="text-xs text-slate-400 font-mono">Microsoft or Google Authenticator</p>
          </div>
        </div>

        {loading ? (
          <div className="flex flex-col items-center justify-center py-12 gap-3">
            <Loader2 className="w-8 h-8 animate-spin text-emerald-400" />
            <p className="text-xs font-mono text-slate-400">Generating secure pairing key...</p>
          </div>
        ) : success ? (
          <div className="flex flex-col items-center justify-center py-10 gap-3 text-center">
            <CheckCircle2 className="w-12 h-12 text-emerald-400 animate-bounce" />
            <h3 className="text-base font-bold text-white">Authenticator Paired!</h3>
            <p className="text-xs font-mono text-slate-300">
              Your Microsoft Authenticator app is now linked. You can sign in using 6-digit codes anytime.
            </p>
          </div>
        ) : (
          <form onSubmit={handleVerifyAndEnable} className="space-y-4">
            {/* Step 1: Scan QR */}
            <div className="bg-[#070d18] border border-[#162238] rounded-xl p-4 flex flex-col items-center text-center">
              <span className="text-[11px] font-mono text-slate-400 mb-2 uppercase tracking-wider font-semibold">
                1. Scan QR with Microsoft Authenticator
              </span>
              {qrBase64 ? (
                <div className="bg-white p-2.5 rounded-xl shadow-md my-1">
                  <img src={qrBase64} alt="Authenticator QR Code" className="w-44 h-44 object-contain" />
                </div>
              ) : (
                <div className="w-44 h-44 bg-slate-900 rounded-xl flex items-center justify-center">
                  <QrCode className="w-12 h-12 text-slate-600" />
                </div>
              )}

              {/* Secret key fallback */}
              <div className="mt-3 w-full">
                <span className="text-[10px] font-mono text-slate-500 block mb-1">
                  Or enter manual secret key:
                </span>
                <div className="flex items-center justify-between bg-[#0b1322] border border-[#1a2942] rounded-lg px-3 py-1.5 text-xs font-mono">
                  <span className="text-emerald-400 tracking-wider truncate select-all">{secret}</span>
                  <button
                    type="button"
                    onClick={handleCopySecret}
                    className="ml-2 text-slate-400 hover:text-white p-1"
                    title="Copy secret"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>

            {/* App Store Links */}
            <div className="flex items-center justify-between text-[11px] font-mono px-1">
              <a
                href="https://apps.apple.com/in/app/microsoft-authenticator/id983156458"
                target="_blank"
                rel="noreferrer"
                className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
              >
                <span>Microsoft Authenticator</span>
                <ExternalLink className="w-3 h-3" />
              </a>
              <span className="text-slate-600">•</span>
              <span className="text-slate-400">Google Authenticator</span>
            </div>

            {/* Step 2: Enter 6-digit code */}
            <div>
              <label htmlFor="totp-code" className="block text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 font-semibold">
                2. Enter 6-digit code from App
              </label>
              <input
                id="totp-code"
                type="text"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                placeholder="123456"
                required
                className="w-full text-center tracking-[0.4em] text-lg font-mono px-4 py-2.5 bg-[#080d19] border border-[#162238] rounded-xl text-emerald-400 placeholder-slate-700 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/60 transition"
              />
            </div>

            {/* Error Message */}
            {error && (
              <div className="p-2.5 rounded-lg border border-red-500/60 bg-red-950/20 text-red-400 font-mono text-xs">
                {error}
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={submitting || code.length < 6}
              className="w-full py-3 px-4 bg-[#10b981] hover:bg-[#059669] active:bg-[#047857] text-slate-950 font-bold text-sm rounded-xl flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/20 transition cursor-pointer disabled:opacity-50"
            >
              {submitting ? (
                <Loader2 className="w-4 h-4 animate-spin text-slate-950" />
              ) : (
                <span>Activate Authenticator</span>
              )}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};

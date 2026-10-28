import React, { useRef, useState, useEffect } from 'react';
import { RotateCw, ShieldAlert } from 'lucide-react';

interface OTPInputProps {
  length?: number;
  onComplete: (code: string) => void;
  onResend?: () => Promise<void>;
  isLoading?: boolean;
  error?: string | null;
  recipientText?: string;
}

export const OTPInput: React.FC<OTPInputProps> = ({
  length = 6,
  onComplete,
  onResend,
  isLoading = false,
  error = null,
  recipientText,
}) => {
  const [digits, setDigits] = useState<string[]>(Array(length).fill(''));
  const [countdown, setCountdown] = useState(60);
  const [resending, setResending] = useState(false);
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    if (countdown > 0) {
      const timer = setTimeout(() => setCountdown((c) => c - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [countdown]);

  const handleChange = (index: number, value: string) => {
    const cleanValue = value.replace(/\D/g, '');
    if (!cleanValue) {
      const newDigits = [...digits];
      newDigits[index] = '';
      setDigits(newDigits);
      return;
    }

    const digit = cleanValue[cleanValue.length - 1];
    const newDigits = [...digits];
    newDigits[index] = digit;
    setDigits(newDigits);

    // Auto-focus next input
    if (index < length - 1) {
      inputRefs.current[index + 1]?.focus();
    }

    // Check completion
    if (newDigits.every((d) => d !== '') && newDigits.length === length) {
      onComplete(newDigits.join(''));
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !digits[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, length);
    if (!pastedData) return;

    const newDigits = [...digits];
    for (let i = 0; i < pastedData.length; i++) {
      newDigits[i] = pastedData[i];
    }
    setDigits(newDigits);

    const focusIndex = Math.min(pastedData.length, length - 1);
    inputRefs.current[focusIndex]?.focus();

    if (pastedData.length === length) {
      onComplete(pastedData);
    }
  };

  const handleResendClick = async () => {
    if (countdown > 0 || !onResend || resending) return;
    setResending(true);
    try {
      await onResend();
      setCountdown(60);
      setDigits(Array(length).fill(''));
      inputRefs.current[0]?.focus();
    } finally {
      setResending(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="text-center space-y-1">
        <h3 className="text-lg font-bold text-slate-100">Two-Factor Authentication</h3>
        <p className="text-xs text-slate-400">
          Enter the 6-digit security verification code sent to{' '}
          <strong className="text-cyan-400 font-mono">{recipientText || 'your registered device'}</strong>.
        </p>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="flex items-center gap-2 p-3 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs rounded-xl">
          <ShieldAlert className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* 6 Digit Split Input Container */}
      <div className="flex justify-center gap-2.5 sm:gap-3">
        {digits.map((digit, index) => (
          <input
            key={index}
            ref={(el) => { inputRefs.current[index] = el; }}
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={1}
            value={digit}
            onChange={(e) => handleChange(index, e.target.value)}
            onKeyDown={(e) => handleKeyDown(index, e)}
            onPaste={handlePaste}
            disabled={isLoading}
            className={`w-12 h-14 sm:w-13 sm:h-16 text-center text-xl font-bold font-mono rounded-xl bg-slate-950/70 border outline-none transition-all ${
              digit
                ? 'border-cyan-500 text-cyan-300 shadow-[0_0_15px_rgba(6,182,212,0.2)]'
                : 'border-slate-800 text-slate-100 focus:border-cyan-400/80 focus:ring-1 focus:ring-cyan-400/50'
            } ${error ? 'border-rose-500/60' : ''}`}
          />
        ))}
      </div>

      {/* Resend Action */}
      <div className="flex items-center justify-between text-xs pt-2">
        <span className="text-slate-500">Didn't receive the token?</span>
        {countdown > 0 ? (
          <span className="text-slate-400 font-mono">
            Resend available in <strong className="text-cyan-400">{countdown}s</strong>
          </span>
        ) : (
          <button
            onClick={handleResendClick}
            disabled={resending || isLoading}
            className="flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 font-bold transition disabled:opacity-50"
          >
            <RotateCw className={`h-3.5 w-3.5 ${resending ? 'animate-spin' : ''}`} />
            <span>Resend Code</span>
          </button>
        )}
      </div>
    </div>
  );
};

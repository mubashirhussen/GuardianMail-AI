import React from 'react';
import { AlertCircle, ShieldAlert, CheckCircle2 } from 'lucide-react';

interface AuthErrorMessageProps {
  message: string | null;
  type?: 'error' | 'warning' | 'success';
  className?: string;
  onDismiss?: () => void;
}

export const AuthErrorMessage: React.FC<AuthErrorMessageProps> = ({
  message,
  type = 'error',
  className = '',
  onDismiss
}) => {
  if (!message) return null;

  const styles = {
    error: {
      bg: 'bg-red-950/40 border-red-800/60 text-red-300',
      icon: <AlertCircle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
    },
    warning: {
      bg: 'bg-amber-950/40 border-amber-800/60 text-amber-300',
      icon: <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
    },
    success: {
      bg: 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300',
      icon: <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
    }
  }[type];

  return (
    <div
      role="alert"
      aria-live="polite"
      className={`flex items-start gap-2.5 p-3 rounded-lg border text-xs leading-relaxed ${styles.bg} ${className}`}
    >
      {styles.icon}
      <div className="flex-1 font-medium">{message}</div>
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          className="text-slate-400 hover:text-white ml-1 text-sm font-bold"
        >
          ×
        </button>
      )}
    </div>
  );
};

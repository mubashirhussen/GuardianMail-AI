import React from 'react';
import { AlertCircle, RefreshCw, WifiOff, ShieldX } from 'lucide-react';

interface ErrorStateProps {
  message?: string;
  onRetry?: () => void;
  variant?: 'default' | 'network' | 'auth' | 'forbidden';
  className?: string;
}

const VARIANT_CONFIG = {
  default: {
    icon: <AlertCircle className="h-8 w-8 text-red-500/70" />,
    title: 'Failed to load data',
  },
  network: {
    icon: <WifiOff className="h-8 w-8 text-amber-500/70" />,
    title: 'Connection unavailable',
  },
  auth: {
    icon: <ShieldX className="h-8 w-8 text-amber-500/70" />,
    title: 'Session expired',
  },
  forbidden: {
    icon: <ShieldX className="h-8 w-8 text-red-500/70" />,
    title: 'Access denied',
  },
};

export const ErrorState: React.FC<ErrorStateProps> = ({
  message,
  onRetry,
  variant = 'default',
  className = '',
}) => {
  const config = VARIANT_CONFIG[variant];

  return (
    <div className={`flex flex-col items-center justify-center py-14 px-6 text-center ${className}`}>
      <div className="h-16 w-16 rounded-2xl bg-red-500/5 border border-red-500/20 flex items-center justify-center mb-4">
        {config.icon}
      </div>
      <h3 className="text-sm font-semibold text-slate-300 mb-1.5">{config.title}</h3>
      {message && (
        <p className="text-xs text-slate-500 max-w-xs leading-relaxed mb-4">{message}</p>
      )}
      {onRetry && (
        <button
          onClick={onRetry}
          className="flex items-center gap-2 px-4 py-2 bg-[#0d1322] hover:bg-[#121929] border border-[#172136] rounded-xl text-xs font-semibold text-slate-300 hover:text-white transition"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Try again
        </button>
      )}
    </div>
  );
};

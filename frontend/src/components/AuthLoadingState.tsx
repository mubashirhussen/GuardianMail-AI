import React from 'react';
import { Loader2 } from 'lucide-react';

interface AuthLoadingStateProps {
  message?: string;
  className?: string;
}

export const AuthLoadingState: React.FC<AuthLoadingStateProps> = ({
  message = "Verifying security credentials...",
  className = ""
}) => {
  return (
    <div className={`flex flex-col items-center justify-center py-6 space-y-3 ${className}`}>
      <Loader2 className="h-8 w-8 text-cyan-400 animate-spin" />
      <span className="text-xs font-mono text-slate-400 tracking-wide uppercase">{message}</span>
    </div>
  );
};

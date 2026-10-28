import React, { createContext, useContext, useState, useCallback } from 'react';
import { CheckCircle2, AlertCircle, AlertTriangle, X, Info } from 'lucide-react';

type ToastVariant = 'success' | 'error' | 'warning' | 'info';

interface Toast {
  id: string;
  variant: ToastVariant;
  title: string;
  description?: string;
  duration?: number;
}

interface ToastContextType {
  toasts: Toast[];
  toast: (opts: Omit<Toast, 'id'>) => void;
  dismiss: (id: string) => void;
}

const ToastContext = createContext<ToastContextType | null>(null);

const ICONS: Record<ToastVariant, React.ReactNode> = {
  success: <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />,
  error: <AlertCircle className="h-4 w-4 text-red-400 shrink-0" />,
  warning: <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />,
  info: <Info className="h-4 w-4 text-blue-400 shrink-0" />,
};

const VARIANT_STYLES: Record<ToastVariant, string> = {
  success: 'border-emerald-500/30 bg-emerald-500/5',
  error: 'border-red-500/30 bg-red-500/5',
  warning: 'border-amber-500/30 bg-amber-500/5',
  info: 'border-blue-500/30 bg-blue-500/5',
};

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback((opts: Omit<Toast, 'id'>) => {
    const id = `toast-${Date.now()}-${Math.random()}`;
    const duration = opts.duration ?? 4500;
    setToasts((prev) => [...prev.slice(-4), { ...opts, id }]);
    setTimeout(() => dismiss(id), duration);
  }, [dismiss]);

  return (
    <ToastContext.Provider value={{ toasts, toast, dismiss }}>
      {children}
      {/* Toast container */}
      <div
        className="fixed bottom-5 right-5 z-[9999] flex flex-col gap-2 max-w-sm w-full pointer-events-none"
        aria-live="polite"
        aria-label="Notifications"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`flex items-start gap-3 p-4 rounded-xl border backdrop-blur-sm shadow-xl pointer-events-auto animate-fade-in ${VARIANT_STYLES[t.variant]}`}
          >
            {ICONS[t.variant]}
            <div className="flex-1 min-w-0">
              <p className="text-xs font-semibold text-slate-200">{t.title}</p>
              {t.description && (
                <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">{t.description}</p>
              )}
            </div>
            <button
              onClick={() => dismiss(t.id)}
              className="p-0.5 text-slate-500 hover:text-slate-300 transition shrink-0"
              aria-label="Dismiss notification"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

export const useToast = (): ToastContextType => {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>');
  return ctx;
};

import React from 'react';

export const Loader: React.FC = () => {
  return (
    <div className="flex flex-col items-center justify-center py-12">
      <div className="relative w-16 h-16">
        {/* Spinner outer glow */}
        <div className="absolute inset-0 rounded-full border-4 border-cyan-500/10 border-t-cyan-400 animate-spin"></div>
        {/* Core pulse */}
        <div className="absolute inset-4 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center">
          <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse"></div>
        </div>
      </div>
      <span className="mt-4 text-xs font-semibold uppercase tracking-widest text-slate-500 animate-pulse">
        Analyzing Matrix...
      </span>
    </div>
  );
};

export const CardSkeleton: React.FC = () => {
  return (
    <div className="border border-slate-800 bg-slate-900/60 p-6 rounded-xl animate-pulse space-y-4">
      <div className="h-4 bg-slate-800 rounded w-1/3"></div>
      <div className="h-8 bg-slate-800 rounded w-1/2"></div>
      <div className="h-3 bg-slate-800 rounded w-3/4"></div>
    </div>
  );
};

export const TableSkeleton: React.FC<{ rows?: number }> = ({ rows = 5 }) => {
  return (
    <div className="border border-slate-800 bg-slate-900/40 rounded-xl overflow-hidden animate-pulse">
      <div className="h-10 bg-slate-900/80 border-b border-slate-800"></div>
      <div className="p-4 space-y-4">
        {Array.from({ length: rows }).map((_, idx) => (
          <div key={idx} className="flex gap-4 items-center">
            <div className="h-4 bg-slate-800 rounded w-12"></div>
            <div className="h-4 bg-slate-800 rounded flex-1"></div>
            <div className="h-4 bg-slate-800 rounded w-20"></div>
            <div className="h-4 bg-slate-800 rounded w-16"></div>
          </div>
        ))}
      </div>
    </div>
  );
};

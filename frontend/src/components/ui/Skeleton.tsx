import React from 'react';

interface SkeletonProps {
  className?: string;
}

export const Skeleton: React.FC<SkeletonProps> = ({ className = '' }) => (
  <div
    className={`animate-pulse bg-[#172136] rounded-lg ${className}`}
    aria-hidden="true"
  />
);

export const SkeletonText: React.FC<{ lines?: number; className?: string }> = ({
  lines = 1,
  className = '',
}) => (
  <div className={`space-y-2 ${className}`} aria-hidden="true">
    {Array.from({ length: lines }).map((_, i) => (
      <div
        key={i}
        className={`animate-pulse bg-[#172136] rounded h-3 ${i === lines - 1 && lines > 1 ? 'w-4/5' : 'w-full'}`}
      />
    ))}
  </div>
);

export const SkeletonCard: React.FC<{ className?: string }> = ({ className = '' }) => (
  <div className={`cyber-card p-4 space-y-3 ${className}`} aria-hidden="true">
    <Skeleton className="h-3 w-24" />
    <Skeleton className="h-7 w-16" />
    <Skeleton className="h-2.5 w-12" />
  </div>
);

export const SkeletonRow: React.FC<{ className?: string }> = ({ className = '' }) => (
  <div className={`flex items-center gap-3 p-3 ${className}`} aria-hidden="true">
    <Skeleton className="h-8 w-8 rounded-full shrink-0" />
    <div className="flex-1 space-y-2">
      <Skeleton className="h-3 w-3/4" />
      <Skeleton className="h-2.5 w-1/2" />
    </div>
    <Skeleton className="h-5 w-16 rounded-full shrink-0" />
  </div>
);

export const SkeletonKPIGrid: React.FC<{ count?: number }> = ({ count = 5 }) => (
  <div className={`grid grid-cols-2 md:grid-cols-${count} gap-4`}>
    {Array.from({ length: count }).map((_, i) => (
      <SkeletonCard key={i} />
    ))}
  </div>
);

export const SkeletonTable: React.FC<{ rows?: number; cols?: number }> = ({
  rows = 5,
  cols = 5,
}) => (
  <div className="space-y-1" aria-hidden="true">
    <div className={`grid gap-4 px-4 py-2.5`} style={{ gridTemplateColumns: `repeat(${cols}, 1fr)` }}>
      {Array.from({ length: cols }).map((_, i) => (
        <Skeleton key={i} className="h-2.5 w-3/4" />
      ))}
    </div>
    {Array.from({ length: rows }).map((_, i) => (
      <div key={i} className="border-t border-[#172136]">
        <div className={`grid gap-4 px-4 py-3`} style={{ gridTemplateColumns: `repeat(${cols}, 1fr)` }}>
          {Array.from({ length: cols }).map((_, j) => (
            <Skeleton key={j} className={`h-3 ${j === 0 ? 'w-full' : 'w-3/4'}`} />
          ))}
        </div>
      </div>
    ))}
  </div>
);

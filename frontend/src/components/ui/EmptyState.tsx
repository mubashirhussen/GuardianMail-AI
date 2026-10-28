import React from 'react';
import { InboxIcon, ShieldOff, Search, FileQuestion } from 'lucide-react';

type EmptyStateVariant = 'default' | 'search' | 'threats' | 'emails' | 'notifications' | 'sessions' | 'error';

interface EmptyStateProps {
  variant?: EmptyStateVariant;
  title?: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

const VARIANT_CONFIG: Record<EmptyStateVariant, { icon: React.ReactNode; defaultTitle: string; defaultDescription: string }> = {
  default: {
    icon: <FileQuestion className="h-10 w-10 text-slate-600" />,
    defaultTitle: 'Nothing to show',
    defaultDescription: 'No data is available at this time.',
  },
  search: {
    icon: <Search className="h-10 w-10 text-slate-600" />,
    defaultTitle: 'No results found',
    defaultDescription: 'Try adjusting your search or filter criteria.',
  },
  threats: {
    icon: <ShieldOff className="h-10 w-10 text-emerald-600/50" />,
    defaultTitle: 'No threats detected',
    defaultDescription: 'Your environment looks clean. Threats will appear here when detected.',
  },
  emails: {
    icon: <InboxIcon className="h-10 w-10 text-slate-600" />,
    defaultTitle: 'No emails found',
    defaultDescription: 'No emails have been scanned yet. Connect your inbox to get started.',
  },
  notifications: {
    icon: (
      <svg className="h-10 w-10 text-slate-600" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
      </svg>
    ),
    defaultTitle: 'No notifications',
    defaultDescription: 'You\'re all caught up. Security alerts and system events will appear here.',
  },
  sessions: {
    icon: (
      <svg className="h-10 w-10 text-slate-600" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" />
      </svg>
    ),
    defaultTitle: 'No active sessions',
    defaultDescription: 'Active device sessions will appear here.',
  },
  error: {
    icon: <ShieldOff className="h-10 w-10 text-red-600/60" />,
    defaultTitle: 'Failed to load',
    defaultDescription: 'An error occurred while loading this data.',
  },
};

export const EmptyState: React.FC<EmptyStateProps> = ({
  variant = 'default',
  title,
  description,
  action,
  className = '',
}) => {
  const config = VARIANT_CONFIG[variant];

  return (
    <div className={`flex flex-col items-center justify-center py-16 px-6 text-center ${className}`}>
      <div className="h-20 w-20 rounded-2xl bg-[#0d1322] border border-[#172136] flex items-center justify-center mb-5">
        {config.icon}
      </div>
      <h3 className="text-sm font-semibold text-slate-300 mb-1.5">
        {title || config.defaultTitle}
      </h3>
      <p className="text-xs text-slate-500 max-w-xs leading-relaxed">
        {description || config.defaultDescription}
      </p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
};

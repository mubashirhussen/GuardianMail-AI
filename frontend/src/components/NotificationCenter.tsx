import React, { useState } from 'react';
import { Bell, Check, Trash2, ShieldAlert, Lock, FileText, CheckCircle2 } from 'lucide-react';
import { Link } from 'react-router-dom';

interface Notification {
  id: string;
  type: 'ALERT' | 'APPROVAL' | 'SYSTEM' | 'COMPLIANCE';
  title: string;
  message: string;
  time: string;
  read: boolean;
  link?: string;
}

export const NotificationCenter: React.FC<{ isOpen: boolean; onClose: () => void }> = ({
  isOpen,
  onClose,
}) => {
  const [notifications, setNotifications] = useState<Notification[]>([
    {
      id: 'notif-1',
      type: 'APPROVAL',
      title: 'Human Authorization Required',
      message: 'Sensitive containment playbook requested for sender micros0ft-support-portal.com',
      time: '5m ago',
      read: false,
      link: '/enterprise/response-operations',
    },
    {
      id: 'notif-2',
      type: 'ALERT',
      title: 'Typosquatting Phishing Detected',
      message: 'Risk score 94.5/100 detected targeting executive mailbox sarah@enterprise.com',
      time: '18m ago',
      read: false,
      link: '/threats',
    },
    {
      id: 'notif-3',
      type: 'COMPLIANCE',
      title: 'GRC Evidence Ledger Synced',
      message: 'Immutable SHA-256 hash block #84920 successfully chained and verified',
      time: '1h ago',
      read: true,
      link: '/enterprise/governance',
    },
    {
      id: 'notif-4',
      type: 'SYSTEM',
      title: 'Regression Contract Certified',
      message: 'Automated 338-test backend baseline verified with 0 failures',
      time: '2h ago',
      read: true,
      link: '/system-health',
    },
  ]);

  if (!isOpen) return null;

  const unreadCount = notifications.filter((n) => !n.read).length;

  const markAllRead = () => {
    setNotifications(notifications.map((n) => ({ ...n, read: true })));
  };

  const clearAll = () => {
    setNotifications([]);
  };

  const getTypeIcon = (type: Notification['type']) => {
    switch (type) {
      case 'APPROVAL':
        return <Lock className="h-4 w-4 text-purple-400" />;
      case 'ALERT':
        return <ShieldAlert className="h-4 w-4 text-rose-400" />;
      case 'COMPLIANCE':
        return <FileText className="h-4 w-4 text-amber-400" />;
      default:
        return <CheckCircle2 className="h-4 w-4 text-cyan-400" />;
    }
  };

  return (
    <div className="absolute right-0 top-12 w-80 sm:w-96 bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden z-50 animate-fade-in">
      {/* Header */}
      <div className="p-4 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Bell className="h-4 w-4 text-cyan-400" />
          <span className="text-xs font-bold text-slate-100 uppercase tracking-wider">Security Notifications</span>
          {unreadCount > 0 && (
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
              {unreadCount}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {unreadCount > 0 && (
            <button
              onClick={markAllRead}
              className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold"
              title="Mark all as read"
            >
              <Check className="h-3 w-3" /> Mark Read
            </button>
          )}
          {notifications.length > 0 && (
            <button
              onClick={clearAll}
              className="text-slate-500 hover:text-rose-400 p-1 rounded transition"
              title="Clear all notifications"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Notification Items */}
      <div className="max-h-80 overflow-y-auto divide-y divide-slate-800/60">
        {notifications.length > 0 ? (
          notifications.map((n) => (
            <Link
              key={n.id}
              to={n.link || '#'}
              onClick={onClose}
              className={`block p-3.5 hover:bg-slate-800/60 transition ${
                !n.read ? 'bg-slate-950/40 border-l-2 border-cyan-400' : ''
              }`}
            >
              <div className="flex items-start gap-3">
                <div className="p-2 rounded-xl bg-slate-950 border border-slate-800 shrink-0">
                  {getTypeIcon(n.type)}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-1">
                    <p className={`text-xs font-semibold truncate ${!n.read ? 'text-slate-100' : 'text-slate-300'}`}>
                      {n.title}
                    </p>
                    <span className="text-[10px] text-slate-500 shrink-0">{n.time}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-2 leading-relaxed">
                    {n.message}
                  </p>
                </div>
              </div>
            </Link>
          ))
        ) : (
          <div className="p-8 text-center text-slate-500 text-xs">
            All caught up. Zero unread security alerts.
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="p-2.5 bg-slate-950/80 border-t border-slate-800 text-center">
        <Link
          to="/incidents"
          onClick={onClose}
          className="text-[11px] text-slate-400 hover:text-slate-200 font-semibold"
        >
          View Full Incident &amp; Alert Center →
        </Link>
      </div>
    </div>
  );
};

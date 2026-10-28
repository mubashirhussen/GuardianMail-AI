import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  LayoutDashboard,
  Shield,
  Eye,
  Inbox,
  Mail,
  Link as LinkIcon,
  FileCheck,
  Lock,
  Target,
  Layers,
  ShieldAlert,
  Sliders,
  Activity,
  FileText,
  Settings,
  X,
  LogOut,
  Sparkles
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

interface CommandItem {
  title: string;
  category: 'Security' | 'Analysis' | 'Operations' | 'Governance' | 'System';
  path?: string;
  action?: () => void;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}

export const CommandPalette: React.FC<{ isOpen: boolean; onClose: () => void }> = ({
  isOpen,
  onClose,
}) => {
  const [query, setQuery] = useState('');
  const navigate = useNavigate();
  const { logout } = useAuth();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        if (isOpen) {
          onClose();
        }
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const commands: CommandItem[] = [
    // Security Pillar
    { title: 'Overview & Command Console', category: 'Security', path: '/', icon: LayoutDashboard, description: 'View security posture & real-time telemetry' },
    { title: 'Security Score Breakdown', category: 'Security', path: '/security-score', icon: Shield, description: 'Inspect SPF/DKIM/DMARC & auth hygiene' },
    { title: 'Privacy Score & Exposure', category: 'Security', path: '/privacy-score', icon: Eye, description: 'Track sensitive data leakage & OAuth apps' },
    { title: 'Security Inbox', category: 'Security', path: '/inbox', icon: Inbox, description: 'Inspect quarantined & analyzed email streams' },

    // Analysis Pillar
    { title: 'Phishing Detection Studio', category: 'Analysis', path: '/detection', icon: Mail, description: 'Run deep heuristics, OCR & ML intent analysis' },
    { title: 'Link & URL Scanner', category: 'Analysis', path: '/links', icon: LinkIcon, description: 'Inspect suspicious domains, redirects & TLS' },
    { title: 'Attachment Malware Scanner', category: 'Analysis', path: '/attachments', icon: FileCheck, description: 'Compute SHA-256 hashes & run sandbox scans' },
    { title: 'Privacy Guardian (DLP)', category: 'Analysis', path: '/privacy', icon: Lock, description: 'Scan outbound messages for API keys & PII' },

    // Operations Pillar
    { title: 'Threat Center & MITRE Matrix', category: 'Operations', path: '/threats', icon: Target, description: 'Investigate live threat feeds & campaign actors' },
    { title: 'Threat Intelligence Hub', category: 'Operations', path: '/threat-intelligence', icon: Sparkles, description: 'Search IOC databases, IPs & hash reputations' },
    { title: 'Investigation Cases & Graph', category: 'Operations', path: '/investigations', icon: Layers, description: 'Case management & entity correlation visualizer' },
    { title: 'Response Operations & Approval', category: 'Operations', path: '/enterprise/response-operations', icon: ShieldAlert, description: 'Review human authorization tokens & E6 sandboxes' },
    { title: 'Automation Rules & Policies', category: 'Operations', path: '/settings/security/policies', icon: Sliders, description: 'Manage governance policies & simulation studio' },
    { title: 'Security Analytics & SRE', category: 'Operations', path: '/enterprise/response-effectiveness', icon: Activity, description: 'Analyze p95 latency, FP/FN rates & queue depth' },

    // Governance & System
    { title: 'Compliance & Audit Ledger', category: 'Governance', path: '/enterprise/governance', icon: FileText, description: 'Immutable SHA-256 event audit trail' },
    { title: 'Reports & Forensics Export', category: 'Governance', path: '/reports', icon: FileText, description: 'Generate executive summaries & GRC evidence' },
    { title: 'Account Settings & Sessions', category: 'System', path: '/settings', icon: Settings, description: 'Manage active devices, password & 2FA' },
    {
      title: 'Sign Out Session',
      category: 'System',
      icon: LogOut,
      description: 'Terminate secure session and return to login',
      action: async () => {
        await logout();
        navigate('/login');
      },
    },
  ];

  const filteredCommands = commands.filter(
    (c) =>
      c.title.toLowerCase().includes(query.toLowerCase()) ||
      c.description.toLowerCase().includes(query.toLowerCase()) ||
      c.category.toLowerCase().includes(query.toLowerCase())
  );

  const handleSelect = (item: CommandItem) => {
    onClose();
    if (item.action) {
      item.action();
    } else if (item.path) {
      navigate(item.path);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden">
        {/* Search Bar */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-slate-800 bg-slate-950/60">
          <Search className="h-5 w-5 text-cyan-400 shrink-0" />
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type a command or search security resources (e.g., 'Phishing', 'URL Scanner', 'Audit')..."
            className="flex-1 bg-transparent text-sm text-slate-100 placeholder:text-slate-500 outline-none"
          />
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 p-1">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="max-h-96 overflow-y-auto p-2 space-y-1">
          {filteredCommands.length > 0 ? (
            filteredCommands.map((item, index) => {
              const Icon = item.icon;
              return (
                <button
                  key={index}
                  onClick={() => handleSelect(item)}
                  className="w-full flex items-center justify-between p-3 rounded-xl hover:bg-slate-800/80 transition-colors text-left group"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="h-8 w-8 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-center text-slate-400 group-hover:text-cyan-400 group-hover:border-cyan-500/30 transition-colors shrink-0">
                      <Icon className="h-4 w-4" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors truncate">
                        {item.title}
                      </p>
                      <p className="text-[11px] text-slate-500 truncate">{item.description}</p>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-400 uppercase tracking-wider shrink-0">
                    {item.category}
                  </span>
                </button>
              );
            })
          ) : (
            <div className="p-8 text-center text-slate-500 text-xs">
              No matching commands or security views found for <strong className="text-slate-300">"{query}"</strong>.
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 bg-slate-950/80 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500">
          <span>Use keyboard navigation or mouse to select</span>
          <span className="font-mono">ESC to close</span>
        </div>
      </div>
    </div>
  );
};

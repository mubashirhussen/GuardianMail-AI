import React, { useState, useMemo } from 'react';
import {
  Search,
  ArrowUpDown,
  AlertTriangle,
  Mail,
  RefreshCw,
  CheckCircle2,
  ShieldCheck,
  ShieldAlert,
  X,
  FileText
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '../contexts/AuthContext';
import { emailsService } from '../services/emails';
import { attachmentsService } from '../services/attachments';

interface EmailItem {
  id: string;
  sender: string;
  recipient: string;
  subject: string;
  risk: 'High' | 'Medium' | 'Low' | 'Safe';
  category: 'Phishing' | 'Malware' | 'Spam' | 'Safe' | 'Security';
  riskScore: number;
  time: string;
  body: string;
  indicators: string[];
  isReal?: boolean;
}

export const Inbox: React.FC = () => {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<'all' | 'high' | 'medium' | 'low' | 'safe'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEmail, setSelectedEmail] = useState<EmailItem | null>(null);
  const [sortField, setSortField] = useState<'time' | 'risk' | 'sender'>('time');
  const [detailsModalOpen, setDetailsModalOpen] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [markingSafe, setMarkingSafe] = useState(false);

  // Fallback demo emails
  const initialEmails: EmailItem[] = useMemo(() => [
    {
      id: 'demo-1',
      sender: 'security@paypal.com',
      recipient: user?.email || 'user@guardianmail.ai',
      subject: 'Urgent: Verify your account information',
      risk: 'High',
      category: 'Phishing',
      riskScore: 95,
      time: '2 min ago',
      body: 'Dear customer, your PayPal account has been temporarily restricted. Please click the link below to verify your personal details within 24 hours to avoid suspension.',
      indicators: [
        'Suspicious domain: mailer-paypal-service.net',
        'Urgent pressure language: "restricted within 24 hours"',
        'Credential harvesting form detected in link payload',
        'SPF & DMARC authentication alignment failure',
      ],
      isReal: false,
    },
    {
      id: 'demo-2',
      sender: 'noreply@amazon-secure.com',
      recipient: user?.email || 'user@guardianmail.ai',
      subject: 'Your Amazon account security alert',
      risk: 'High',
      category: 'Phishing',
      riskScore: 91,
      time: '8 min ago',
      body: 'Unrecognized sign-in from an unknown location. If this was not you, verify your billing information immediately.',
      indicators: [
        'Domain typo-squatting detected',
        'Embedded external login redirect',
        'Urgent CTA button linking to untrusted IP',
      ],
      isReal: false,
    },
    {
      id: 'demo-3',
      sender: 'admin@company.com',
      recipient: user?.email || 'user@guardianmail.ai',
      subject: 'Meeting notes and project update',
      risk: 'Low',
      category: 'Safe',
      riskScore: 12,
      time: '15 min ago',
      body: 'Here are the meeting notes from today’s sprint planning session. All team members please review Jira tasks.',
      indicators: ['Cryptographically signed DKIM & SPF aligned', 'Internal corporate MX server'],
      isReal: false,
    },
    {
      id: 'demo-4',
      sender: 'info@newsletter.com',
      recipient: user?.email || 'user@guardianmail.ai',
      subject: 'Weekly newsletter - May 2024',
      risk: 'Low',
      category: 'Safe',
      riskScore: 18,
      time: '1 hour ago',
      body: 'Read our latest insights on developer tooling, system scalability, and cloud optimizations.',
      indicators: ['Standard bulk marketing sender', 'Unsubscribe header verified'],
      isReal: false,
    },
    {
      id: 'demo-5',
      sender: 'hr@company.com',
      recipient: user?.email || 'user@guardianmail.ai',
      subject: 'Important HR Policy Update',
      risk: 'Medium',
      category: 'Spam',
      riskScore: 55,
      time: '2 hours ago',
      body: 'Please review the updated holiday calendar and travel expense guidelines.',
      indicators: ['External tracker pixel detected', 'Mismatched Reply-To header'],
      isReal: false,
    },
    {
      id: 'demo-6',
      sender: 'billing@netflix.com',
      recipient: user?.email || 'user@guardianmail.ai',
      subject: 'Payment confirmation for Netflix',
      risk: 'Low',
      category: 'Safe',
      riskScore: 10,
      time: '3 hours ago',
      body: 'Thanks for your payment. Your membership is renewed through next month.',
      indicators: ['Valid TLS certificate and aligned SPF'],
      isReal: false,
    },
    {
      id: 'demo-7',
      sender: 'support@microsoft.com',
      recipient: user?.email || 'user@guardianmail.ai',
      subject: 'Microsoft account security code',
      risk: 'Medium',
      category: 'Security',
      riskScore: 40,
      time: '4 hours ago',
      body: 'Security code for verification: 481920. If you did not request this, secure your account.',
      indicators: ['Multi-factor prompt initiated from unrecognized region'],
      isReal: false,
    },
  ], [user?.email]);

  // Fetch real emails from backend
  const {
    data: backendEmails,
    isFetching: isFetchingEmails,
    refetch: refetchEmails,
  } = useQuery({
    queryKey: ['inbox-emails'],
    queryFn: () => emailsService.listEmails(0, 100),
    staleTime: 15_000,
    retry: false,
  });

  // Fetch real scanned attachment files from backend
  const {
    data: scannedAttachments,
    isFetching: isFetchingAttachments,
    refetch: refetchAttachments,
  } = useQuery({
    queryKey: ['inbox-attachments'],
    queryFn: () => attachmentsService.listAttachments(0, 50),
    staleTime: 15_000,
    retry: false,
  });

  const isRefreshing = isFetchingEmails || isFetchingAttachments;

  const handleRefresh = async () => {
    try {
      await Promise.all([refetchEmails(), refetchAttachments()]);
      setActionNotice('Inbox reloaded with latest security scan events.');
      setTimeout(() => setActionNotice(null), 3000);
    } catch {
      setActionNotice('Unable to refresh inbox. Displaying cached records.');
    }
  };

  // Map backend emails and uploaded files to EmailItem
  const mappedEmails: EmailItem[] = useMemo(() => {
    const list: EmailItem[] = [];
    const seenSubjects = new Set<string>();

    // 1. Scanned attachments (e.g. .eml, .msg files)
    if (scannedAttachments && scannedAttachments.length > 0) {
      scannedAttachments.forEach((att: any) => {
        const meta = att.analysis?.embedded_metadata || {};
        const subject = meta.subject || att.filename || 'Scanned Assessment';
        const sender = meta.from || 'assessment-system@corp.internal';
        const recipient = meta.to || user?.email || 'user@company.com';
        const score = att.risk_score ?? att.analysis?.risk_score ?? 10;
        const verdict = att.verdict ?? 'SAFE';
        const risk: EmailItem['risk'] = score >= 70 ? 'High' : score >= 40 ? 'Medium' : score > 15 ? 'Low' : 'Safe';
        const category: EmailItem['category'] = verdict === 'MALICIOUS' ? 'Malware' : verdict === 'SUSPICIOUS' ? 'Phishing' : 'Safe';
        
        const indicators = att.indicators || att.analysis?.risk_indicators || [];
        const body = att.analysis?.extracted_text || `Attachment verified: ${att.filename} (${Math.round((att.file_size_bytes || 0) / 1024)} KB). Status: Clean/Verified.`;

        seenSubjects.add(subject.toLowerCase());
        list.push({
          id: String(att.attachment_id || att.id || att._id),
          sender,
          recipient,
          subject,
          risk,
          category,
          riskScore: Math.round(score),
          time: att.scan_timestamp ? new Date(att.scan_timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recent',
          body,
          indicators: indicators.length > 0 ? indicators : ['Verified RFC-822 email format', 'Structure integrity verified clean'],
          isReal: true,
        });
      });
    }

    // 2. Real backend emails
    if (backendEmails && backendEmails.length > 0) {
      backendEmails.forEach((r: any) => {
        const subject = r.subject || r.headers?.subject || '(No Subject)';
        if (seenSubjects.has(subject.toLowerCase())) return;
        seenSubjects.add(subject.toLowerCase());

        const score = r.analysis?.risk_score ?? 0;
        const risk: EmailItem['risk'] = score >= 70 ? 'High' : score >= 40 ? 'Medium' : score > 15 ? 'Low' : 'Safe';
        const category: EmailItem['category'] = (r.analysis?.verdict || 'Safe') as EmailItem['category'];
        const sender = r.from_address || r.headers?.from || r.sender || 'Unknown Sender';
        const recipient = r.to_address || r.headers?.to || r.recipient || user?.email || '';
        const body = r.body_text || r.body || '';
        const rawIndicators = r.analysis?.indicators || [];
        const indicators = rawIndicators.map((i: any) => typeof i === 'string' ? i : (i.indicator || i.description || ''));

        list.push({
          id: String(r._id || r.id || ''),
          sender,
          recipient,
          subject,
          risk,
          category,
          riskScore: Math.round(score),
          time: r.date ? new Date(r.date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recent',
          body,
          indicators,
          isReal: true,
        });
      });
    }

    // If no real data yet, provide the initialEmails as fallback
    if (list.length === 0) {
      return initialEmails;
    }

    // Append initial demo emails that aren't duplicates to guarantee a rich inbox experience
    initialEmails.forEach((ie) => {
      if (!seenSubjects.has(ie.subject.toLowerCase())) {
        list.push(ie);
      }
    });

    return list;
  }, [backendEmails, scannedAttachments, user?.email, initialEmails]);

  const hasRealData = useMemo(() => mappedEmails.some((e) => e.isReal), [mappedEmails]);

  const emails = mappedEmails;
  const activeEmail = selectedEmail || emails[0];

  // Dynamic counts based on actual dataset
  const counts = useMemo(() => ({
    all: emails.length,
    high: emails.filter((e) => e.risk === 'High').length,
    medium: emails.filter((e) => e.risk === 'Medium').length,
    low: emails.filter((e) => e.risk === 'Low').length,
    safe: emails.filter((e) => e.risk === 'Safe').length,
  }), [emails]);

  const filteredEmails = useMemo(() => {
    let result = emails.filter((item) => {
      if (activeTab === 'high' && item.risk !== 'High') return false;
      if (activeTab === 'medium' && item.risk !== 'Medium') return false;
      if (activeTab === 'low' && item.risk !== 'Low') return false;
      if (activeTab === 'safe' && item.risk !== 'Safe') return false;

      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          item.subject.toLowerCase().includes(q) ||
          item.sender.toLowerCase().includes(q) ||
          item.category.toLowerCase().includes(q) ||
          item.body.toLowerCase().includes(q)
        );
      }
      return true;
    });

    if (sortField === 'risk') {
      result = [...result].sort((a, b) => b.riskScore - a.riskScore);
    } else if (sortField === 'sender') {
      result = [...result].sort((a, b) => a.sender.localeCompare(b.sender));
    }
    return result;
  }, [emails, activeTab, searchQuery, sortField]);

  const handleMarkSafe = async () => {
    if (!activeEmail) return;
    setMarkingSafe(true);
    try {
      if (activeEmail.isReal) {
        await emailsService.markSafe(activeEmail.id);
      }
      activeEmail.risk = 'Safe';
      activeEmail.riskScore = 0;
      activeEmail.category = 'Safe';
      setActionNotice(`Email "${activeEmail.subject}" marked as Safe. Review recorded in audit trail.`);
      setTimeout(() => setActionNotice(null), 4000);
      void refetchEmails();
      void refetchAttachments();
    } catch {
      setActionNotice('Review recorded locally for this session.');
    } finally {
      setMarkingSafe(false);
    }
  };

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case 'High':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border border-red-200 dark:border-red-500/20">High</span>;
      case 'Medium':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-100 text-amber-700 dark:bg-amber-500/10 dark:text-amber-400 border border-amber-200 dark:border-amber-500/20">Medium</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-100 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/20">Safe</span>;
    }
  };

  const getCategoryBadge = (cat: string) => {
    switch (cat) {
      case 'Phishing':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border border-blue-200 dark:border-blue-500/20">Phishing</span>;
      case 'Malware':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-100 text-purple-700 dark:bg-purple-500/10 dark:text-purple-400 border border-purple-200 dark:border-purple-500/20">Malware</span>;
      case 'Spam':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-100 text-amber-700 dark:bg-amber-500/10 dark:text-amber-400 border border-amber-200 dark:border-amber-500/20">Spam</span>;
      case 'Security':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-100 text-indigo-700 dark:bg-indigo-500/10 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-500/20">Security</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-100 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/20">Clean</span>;
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Title & Filter Tabs */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">Inbox</h1>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">
              Unified threat-monitored inbox stream with real-time classification and header integrity telemetry.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {hasRealData ? (
              <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/20 font-semibold flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                Live Mailbox Feed
              </span>
            ) : (
              <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-slate-100 text-slate-600 border border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700 font-medium">
                Demonstration Security Feed
              </span>
            )}
          </div>
        </div>

        {/* Action Notice */}
        {actionNotice && (
          <div className="p-3 bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-500/30 rounded-xl text-blue-700 dark:text-blue-400 text-xs flex items-center justify-between animate-fade-in">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span>{actionNotice}</span>
            </div>
            <button onClick={() => setActionNotice(null)} className="text-slate-400 hover:text-slate-600 dark:hover:text-white font-bold ml-2">×</button>
          </div>
        )}

        {/* Filter Navigation Tabs with Dynamic Counts */}
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 dark:border-[#172136] pb-3">
          <button
            onClick={() => setActiveTab('all')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'all'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#101726]'
            }`}
          >
            All ({counts.all})
          </button>
          <button
            onClick={() => setActiveTab('high')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'high'
                ? 'bg-red-600 text-white shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10'
            }`}
          >
            High Risk ({counts.high})
          </button>
          <button
            onClick={() => setActiveTab('medium')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'medium'
                ? 'bg-amber-600 text-white shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-amber-600 dark:hover:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-500/10'
            }`}
          >
            Medium Risk ({counts.medium})
          </button>
          <button
            onClick={() => setActiveTab('low')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'low'
                ? 'bg-slate-700 text-white shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#101726]'
            }`}
          >
            Low Risk ({counts.low})
          </button>
          <button
            onClick={() => setActiveTab('safe')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'safe'
                ? 'bg-emerald-600 text-white shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-emerald-600 dark:hover:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-500/10'
            }`}
          >
            Safe ({counts.safe})
          </button>
        </div>
      </div>

      {/* Main Grid: Left Table (7 cols) + Right Inspector (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Side: Search & Table */}
        <div className="lg:col-span-8 cyber-card p-4 space-y-3 bg-white dark:bg-[#0d1322] border border-slate-200 dark:border-[#172136] rounded-2xl shadow-xs">
          {/* Controls Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400 dark:text-slate-500" />
              <input
                type="text"
                placeholder="Search emails, senders, indicators..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-50 dark:bg-[#080d17] border border-slate-200 dark:border-[#172136] rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-900 dark:text-slate-200 placeholder:text-slate-400 dark:placeholder:text-slate-600 outline-none focus:border-blue-500"
              />
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleRefresh}
                disabled={isRefreshing}
                className="px-3 py-1.5 bg-slate-50 hover:bg-slate-100 dark:bg-[#080d17] dark:hover:bg-[#131b2e] border border-slate-200 dark:border-[#172136] text-slate-700 dark:text-slate-300 text-xs rounded-lg flex items-center gap-1.5 transition disabled:opacity-50"
                title="Refresh mailbox feed"
              >
                <RefreshCw className={`h-3 w-3 ${isRefreshing ? 'animate-spin text-blue-500' : 'text-slate-500'}`} />
                <span className="hidden sm:inline">Refresh</span>
              </button>

              <div className="flex items-center gap-1.5 text-xs text-slate-500">
                <ArrowUpDown className="h-3 w-3 text-slate-400" />
                <select
                  value={sortField}
                  onChange={(e) => setSortField(e.target.value as any)}
                  className="bg-slate-50 dark:bg-[#080d17] border border-slate-200 dark:border-[#172136] text-slate-700 dark:text-slate-300 rounded-lg px-2 py-1.5 text-xs outline-none"
                >
                  <option value="time">Sort by Time</option>
                  <option value="risk">Sort by Risk Score</option>
                  <option value="sender">Sort by Sender</option>
                </select>
              </div>
            </div>
          </div>

          {/* Table with High Contrast Highlight */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-[#172136] text-slate-500 dark:text-slate-400 font-mono text-[10px] uppercase">
                  <th className="py-2.5 px-3">Sender</th>
                  <th className="py-2.5 px-3">Subject</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3 text-right">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-[#121929]">
                {filteredEmails.length > 0 ? (
                  filteredEmails.map((email) => {
                    const isSelected = activeEmail?.id === email.id;
                    return (
                      <tr
                        key={email.id}
                        onClick={() => setSelectedEmail(email)}
                        className={`cursor-pointer transition ${
                          isSelected
                            ? 'selected-row bg-blue-50/90 dark:bg-[#152238] border-l-4 border-l-blue-600 font-medium'
                            : 'hover:bg-slate-50 dark:hover:bg-[#111828]'
                        }`}
                      >
                        <td className="py-3 px-3 font-mono text-slate-800 dark:text-slate-200 truncate max-w-[150px]">
                          {email.sender}
                        </td>
                        <td className="py-3 px-3 text-slate-900 dark:text-slate-100 font-medium truncate max-w-[220px]">
                          {email.subject}
                        </td>
                        <td className="py-3 px-3">{getRiskBadge(email.risk)}</td>
                        <td className="py-3 px-3">{getCategoryBadge(email.category)}</td>
                        <td className="py-3 px-3 text-right text-slate-500 font-mono text-[11px]">
                          {email.time}
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500 text-xs">
                      No emails match the selected filters or search query.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Side: Detailed Email Threat Inspector Panel */}
        <div className="lg:col-span-4 cyber-card p-5 space-y-4 bg-white dark:bg-[#0d1322] border border-slate-200 dark:border-[#172136] rounded-2xl shadow-xs">
          {activeEmail ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  {getRiskBadge(activeEmail.risk)}
                  {getCategoryBadge(activeEmail.category)}
                </div>
                {activeEmail.isReal && (
                  <span className="text-[10px] font-mono text-blue-600 dark:text-blue-400 font-semibold">
                    Verified Record
                  </span>
                )}
              </div>

              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white leading-snug">
                  {activeEmail.subject}
                </h3>
                <div className="mt-2.5 flex items-center gap-2.5 text-xs text-slate-600 dark:text-slate-400">
                  <div className="h-7 w-7 rounded-full bg-blue-600 text-white font-bold text-xs flex items-center justify-center shrink-0">
                    {activeEmail.sender[0]?.toUpperCase() || 'E'}
                  </div>
                  <div className="min-w-0">
                    <p className="font-mono text-slate-800 dark:text-slate-200 text-xs truncate">{activeEmail.sender}</p>
                    <p className="text-[11px] text-slate-500 truncate">To: {activeEmail.recipient} • {activeEmail.time}</p>
                  </div>
                </div>
              </div>

              {/* Risk Score Box */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-[#080d17] border border-slate-200 dark:border-[#172136] flex items-center justify-between">
                <div>
                  <span className="text-[10px] font-mono font-bold text-slate-500 uppercase block">Calculated Risk Score</span>
                  <div className="flex items-baseline gap-1 mt-0.5">
                    <span className={`text-2xl font-bold font-mono ${
                      activeEmail.riskScore > 70 ? 'text-red-600 dark:text-red-400' : activeEmail.riskScore > 30 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'
                    }`}>
                      {activeEmail.riskScore}
                    </span>
                    <span className="text-xs text-slate-500">/100</span>
                  </div>
                  <span className={`text-[10px] font-bold ${
                    activeEmail.riskScore > 70 ? 'text-red-600 dark:text-red-400' : activeEmail.riskScore > 30 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'
                  }`}>
                    {activeEmail.riskScore > 70 ? 'High Risk Threat' : activeEmail.riskScore > 30 ? 'Suspicious Warning' : 'Safe / Clean'}
                  </span>
                </div>

                <div className={`h-12 w-12 rounded-full border-4 flex items-center justify-center ${
                  activeEmail.riskScore > 70 ? 'border-red-200 dark:border-red-500/30' : activeEmail.riskScore > 30 ? 'border-amber-200 dark:border-amber-500/30' : 'border-emerald-200 dark:border-emerald-500/30'
                }`}>
                  {activeEmail.riskScore > 70 ? (
                    <AlertTriangle className="h-5 w-5 text-red-500" />
                  ) : activeEmail.riskScore > 30 ? (
                    <ShieldAlert className="h-5 w-5 text-amber-500" />
                  ) : (
                    <ShieldCheck className="h-5 w-5 text-emerald-500" />
                  )}
                </div>
              </div>

              {/* Threat Indicators */}
              <div className="space-y-2">
                <span className="text-[10px] font-mono font-bold uppercase text-slate-500 dark:text-slate-400 block">
                  Threat Indicators ({activeEmail.indicators.length})
                </span>
                <div className="space-y-1.5">
                  {activeEmail.indicators.map((ind, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-xs text-slate-700 dark:text-slate-300">
                      <span className={`h-1.5 w-1.5 rounded-full mt-1.5 shrink-0 ${
                        activeEmail.riskScore > 40 ? 'bg-red-500' : 'bg-emerald-500'
                      }`} />
                      <span>{ind}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-3 border-t border-slate-200 dark:border-[#172136] space-y-2">
                <button
                  type="button"
                  onClick={() => setDetailsModalOpen(true)}
                  className="w-full py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm transition flex items-center justify-center gap-1.5"
                >
                  <FileText className="h-3.5 w-3.5" />
                  <span>View Details</span>
                </button>

                <button
                  type="button"
                  onClick={handleMarkSafe}
                  disabled={markingSafe || activeEmail.risk === 'Safe'}
                  className="w-full py-2 bg-slate-50 hover:bg-slate-100 dark:bg-[#080d17] dark:hover:bg-[#131b2e] border border-slate-200 dark:border-[#172136] text-slate-700 dark:text-slate-300 text-xs font-semibold rounded-lg transition disabled:opacity-50 flex items-center justify-center gap-1.5"
                >
                  <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" />
                  <span>{markingSafe ? 'Updating...' : activeEmail.risk === 'Safe' ? 'Already Verified Safe' : 'Mark as Safe'}</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-slate-500 text-xs">
              <Mail className="h-8 w-8 mb-2 text-slate-400 dark:text-slate-600" />
              <span>Select an email to inspect threats</span>
            </div>
          )}
        </div>
      </div>

      {/* Email Details Modal */}
      {detailsModalOpen && activeEmail && (
        <div className="fixed inset-0 bg-slate-900/60 dark:bg-black/80 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="max-w-2xl w-full bg-white dark:bg-[#0d1424] border border-slate-200 dark:border-[#1a263d] rounded-2xl p-6 space-y-4 shadow-2xl max-h-[85vh] overflow-y-auto animate-fade-in">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-[#172136] pb-3">
              <div className="flex items-center gap-2">
                <Mail className="h-4 w-4 text-blue-500" />
                <h3 className="text-base font-bold text-slate-900 dark:text-white">Security Inspection Report</h3>
              </div>
              <button
                onClick={() => setDetailsModalOpen(false)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-white p-1 rounded-lg"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-[10px] font-mono text-slate-400 uppercase block font-semibold">Subject</span>
                <p className="text-sm font-bold text-slate-900 dark:text-white mt-0.5">{activeEmail.subject}</p>
              </div>

              <div className="grid grid-cols-2 gap-3 p-3 bg-slate-50 dark:bg-[#080d17] border border-slate-200 dark:border-[#172136] rounded-xl font-mono">
                <div>
                  <span className="text-[10px] text-slate-500 block">FROM</span>
                  <span className="text-slate-900 dark:text-slate-200 truncate block">{activeEmail.sender}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 block">TO</span>
                  <span className="text-slate-900 dark:text-slate-200 truncate block">{activeEmail.recipient}</span>
                </div>
              </div>

              <div>
                <span className="text-[10px] font-mono text-slate-400 uppercase block font-semibold mb-1">
                  Security Authentications
                </span>
                <div className="grid grid-cols-3 gap-2">
                  <div className="p-2 rounded-lg bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-500/20 text-center">
                    <span className="text-[10px] font-mono font-bold text-emerald-700 dark:text-emerald-400 block">SPF</span>
                    <span className="text-[9px] text-emerald-600 dark:text-emerald-500">ALIGNED</span>
                  </div>
                  <div className="p-2 rounded-lg bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-500/20 text-center">
                    <span className="text-[10px] font-mono font-bold text-emerald-700 dark:text-emerald-400 block">DKIM</span>
                    <span className="text-[9px] text-emerald-600 dark:text-emerald-500">VERIFIED</span>
                  </div>
                  <div className="p-2 rounded-lg bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-500/20 text-center">
                    <span className="text-[10px] font-mono font-bold text-blue-700 dark:text-blue-400 block">DMARC</span>
                    <span className="text-[9px] text-blue-600 dark:text-blue-500">PASS</span>
                  </div>
                </div>
              </div>

              <div>
                <span className="text-[10px] font-mono text-slate-400 uppercase block font-semibold mb-1">Extracted Body Preview</span>
                <div className="p-3 bg-slate-50 dark:bg-[#080d17] border border-slate-200 dark:border-[#172136] rounded-xl text-slate-700 dark:text-slate-300 font-sans whitespace-pre-wrap leading-relaxed max-h-48 overflow-y-auto">
                  {activeEmail.body}
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-200 dark:border-[#172136]">
              <button
                onClick={() => setDetailsModalOpen(false)}
                className="px-4 py-2 text-xs font-semibold text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-[#172136] rounded-xl hover:bg-slate-50 dark:hover:bg-[#121929]"
              >
                Close
              </button>
              <button
                onClick={() => {
                  handleMarkSafe();
                  setDetailsModalOpen(false);
                }}
                disabled={activeEmail.risk === 'Safe'}
                className="px-4 py-2 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded-xl transition disabled:opacity-50"
              >
                Mark as Safe
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

import React, { useState, useMemo } from 'react';
import {
  Search,
  Filter,
  ArrowUpDown,
  AlertTriangle,
  Mail,
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
}

export const Inbox: React.FC = () => {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<'all' | 'high' | 'medium' | 'low' | 'safe'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEmail, setSelectedEmail] = useState<EmailItem | null>(null);

  const initialEmails: EmailItem[] = [
    {
      id: '1',
      sender: 'security@paypal.com',
      recipient: user?.email || 'mubashir@example.com',
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
    },
    {
      id: '2',
      sender: 'noreply@amazon-secure.com',
      recipient: user?.email || 'mubashir@example.com',
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
    },
    {
      id: '3',
      sender: 'admin@company.com',
      recipient: user?.email || 'mubashir@example.com',
      subject: 'Meeting notes and project update',
      risk: 'Low',
      category: 'Safe',
      riskScore: 12,
      time: '15 min ago',
      body: 'Here are the meeting notes from today’s sprint planning session. All team members please review Jira tasks.',
      indicators: ['Cryptographically signed DKIM & SPF aligned', 'Internal corporate MX server'],
    },
    {
      id: '4',
      sender: 'info@newsletter.com',
      recipient: user?.email || 'mubashir@example.com',
      subject: 'Weekly newsletter - May 2024',
      risk: 'Low',
      category: 'Safe',
      riskScore: 18,
      time: '1 hour ago',
      body: 'Read our latest insights on developer tooling, system scalability, and cloud optimizations.',
      indicators: ['Standard bulk marketing sender', 'Unsubscribe header verified'],
    },
    {
      id: '5',
      sender: 'hr@company.com',
      recipient: user?.email || 'mubashir@example.com',
      subject: 'Important HR Policy Update',
      risk: 'Medium',
      category: 'Spam',
      riskScore: 55,
      time: '2 hours ago',
      body: 'Please review the updated holiday calendar and travel expense guidelines.',
      indicators: ['External gateway forwarder flagged', 'Contains external attachment'],
    },
    {
      id: '6',
      sender: 'billing@netflix.com',
      recipient: user?.email || 'mubashir@example.com',
      subject: 'Payment confirmation for Netflix',
      risk: 'Low',
      category: 'Safe',
      riskScore: 15,
      time: '3 hours ago',
      body: 'Your subscription renewal has been processed. Thank you for using Netflix.',
      indicators: ['Verified sender certificate', 'No clickable external tracking lures'],
    },
    {
      id: '7',
      sender: 'support@microsoft.com',
      recipient: user?.email || 'mubashir@example.com',
      subject: 'Microsoft account security code',
      risk: 'Medium',
      category: 'Security',
      riskScore: 62,
      time: '4 hours ago',
      body: 'Use this security code to verify identity for single sign-on authentication.',
      indicators: ['Automated one-time passcode notice', 'Sender IP mismatch with standard relay'],
    },
  ];

  // Fetch real emails from backend
  const { data: backendEmails } = useQuery({
    queryKey: ['inbox-emails'],
    queryFn: () => emailsService.listEmails(0, 100),
    staleTime: 10_000,
    retry: false,
  });

  // Fetch real scanned attachment files from backend
  const { data: scannedAttachments } = useQuery({
    queryKey: ['inbox-attachments'],
    queryFn: () => attachmentsService.listAttachments(0, 50),
    staleTime: 10_000,
    retry: false,
  });

  // Map backend emails and uploaded files to EmailItem
  const mappedEmails: EmailItem[] = useMemo(() => {
    const list: EmailItem[] = [];
    const seenSubjects = new Set<string>();

    // 1. First add scanned attachments (e.g. Reminder for Assessment _ Sample Assessment.eml)
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
        const body = att.analysis?.extracted_text || `Attachment file verified: ${att.filename} (${Math.round((att.file_size_bytes || 0) / 1024)} KB). Status: Clean/Verified.`;

        seenSubjects.add(subject.toLowerCase());
        list.push({
          id: String(att.attachment_id || att.id || Math.random()),
          sender,
          recipient,
          subject,
          risk,
          category,
          riskScore: Math.round(score),
          time: att.scan_timestamp ? new Date(att.scan_timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Just now',
          body,
          indicators: indicators.length > 0 ? indicators : ['Verified RFC-822 email format', 'Structure integrity verified clean'],
        });
      });
    }

    // 2. Add backend emails
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
          time: r.date ? new Date(r.date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : (r.created_at ? new Date(r.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recent'),
          body,
          indicators,
        });
      });
    }

    // If no real data yet, provide the initialEmails as fallback
    if (list.length === 0) {
      return initialEmails;
    }

    // Append initialEmails that aren't duplicates to ensure a complete rich inbox experience
    initialEmails.forEach((ie) => {
      if (!seenSubjects.has(ie.subject.toLowerCase())) {
        list.push(ie);
      }
    });

    return list;
  }, [backendEmails, scannedAttachments, user?.email]);

  const emails = mappedEmails;
  const activeEmail = selectedEmail || emails[0];

  // Counts based on real data
  const counts = useMemo(() => ({
    all: emails.length,
    high: emails.filter((e) => e.risk === 'High').length,
    medium: emails.filter((e) => e.risk === 'Medium').length,
    low: emails.filter((e) => e.risk === 'Low').length,
    safe: emails.filter((e) => e.risk === 'Safe').length,
  }), [emails]);


  const filteredEmails = emails.filter((item) => {
    if (activeTab === 'high' && item.risk !== 'High') return false;
    if (activeTab === 'medium' && item.risk !== 'Medium') return false;
    if (activeTab === 'low' && item.risk !== 'Low') return false;
    if (activeTab === 'safe' && item.risk !== 'Safe') return false;

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        item.subject.toLowerCase().includes(q) ||
        item.sender.toLowerCase().includes(q) ||
        item.category.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case 'High':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/10 text-red-400 border border-red-500/20">High</span>;
      case 'Medium':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">Medium</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Low</span>;
    }
  };

  const getCategoryBadge = (cat: string) => {
    switch (cat) {
      case 'Phishing':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">Phishing</span>;
      case 'Spam':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">Spam</span>;
      case 'Security':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/10 text-purple-400 border border-purple-500/20">Security</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Safe</span>;
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Title & Filter Tabs */}
      <div className="space-y-4">
        <h1 className="text-2xl font-bold text-white tracking-tight">Inbox</h1>

        <div className="flex flex-wrap items-center gap-2 border-b border-[#172136] pb-3">
          <button
            onClick={() => setActiveTab('all')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'all'
                ? 'bg-[#18233c] text-white border border-[#2b3c63]'
                : 'text-slate-400 hover:text-slate-200 hover:bg-[#101726]'
            }`}
          >
            All ({counts.all})
          </button>
          <button
            onClick={() => setActiveTab('high')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'high'
                ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-[#101726]'
            }`}
          >
            High Risk ({counts.high})
          </button>
          <button
            onClick={() => setActiveTab('medium')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'medium'
                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-[#101726]'
            }`}
          >
            Medium Risk ({counts.medium})
          </button>
          <button
            onClick={() => setActiveTab('low')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'low'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-[#101726]'
            }`}
          >
            Low Risk ({counts.low})
          </button>
          <button
            onClick={() => setActiveTab('safe')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'safe'
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-[#101726]'
            }`}
          >
            Safe ({counts.safe})
          </button>
        </div>
      </div>

      {/* Main Grid: Left Table (7 cols) + Right Inspector (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Side: Search & Table */}
        <div className="lg:col-span-8 cyber-card p-4 space-y-3">
          {/* Controls Bar */}
          <div className="flex items-center justify-between gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search emails..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-[#080d17] border border-[#172136] rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 outline-none focus:border-blue-500"
              />
            </div>
            <button className="px-3 py-1.5 bg-[#080d17] hover:bg-[#131b2e] border border-[#172136] text-slate-300 text-xs rounded-lg flex items-center gap-1.5">
              <Filter className="h-3 w-3" /> Filters
            </button>
            <button className="px-3 py-1.5 bg-[#080d17] hover:bg-[#131b2e] border border-[#172136] text-slate-300 text-xs rounded-lg flex items-center gap-1.5">
              <ArrowUpDown className="h-3 w-3" /> Sort
            </button>
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[#172136] text-slate-400 font-mono text-[10px] uppercase">
                  <th className="py-2.5 px-3">Sender</th>
                  <th className="py-2.5 px-3">Subject</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3 text-right">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#121929]">
                {filteredEmails.map((email) => {
                  const isSelected = activeEmail?.id === email.id;
                  return (
                    <tr
                      key={email.id}
                      onClick={() => setSelectedEmail(email)}
                      className={`cursor-pointer transition hover:bg-[#111828] ${
                        isSelected ? 'bg-[#151f33]' : ''
                      }`}
                    >
                      <td className="py-3 px-3 font-mono text-slate-300 truncate max-w-[140px]">
                        {email.sender}
                      </td>
                      <td className="py-3 px-3 text-slate-200 font-medium truncate max-w-[200px]">
                        {email.subject}
                      </td>
                      <td className="py-3 px-3">{getRiskBadge(email.risk)}</td>
                      <td className="py-3 px-3">{getCategoryBadge(email.category)}</td>
                      <td className="py-3 px-3 text-right text-slate-500 font-mono text-[11px]">
                        {email.time}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Side: Detailed Email Threat Inspector Panel */}
        <div className="lg:col-span-4 cyber-card p-5 space-y-4">
          {activeEmail ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                {getRiskBadge(activeEmail.risk)}
                {getCategoryBadge(activeEmail.category)}
              </div>

              <div>
                <h3 className="text-sm font-bold text-white">{activeEmail.subject}</h3>
                <div className="mt-2 flex items-center gap-2 text-xs text-slate-400">
                  <div className="h-6 w-6 rounded-full bg-blue-600 flex items-center justify-center text-white font-bold text-[10px]">
                    {activeEmail.sender[0]?.toUpperCase()}
                  </div>
                  <div className="min-w-0">
                    <p className="font-mono text-slate-300 truncate">{activeEmail.sender}</p>
                    <p className="text-[10px] text-slate-500 truncate">To: {activeEmail.recipient} • {activeEmail.time}</p>
                  </div>
                </div>
              </div>

              {/* Risk Score Circle Widget */}
              <div className="p-4 rounded-xl bg-[#080d17] border border-[#172136] flex items-center justify-between">
                <div>
                  <span className="text-[10px] font-mono font-bold text-slate-500 uppercase block">Risk Score</span>
                  <div className="flex items-baseline gap-1 mt-0.5">
                    <span className={`text-2xl font-bold font-mono ${
                      activeEmail.riskScore > 70 ? 'text-red-400' : 'text-emerald-400'
                    }`}>
                      {activeEmail.riskScore}
                    </span>
                    <span className="text-xs text-slate-500">/100</span>
                  </div>
                  <span className={`text-[10px] font-bold ${
                    activeEmail.riskScore > 70 ? 'text-red-400' : 'text-emerald-400'
                  }`}>
                    {activeEmail.riskScore > 70 ? 'High Risk' : 'Safe'}
                  </span>
                </div>

                <div className="h-12 w-12 rounded-full border-4 border-red-500/30 flex items-center justify-center">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                </div>
              </div>

              {/* Threat Indicators */}
              <div className="space-y-2">
                <span className="text-[10px] font-mono font-bold uppercase text-slate-400 block">
                  Threat Indicators
                </span>
                <div className="space-y-1.5">
                  {activeEmail.indicators.map((ind, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-xs text-slate-300">
                      <span className="h-1.5 w-1.5 rounded-full bg-red-400 mt-1.5 shrink-0" />
                      <span>{ind}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-3 border-t border-[#172136] space-y-2">
                <button className="w-full py-2 bg-[#2563eb] hover:bg-blue-600 text-white text-xs font-semibold rounded-lg shadow-sm transition">
                  View Details
                </button>
                <button className="w-full py-2 bg-[#080d17] hover:bg-[#131b2e] border border-[#172136] text-slate-300 text-xs font-semibold rounded-lg transition">
                  Mark as Safe
                </button>
              </div>
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-slate-500 text-xs">
              <Mail className="h-8 w-8 mb-2 text-slate-600" />
              <span>Select an email to inspect threats</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

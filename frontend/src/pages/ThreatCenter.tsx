import React, { useState } from 'react';
import {
  AlertTriangle,
  Search,
  CheckCircle2,
  TrendingDown,
  TrendingUp,
  Clock,
  Eye
} from 'lucide-react';
import {
  AreaChart,
  Area,
  ResponsiveContainer,
  Tooltip
} from 'recharts';

export const ThreatCenter: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'all' | 'high' | 'investigating' | 'resolved' | 'fp'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const chartData = [
    { day: 'Mon', threats: 120 },
    { day: 'Tue', threats: 180 },
    { day: 'Wed', threats: 140 },
    { day: 'Thu', threats: 240 },
    { day: 'Fri', threats: 320 },
    { day: 'Sat', threats: 210 },
    { day: 'Sun', threats: 290 },
  ];

  const threats = [
    {
      id: 1,
      title: 'Phishing Campaign - PayPal Spoof',
      risk: 'High',
      category: 'Phishing',
      status: 'Under Investigation',
      time: '2 min ago',
    },
    {
      id: 2,
      title: 'Malware Attachment - Invoice.pdf',
      risk: 'High',
      category: 'Malware',
      status: 'Under Investigation',
      time: '15 min ago',
    },
    {
      id: 3,
      title: 'Suspicious Login Attempt',
      risk: 'Medium',
      category: 'Account Takeover',
      status: 'Investigating',
      time: '1 hour ago',
    },
    {
      id: 4,
      title: 'BEC - CEO Impersonation',
      risk: 'High',
      category: 'BEC',
      status: 'Under Investigation',
      time: '2 hours ago',
    },
    {
      id: 5,
      title: 'Spam Campaign - Crypto Scams',
      risk: 'Low',
      category: 'Spam',
      status: 'Resolved',
      time: '3 hours ago',
    },
  ];

  const topThreatTypes = [
    { name: 'Phishing', percentage: 45, color: '#3b82f6' },
    { name: 'Malware', percentage: 25, color: '#ec4899' },
    { name: 'Account Takeover', percentage: 15, color: '#f59e0b' },
    { name: 'BEC', percentage: 10, color: '#8b5cf6' },
    { name: 'Spam', percentage: 5, color: '#06b6d4' },
  ];

  return (
    <div className="space-y-6 pb-12">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Threat Center</h1>
        <p className="text-xs text-slate-400 mt-1">
          Monitor and investigate security threats across your organization.
        </p>
      </div>

      {/* 4 KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="cyber-card p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Total Threats</span>
            <AlertTriangle className="h-4 w-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">1,248</div>
          <div className="flex items-center gap-1 text-emerald-400 text-[10px] font-semibold">
            <TrendingDown className="h-3 w-3" />
            <span>-12%</span>
          </div>
        </div>

        <div className="cyber-card p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>High Risk</span>
            <AlertTriangle className="h-4 w-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400">142</div>
          <div className="flex items-center gap-1 text-red-400 text-[10px] font-semibold">
            <TrendingUp className="h-3 w-3" />
            <span>+5%</span>
          </div>
        </div>

        <div className="cyber-card p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Under Investigation</span>
            <Clock className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">28</div>
          <div className="flex items-center gap-1 text-amber-400 text-[10px] font-semibold">
            <TrendingDown className="h-3 w-3" />
            <span>-15%</span>
          </div>
        </div>

        <div className="cyber-card p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Resolved</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">1,078</div>
          <div className="flex items-center gap-1 text-emerald-400 text-[10px] font-semibold">
            <TrendingUp className="h-3 w-3" />
            <span>+20%</span>
          </div>
        </div>
      </div>

      {/* Threat Overview Graph & Top Threat Types */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 cyber-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white">Threat Overview</h3>
            <span className="text-[11px] text-slate-500 font-mono">Last 7 days</span>
          </div>

          <div className="h-48 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0d1322',
                    borderColor: '#1e2c47',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Area type="monotone" dataKey="threats" stroke="#ef4444" fillOpacity={1} fill="url(#colorThreats)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="lg:col-span-4 cyber-card p-5 space-y-4 flex flex-col justify-between">
          <h3 className="text-sm font-bold text-white">Top Threat Types</h3>

          <div className="space-y-3">
            {topThreatTypes.map((item) => (
              <div key={item.name} className="space-y-1">
                <div className="flex justify-between text-xs text-slate-300">
                  <span>{item.name}</span>
                  <span className="font-mono">{item.percentage}%</span>
                </div>
                <div className="w-full bg-[#080d17] h-1.5 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${item.percentage}%`, backgroundColor: item.color }}
                  />
                </div>
              </div>
            ))}
          </div>

          <button className="w-full py-2 bg-[#080d17] hover:bg-[#131b2e] border border-[#172136] text-slate-300 text-xs font-semibold rounded-lg transition">
            View Full Report
          </button>
        </div>
      </div>

      {/* Threat Table */}
      <div className="cyber-card p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            {[
              { label: 'All Threats', val: 'all' },
              { label: 'High Risk', val: 'high' },
              { label: 'Under Investigation', val: 'investigating' },
              { label: 'Resolved', val: 'resolved' },
              { label: 'False Positive', val: 'fp' }
            ].map((tab) => (
              <button
                key={tab.val}
                onClick={() => setActiveTab(tab.val as any)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                  activeTab === tab.val
                    ? 'bg-[#18233c] text-white border border-[#2b3c63]'
                    : 'bg-[#080d17] hover:bg-[#131b2e] text-slate-300 border border-[#172136]'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="relative min-w-[200px]">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search threats..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#080d17] border border-[#172136] rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 outline-none focus:border-blue-500"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#172136] text-slate-400 font-mono text-[10px] uppercase">
                <th className="py-2.5 px-3">Threat</th>
                <th className="py-2.5 px-3">Risk Level</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Detected</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#121929]">
              {threats
                .filter((t) => {
                  if (activeTab === 'high' && t.risk !== 'High') return false;
                  if (activeTab === 'investigating' && !t.status.includes('Investigat')) return false;
                  if (activeTab === 'resolved' && t.status !== 'Resolved') return false;
                  if (searchQuery) {
                    const q = searchQuery.toLowerCase();
                    return t.title.toLowerCase().includes(q) || t.category.toLowerCase().includes(q);
                  }
                  return true;
                })
                .map((t) => (
                <tr key={t.id} className="hover:bg-[#111828] transition">
                  <td className="py-3 px-3 font-semibold text-slate-200">{t.title}</td>
                  <td className="py-3 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      t.risk === 'High' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    }`}>
                      {t.risk}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-slate-300 font-mono">{t.category}</td>
                  <td className="py-3 px-3">
                    <span className="text-amber-400 text-xs font-mono">{t.status}</span>
                  </td>
                  <td className="py-3 px-3 text-slate-500 font-mono text-[11px]">{t.time}</td>
                  <td className="py-3 px-3 text-right">
                    <button className="p-1 hover:text-blue-400 text-slate-400">
                      <Eye className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

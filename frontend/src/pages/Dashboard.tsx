import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { dashboardService } from '../services/dashboard';
import { emailsService } from '../services/emails';
import { incidentsService } from '../services/incidents';
import { Link } from 'react-router-dom';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts';
import { 
  Shield, AlertTriangle, Clock, BarChart3, Mail, 
  ExternalLink, ServerCrash
} from 'lucide-react';
import { Loader, CardSkeleton } from '../components/Loader';

const VERDICT_COLORS = {
  SAFE: '#10b981',
  SUSPICIOUS: '#f59e0b',
  SPAM: '#f97316',
  BEC: '#a855f7',
  MALWARE: '#ef4444',
  PHISHING: '#ef4444'
};

export const Dashboard: React.FC = () => {
  // Query 1: Overview
  const { data: overview, isLoading: overLoading, error: overError } = useQuery({
    queryKey: ['dashboard', 'overview'],
    queryFn: dashboardService.getOverview,
    refetchInterval: 30000 // Poll every 30 seconds
  });

  // Query 2: Threats (Trends and chart datasets)
  const { data: threats, isLoading: threatsLoading } = useQuery({
    queryKey: ['dashboard', 'threats'],
    queryFn: dashboardService.getThreats,
    refetchInterval: 30000
  });

  // Query 3: Recent Emails
  const { data: recentEmails, isLoading: emailsLoading } = useQuery({
    queryKey: ['emails', 'recent'],
    queryFn: () => emailsService.listEmails(0, 5),
    refetchInterval: 20000
  });

  // Query 4: Recent Incidents
  const { data: recentIncidents, isLoading: incsLoading } = useQuery({
    queryKey: ['incidents', 'recent'],
    queryFn: () => incidentsService.listIncidents(0, 5),
    refetchInterval: 20000
  });

  if (overLoading || threatsLoading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
        </div>
        <div className="h-96 bg-slate-900/60 rounded-xl border border-slate-800 flex items-center justify-center">
          <Loader />
        </div>
      </div>
    );
  }

  if (overError) {
    return (
      <div className="flex flex-col items-center justify-center p-12 bg-slate-900 border border-slate-800 rounded-xl text-center max-w-xl mx-auto my-12">
        <ServerCrash className="h-12 w-12 text-red-500 mb-4 animate-bounce" />
        <h2 className="text-xl font-bold text-slate-100 mb-2">Observability Sync Loss</h2>
        <p className="text-sm text-slate-400 mb-6">
          Could not communicate with the GuardianMail AI security backend core APIs. Verify the backend service state.
        </p>
      </div>
    );
  }

  // Format Recharts Pie data
  const severityData = threats?.severity_distribution ? Object.entries(threats.severity_distribution).map(([name, value]) => ({
    name,
    value
  })) : [];

  const trendData = threats?.daily_threat_trends || [];

  return (
    <div className="space-y-6">
      {/* Title Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-50 tracking-tight">Security Command Console</h1>
          <p className="text-xs text-slate-400">Real-time threat feeds and system telemetry status</p>
        </div>
        <div className="flex items-center gap-2 text-xs bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg text-slate-400 font-semibold">
          <Clock className="h-3.5 w-3.5 text-cyan-400" />
          Live Threat Sync: Active
        </div>
      </div>

      {/* Grid: Top Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Protection Card */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl relative overflow-hidden shadow-lg">
          <div className="absolute right-4 top-4 h-9 w-9 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400 border border-emerald-500/20">
            <Shield className="h-5 w-5" />
          </div>
          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Protection Factor</span>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-100">{overview?.avg_protection_score ?? 100}%</span>
            <span className="text-xs text-emerald-400 font-bold">Stable</span>
          </div>
          <p className="mt-2 text-[10px] text-slate-500">Overall defense readiness rating</p>
        </div>

        {/* Total Emails Card */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl relative overflow-hidden shadow-lg">
          <div className="absolute right-4 top-4 h-9 w-9 rounded-lg bg-cyan-500/10 flex items-center justify-center text-cyan-400 border border-cyan-500/20">
            <Mail className="h-5 w-5" />
          </div>
          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Ingested Scans</span>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-100">{overview?.total_emails ?? 0}</span>
            <span className="text-xs text-cyan-400 font-bold">Total</span>
          </div>
          <p className="mt-2 text-[10px] text-slate-500">Total email files parsed dynamically</p>
        </div>

        {/* Threat Alert Card */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl relative overflow-hidden shadow-lg">
          <div className="absolute right-4 top-4 h-9 w-9 rounded-lg bg-red-500/10 flex items-center justify-center text-red-400 border border-red-500/20">
            <AlertTriangle className="h-5 w-5 animate-pulse" />
          </div>
          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Identified Attacks</span>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-100">{overview?.phishing_emails ?? 0}</span>
            <span className="text-xs text-red-500 font-bold">Risk</span>
          </div>
          <p className="mt-2 text-[10px] text-slate-500">Confirmed phishing / malware verdicts</p>
        </div>

        {/* Active Incidents Card */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl relative overflow-hidden shadow-lg">
          <div className="absolute right-4 top-4 h-9 w-9 rounded-lg bg-amber-500/10 flex items-center justify-center text-amber-400 border border-amber-500/20">
            <Clock className="h-5 w-5" />
          </div>
          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Active Incidents</span>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-100">{overview?.open_incidents ?? 0}</span>
            <span className="text-xs text-amber-400 font-bold">Unresolved</span>
          </div>
          <p className="mt-2 text-[10px] text-slate-500">SOC tickets awaiting containment checks</p>
        </div>
      </div>

      {/* Grid: Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scans Trend Chart */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg flex flex-col space-y-4">
          <div className="flex items-center gap-2">
            <BarChart3 className="h-4.5 w-4.5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200">Incident Trend Latency</h3>
          </div>
          <div className="h-64 w-full">
            {trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.2}/>
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                  <XAxis dataKey="date" stroke="#64748b" fontSize={9} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={9} tickLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f8fafc', fontSize: 11 }} />
                  <Area type="monotone" dataKey="count" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#colorCount)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                Insufficient trend logs to render graph.
              </div>
            )}
          </div>
        </div>

        {/* Severity Distribution Pie */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg flex flex-col space-y-4">
          <div className="flex items-center gap-2">
            <Shield className="h-4.5 w-4.5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200">Risk Profile Breakdown</h3>
          </div>
          <div className="h-64 w-full flex items-center justify-center">
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => {
                      const color = VERDICT_COLORS[entry.name as keyof typeof VERDICT_COLORS] || '#64748b';
                      return <Cell key={`cell-${index}`} fill={color} />;
                    })}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f8fafc', fontSize: 11 }} />
                  <Legend wrapperStyle={{ fontSize: 10, color: '#94a3b8' }} layout="horizontal" />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                No threat logs registered.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Grid: Lists Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Email Scans */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg flex flex-col space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-bold text-slate-200">Recent Forensics Scans</h3>
            <Link to="/emails" className="text-xs text-cyan-500 hover:text-cyan-400 flex items-center gap-1">
              View all <ExternalLink className="h-3 w-3" />
            </Link>
          </div>
          <div className="space-y-3 flex-1">
            {emailsLoading ? (
              <Loader />
            ) : recentEmails && recentEmails.length > 0 ? (
              recentEmails.map((email) => {
                const verdict = email.analysis?.verdict || 'SAFE';
                const verdictColor = VERDICT_COLORS[verdict as keyof typeof VERDICT_COLORS] || '#64748b';
                return (
                  <div key={email.id} className="flex justify-between items-center p-3 bg-slate-950/40 border border-slate-800 rounded-xl hover:border-slate-700 transition">
                    <div className="overflow-hidden space-y-0.5">
                      <h4 className="text-xs font-semibold text-slate-200 truncate pr-4">{email.subject}</h4>
                      <p className="text-[10px] text-slate-500 truncate">From: {email.from_address}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[9px] font-bold px-2 py-0.5 rounded-full" style={{ backgroundColor: `${verdictColor}15`, color: verdictColor, border: `1px solid ${verdictColor}25` }}>
                        {verdict}
                      </span>
                      <Link to={`/emails/${email.id}`} className="text-slate-500 hover:text-slate-200">
                        <ExternalLink className="h-3.5 w-3.5" />
                      </Link>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="py-12 text-center text-xs text-slate-500">No scanned logs found. Drag-and-drop an EML file to analyze.</div>
            )}
          </div>
        </div>

        {/* Recent Incidents */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg flex flex-col space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-bold text-slate-200">Active SOC Incidents</h3>
            <Link to="/incidents" className="text-xs text-cyan-500 hover:text-cyan-400 flex items-center gap-1">
              Incident Center <ExternalLink className="h-3 w-3" />
            </Link>
          </div>
          <div className="space-y-3 flex-1">
            {incsLoading ? (
              <Loader />
            ) : recentIncidents && recentIncidents.length > 0 ? (
              recentIncidents.map((inc) => {
                const isCritical = inc.threat_severity === 'CRITICAL' || inc.threat_severity === 'HIGH';
                return (
                  <div key={inc.id} className="flex justify-between items-center p-3 bg-slate-950/40 border border-slate-800 rounded-xl hover:border-slate-700 transition">
                    <div className="overflow-hidden space-y-0.5">
                      <div className="flex items-center gap-1.5">
                        <span className="text-xs font-bold text-slate-200">{inc.incident_id}</span>
                        <span className={`text-[8px] font-bold uppercase px-1.5 py-0.2 rounded-full ${isCritical ? 'bg-red-500/10 text-red-500' : 'bg-amber-500/10 text-amber-500'}`}>
                          {inc.threat_severity}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-500">Status: <span className="text-slate-350">{inc.status}</span></p>
                    </div>
                    <div>
                      <Link to={`/incidents/${inc.id}`} className="text-slate-500 hover:text-slate-200">
                        <ExternalLink className="h-3.5 w-3.5" />
                      </Link>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="py-12 text-center text-xs text-slate-500">No active incidents reported.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

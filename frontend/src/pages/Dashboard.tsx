import React, { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  RefreshCw,
  Sparkles,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { useAuth } from '../contexts/AuthContext';
import { dashboardService } from '../services/dashboard';
import { EmptyState } from '../components/ui/EmptyState';
import { ErrorState } from '../components/ui/ErrorState';
import { SkeletonCard } from '../components/ui/Skeleton';
import { getErrorMessage } from '../utils/errors';

interface DashboardOverview {
  total_emails?: number;
  safe_emails?: number;
  suspicious_emails?: number;
  phishing_emails?: number;
  spam_emails?: number;
  bec_emails?: number;
  malicious_attachments?: number;
  malicious_urls?: number;
  resolved_incidents?: number;
  open_incidents?: number;
  complaint_drafts?: number;
  reports_generated?: number;
  avg_protection_score?: number;
  avg_risk_score?: number;
  detection_accuracy?: number;
}

interface DashboardThreats {
  severity_distribution?: Record<string, number>;
  daily_threat_trends?: Array<{ date?: string; day?: string; count?: number }>;
  top_threat_campaigns?: Array<{ campaign_domain?: string; volume?: number; risk?: number }>;
  attack_categories?: Record<string, number>;
  average_detection_confidence?: number;
}

interface DashboardIncidents {
  status_distribution?: Record<string, number>;
  severity_distribution?: Record<string, number>;
  average_resolution_hours?: number;
  evidence_packages_generated?: number;
  complaint_drafts_created?: number;
}

type TimeRange = '24h' | '7d' | '30d';

const CATEGORY_COLORS = ['#3b82f6', '#ef4444', '#f59e0b', '#06b6d4', '#22c55e', '#a855f7', '#64748b'];

const toNumber = (value: unknown): number => (typeof value === 'number' && Number.isFinite(value) ? value : 0);

const formatNumber = (value: unknown): string => new Intl.NumberFormat('en-US').format(toNumber(value));

const formatScore = (value: unknown): string => toNumber(value).toFixed(1).replace(/\.0$/, '');

const getScoreLabel = (score: number, hasData: boolean): string => {
  if (!hasData) return 'No scan data';
  if (score >= 90) return 'Excellent';
  if (score >= 75) return 'Good';
  if (score >= 50) return 'Fair';
  return 'At Risk';
};

const getScoreClass = (score: number, hasData: boolean): string => {
  if (!hasData) return 'text-slate-400 bg-slate-500/10 border-slate-500/20';
  if (score >= 75) return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
  if (score >= 50) return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
  return 'text-red-400 bg-red-500/10 border-red-500/20';
};

const formatTrendLabel = (rawDate: string | undefined): string => {
  if (!rawDate) return 'Unknown';
  const date = new Date(rawDate);
  if (Number.isNaN(date.getTime())) return rawDate.slice(0, 10);
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
};

const withinRange = (rawDate: string | undefined, range: TimeRange): boolean => {
  if (!rawDate || range === '30d') return true;
  const date = new Date(rawDate);
  if (Number.isNaN(date.getTime())) return true;
  const days = range === '24h' ? 1 : 7;
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);
  return date >= cutoff;
};

export const Dashboard: React.FC = () => {
  const { user } = useAuth();
  const userName = user?.full_name?.split(' ')[0] || user?.email?.split('@')[0] || 'Analyst';
  const [timeRange, setTimeRange] = useState<TimeRange>('7d');

  const overviewQuery = useQuery<DashboardOverview>({
    queryKey: ['dashboard-overview'],
    queryFn: () => dashboardService.getOverview(),
    staleTime: 60_000,
  });

  const threatsQuery = useQuery<DashboardThreats>({
    queryKey: ['dashboard-threats'],
    queryFn: () => dashboardService.getThreats(),
    staleTime: 60_000,
  });

  const incidentsQuery = useQuery<DashboardIncidents>({
    queryKey: ['dashboard-incidents'],
    queryFn: () => dashboardService.getIncidents(),
    staleTime: 60_000,
  });

  const overview = overviewQuery.data ?? {};
  const threats = threatsQuery.data ?? {};
  const incidents = incidentsQuery.data ?? {};

  const isLoading = overviewQuery.isLoading || threatsQuery.isLoading || incidentsQuery.isLoading;
  const isRefreshing = overviewQuery.isFetching || threatsQuery.isFetching || incidentsQuery.isFetching;
  const firstError = overviewQuery.error || threatsQuery.error || incidentsQuery.error;

  const totalEmails = toNumber(overview.total_emails);
  const suspiciousEmails = toNumber(overview.suspicious_emails);
  const phishingEmails = toNumber(overview.phishing_emails);
  const spamEmails = toNumber(overview.spam_emails);
  const becEmails = toNumber(overview.bec_emails);
  const openIncidents = toNumber(overview.open_incidents);
  const resolvedIncidents = toNumber(overview.resolved_incidents);
  const maliciousUrls = toNumber(overview.malicious_urls);
  const maliciousAttachments = toNumber(overview.malicious_attachments);
  const protectionScore = toNumber(overview.avg_protection_score);
  const hasScanData = totalEmails > 0;
  const threatSignals = phishingEmails + spamEmails + becEmails + maliciousUrls + maliciousAttachments;

  const chartData = useMemo(() => {
    return (threats.daily_threat_trends ?? [])
      .filter((item) => withinRange(item.date ?? item.day, timeRange))
      .map((item) => ({
        day: formatTrendLabel(item.date ?? item.day),
        threats: toNumber(item.count),
      }));
  }, [threats.daily_threat_trends, timeRange]);

  const threatCategoryData = useMemo(() => {
    const categories = threats.attack_categories && Object.keys(threats.attack_categories).length > 0
      ? threats.attack_categories
      : threats.severity_distribution ?? {};

    return Object.entries(categories)
      .filter(([, value]) => toNumber(value) > 0)
      .map(([name, value], index) => ({
        name,
        value: toNumber(value),
        color: CATEGORY_COLORS[index % CATEGORY_COLORS.length],
      }));
  }, [threats.attack_categories, threats.severity_distribution]);

  const totalCategorySignals = threatCategoryData.reduce((sum, item) => sum + item.value, 0);

  const recommendations = useMemo(() => {
    const items: Array<{ title: string; body: string; to: string }> = [];

    if (!hasScanData) {
      items.push({
        title: 'Connect scan telemetry',
        body: 'No email scan data is available from the backend yet. Connect a mailbox or run the backend ingestion workflow.',
        to: '/inbox',
      });
    }

    if (openIncidents > 0) {
      items.push({
        title: 'Review open investigations',
        body: `${openIncidents} incident${openIncidents === 1 ? '' : 's'} need analyst review before any containment action.`,
        to: '/investigations',
      });
    }

    if (maliciousUrls > 0) {
      items.push({
        title: 'Inspect malicious links',
        body: `${maliciousUrls} malicious URL signal${maliciousUrls === 1 ? '' : 's'} were reported by the backend.`,
        to: '/links',
      });
    }

    if (maliciousAttachments > 0) {
      items.push({
        title: 'Review attachment findings',
        body: `${maliciousAttachments} attachment finding${maliciousAttachments === 1 ? '' : 's'} require evidence review.`,
        to: '/attachments',
      });
    }

    if (items.length === 0) {
      items.push({
        title: 'Maintain monitoring posture',
        body: 'No immediate analyst recommendations are available from current backend metrics.',
        to: '/security-score',
      });
    }

    return items.slice(0, 3);
  }, [hasScanData, maliciousAttachments, maliciousUrls, openIncidents]);

  const refreshDashboard = () => {
    void Promise.all([
      overviewQuery.refetch(),
      threatsQuery.refetch(),
      incidentsQuery.refetch(),
    ]);
  };

  const kpiCards = [
    {
      label: 'Protection Score',
      value: hasScanData ? formatScore(protectionScore) : '--',
      suffix: hasScanData ? '/100' : '',
      status: getScoreLabel(protectionScore, hasScanData),
      className: getScoreClass(protectionScore, hasScanData),
    },
    {
      label: 'Emails Scanned',
      value: formatNumber(totalEmails),
      status: 'Backend total',
      className: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
    },
    {
      label: 'Threats Detected',
      value: formatNumber(threatSignals),
      status: 'Signals from analysis',
      className: threatSignals > 0 ? 'text-red-400 bg-red-500/10 border-red-500/20' : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    },
    {
      label: 'Suspicious Emails',
      value: formatNumber(suspiciousEmails),
      status: 'Needs triage',
      className: suspiciousEmails > 0 ? 'text-amber-400 bg-amber-500/10 border-amber-500/20' : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    },
    {
      label: 'Open Investigations',
      value: formatNumber(openIncidents),
      status: `${formatNumber(resolvedIncidents)} resolved`,
      className: openIncidents > 0 ? 'text-amber-400 bg-amber-500/10 border-amber-500/20' : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    },
  ];

  return (
    <div className="space-y-6 pb-12">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight text-white">
            Welcome back, {userName}
          </h1>
          <p className="mt-1 text-xs text-slate-400">
            Live security posture from the GuardianMail AI backend.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={refreshDashboard}
            disabled={isRefreshing}
            className="flex items-center gap-2 rounded-lg bg-[#2563eb] px-4 py-2 text-xs font-semibold text-white shadow-md shadow-blue-600/20 transition hover:bg-blue-600 active:scale-95 disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>{isRefreshing ? 'Refreshing...' : 'Refresh Metrics'}</span>
          </button>

          <select
            value={timeRange}
            onChange={(event) => setTimeRange(event.target.value as TimeRange)}
            className="rounded-lg border border-[#1e2c47] bg-[#0e1627] px-3 py-2 text-xs text-slate-300 outline-none transition hover:border-slate-600 focus:border-blue-500"
            aria-label="Threat activity time range"
          >
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
          </select>
        </div>
      </div>

      {firstError && (
        <ErrorState
          message={getErrorMessage(firstError)}
          onRetry={refreshDashboard}
          variant={overviewQuery.error ? 'auth' : 'default'}
          className="cyber-card"
        />
      )}

      {isLoading ? (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
          {Array.from({ length: 5 }).map((_, index) => (
            <SkeletonCard key={index} />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
          {kpiCards.map((card) => (
            <div key={card.label} className="cyber-card space-y-2 p-4">
              <span className="block text-[11px] font-semibold text-slate-400">{card.label}</span>
              <div className="flex items-baseline gap-2">
                <span className="font-mono text-2xl font-bold text-white">{card.value}</span>
                {card.suffix && <span className="text-xs text-slate-500">{card.suffix}</span>}
              </div>
              <div className={`inline-flex rounded border px-2 py-0.5 text-[10px] font-bold ${card.className}`}>
                {card.status}
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="cyber-card space-y-4 p-5 lg:col-span-7">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white">Threat Activity</h3>
            <span className="font-mono text-[11px] text-slate-500">Backend trend feed</span>
          </div>

          {chartData.length > 0 ? (
            <div className="h-64 min-h-64 w-full">
              <ResponsiveContainer width="100%" height="100%" minWidth={320} minHeight={240}>
                <BarChart data={chartData} barCategoryGap={16}>
                  <XAxis dataKey="day" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0d1322',
                      borderColor: '#1e2c47',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="threats" name="Events" fill="#3b82f6" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState
              variant="threats"
              title="No threat activity yet"
              description="Threat trend data will appear after the backend records scanned email activity."
              className="min-h-64"
            />
          )}
        </div>

        <div className="cyber-card flex flex-col justify-between space-y-4 p-5 lg:col-span-5">
          <h3 className="text-sm font-bold text-white">Threat Distribution</h3>

          {threatCategoryData.length > 0 ? (
            <>
              <div className="relative flex h-48 min-h-48 items-center justify-center">
                <ResponsiveContainer width="100%" height="100%" minWidth={260} minHeight={190}>
                  <PieChart>
                    <Pie
                      data={threatCategoryData}
                      cx="50%"
                      cy="50%"
                      innerRadius={55}
                      outerRadius={75}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {threatCategoryData.map((entry) => (
                        <Cell key={entry.name} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0d1322',
                        borderColor: '#1e2c47',
                        borderRadius: '8px',
                        fontSize: '12px',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                  <span className="font-mono text-lg font-bold text-white">{formatNumber(totalCategorySignals)}</span>
                  <span className="text-[10px] font-semibold text-slate-400">Signals</span>
                </div>
              </div>

              <div className="space-y-1.5 border-t border-[#172136] pt-2">
                {threatCategoryData.map((item) => (
                  <Link
                    key={item.name}
                    to={`/threats?category=${encodeURIComponent(item.name)}`}
                    className="flex items-center justify-between rounded px-2 py-1 text-xs transition hover:bg-[#101728]"
                  >
                    <span className="flex items-center gap-2 text-slate-300">
                      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} />
                      {item.name}
                    </span>
                    <span className="font-mono font-semibold text-slate-200">{formatNumber(item.value)}</span>
                  </Link>
                ))}
              </div>
            </>
          ) : (
            <EmptyState
              variant="threats"
              title="No threat categories"
              description="Category distribution is empty because the backend has not reported threat indicators."
              className="min-h-64"
            />
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="cyber-card space-y-3 p-5 lg:col-span-7">
          <div className="flex items-center justify-between border-b border-[#172136] pb-2">
            <h3 className="text-sm font-bold text-white">Campaign Signals</h3>
            <Link to="/threat-intelligence" className="flex items-center gap-1 text-xs font-semibold text-blue-400 hover:text-blue-300">
              View intelligence <ChevronRight className="h-3.5 w-3.5" />
            </Link>
          </div>

          {(threats.top_threat_campaigns ?? []).length > 0 ? (
            <div className="space-y-2">
              {(threats.top_threat_campaigns ?? []).map((campaign) => (
                <div
                  key={campaign.campaign_domain ?? 'unknown'}
                  className="flex items-center justify-between gap-3 rounded-lg border border-[#172136] bg-[#080d17] p-3"
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" />
                    <span className="truncate text-xs font-semibold text-slate-200">
                      {campaign.campaign_domain || 'unknown campaign'}
                    </span>
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    <span className="rounded border border-red-500/20 bg-red-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-red-400">
                      Risk {formatScore(campaign.risk)}
                    </span>
                    <span className="font-mono text-[10px] text-slate-500">{formatNumber(campaign.volume)} events</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              variant="threats"
              title="No campaign signals"
              description="The backend has not correlated scanned email activity into threat campaigns."
            />
          )}
        </div>

        <div className="cyber-card space-y-4 p-5 lg:col-span-5">
          <h3 className="border-b border-[#172136] pb-2 text-sm font-bold text-white">Security Status</h3>

          <div className="space-y-3">
            <StatusRow
              label="Email telemetry"
              value={hasScanData ? 'Active' : 'Not configured'}
              tone={hasScanData ? 'success' : 'warning'}
            />
            <StatusRow
              label="Open investigations"
              value={openIncidents > 0 ? `${openIncidents} pending` : 'Clear'}
              tone={openIncidents > 0 ? 'warning' : 'success'}
            />
            <StatusRow
              label="Evidence packages"
              value={formatNumber(incidents.evidence_packages_generated)}
              tone={toNumber(incidents.evidence_packages_generated) > 0 ? 'info' : 'neutral'}
            />
            <StatusRow
              label="Detection confidence"
              value={`${formatScore(threats.average_detection_confidence)}%`}
              tone={toNumber(threats.average_detection_confidence) >= 80 ? 'success' : 'neutral'}
            />
          </div>
        </div>
      </div>

      <div className="cyber-card space-y-3 p-5">
        <div className="flex items-center gap-2 text-blue-400">
          <Sparkles className="h-4 w-4" />
          <h3 className="text-sm font-bold text-white">Security Recommendations</h3>
        </div>
        <p className="text-xs leading-relaxed text-slate-400">
          Recommendations are advisory. Sensitive containment still requires backend policy evaluation, human authorization,
          controlled execution, and evidence verification.
        </p>
        <div className="grid gap-3 md:grid-cols-3">
          {recommendations.map((item) => (
            <Link key={item.title} to={item.to} className="rounded-lg border border-[#172136] bg-[#080d17] p-4 transition hover:border-blue-500/40 hover:bg-[#0d1524]">
              <div className="mb-2 flex items-center gap-2 text-xs font-bold text-white">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                {item.title}
              </div>
              <p className="text-[11px] leading-relaxed text-slate-400">{item.body}</p>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
};

interface StatusRowProps {
  label: string;
  value: string;
  tone: 'success' | 'warning' | 'info' | 'neutral';
}

const toneClasses: Record<StatusRowProps['tone'], string> = {
  success: 'text-emerald-400',
  warning: 'text-amber-400',
  info: 'text-blue-400',
  neutral: 'text-slate-400',
};

const dotClasses: Record<StatusRowProps['tone'], string> = {
  success: 'bg-emerald-400 shadow-emerald-400/50',
  warning: 'bg-amber-400 shadow-amber-400/50',
  info: 'bg-blue-400 shadow-blue-400/50',
  neutral: 'bg-slate-500 shadow-slate-500/30',
};

const StatusRow: React.FC<StatusRowProps> = ({ label, value, tone }) => (
  <div className="flex items-center justify-between rounded-lg border border-[#172136] bg-[#080d17] p-3.5">
    <div className="flex items-center gap-3">
      <span className={`h-2.5 w-2.5 shrink-0 rounded-full shadow-sm ${dotClasses[tone]}`} />
      <span className="text-xs font-semibold text-slate-200">{label}</span>
    </div>
    <span className={`font-mono text-xs font-bold ${toneClasses[tone]}`}>
      {value}
    </span>
  </div>
);

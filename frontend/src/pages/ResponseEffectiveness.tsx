import React, { useState, useEffect } from 'react';
import { 
  Activity, CheckCircle, Clock, 
  ThumbsUp, Info, Send, RotateCw, ShieldCheck, AlertCircle
} from 'lucide-react';
import { api } from '../services/api';

interface Outcome {
  outcome_id: string;
  decision_id: string;
  execution_id?: string;
  incident_id?: string;
  playbook_id?: string;
  playbook_name?: string;
  action: string;
  severity: string;
  risk_score: number;
  confidence_score: number;
  status: string;
  policy_id?: string;
  policy_version?: number;
  policy_decision_mode?: string;
  policy_decision_reason?: string;
  detection_at?: string;
  decision_created_at?: string;
  approved_at?: string;
  execution_started_at?: string;
  execution_completed_at?: string;
  feedback_status: 'UNCLASSIFIED' | 'REVIEWED';
  feedback_classification?: string;
  feedback_comment?: string;
  feedback_by?: string;
  feedback_at?: string;
  created_at: string;
}

interface AnalyticsOverview {
  total_outcomes: number;
  total_executions: number;
  mean_time_to_respond: number;
  mean_time_to_contain: number;
  mean_time_to_approve: number;
  mean_time_to_execute: number;
  success_rate: number;
  failure_rate: number;
  cancelled_rate: number;
  auto_response_percentage: number;
  human_approval_percentage: number;
  policy_denied_percentage: number;
  recommendation_acceptance_rate: number;
}

interface PolicyEffectiveness {
  policy_id: string;
  version: number;
  evaluations: number;
  allowed: number;
  human_approval: number;
  denied: number;
  successful_actions: number;
  failed_actions: number;
  analyst_accepted: number;
  analyst_rejected: number;
  false_positives: number;
}

export default function ResponseEffectiveness() {
  const [outcomes, setOutcomes] = useState<Outcome[]>([]);
  const [overview, setOverview] = useState<AnalyticsOverview | null>(null);
  const [policies, setPolicies] = useState<PolicyEffectiveness[]>([]);
  const [selectedOutcome, setSelectedOutcome] = useState<Outcome | null>(null);
  const [feedbackClass, setFeedbackClass] = useState('CORRECT_RESPONSE');
  const [feedbackComment, setFeedbackComment] = useState('');
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'outcomes' | 'policies'>('outcomes');
  const [page, setPage] = useState(1);
  const limit = 15;

  const fetchAnalytics = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [overviewRes, policiesRes, outcomesRes] = await Promise.all([
        api.get('/response-analytics/overview'),
        api.get('/response-analytics/policies'),
        api.get(`/response-analytics/outcomes?page=${page}&limit=${limit}`)
      ]);

      setOverview(overviewRes.data);
      setPolicies(policiesRes.data);
      setOutcomes(outcomesRes.data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to retrieve response effectiveness analytics.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, [page]);

  const submitFeedback = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedOutcome) return;

    try {
      setSubmitting(true);
      await api.post(`/response-analytics/outcomes/${selectedOutcome.outcome_id}/feedback`, {
        feedback_classification: feedbackClass,
        comment: feedbackComment
      });
      
      // Reset & Refresh
      setFeedbackComment('');
      setSelectedOutcome(null);
      await fetchAnalytics();
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Failed to submit feedback log.');
    } finally {
      setSubmitting(false);
    }
  };

  const formatDuration = (seconds: number) => {
    if (!seconds || seconds <= 0) return 'N/A';
    if (seconds < 60) return `${seconds.toFixed(1)}s`;
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}m ${secs}s`;
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'SUCCESS':
        return <span className="px-2 py-1 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Success</span>;
      case 'FAILED':
      case 'EXHAUSTED':
        return <span className="px-2 py-1 text-xs font-semibold rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20">Failed</span>;
      case 'DENIED':
        return <span className="px-2 py-1 text-xs font-semibold rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">Denied</span>;
      case 'PENDING_APPROVAL':
        return <span className="px-2 py-1 text-xs font-semibold rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">Awaiting Approval</span>;
      default:
        return <span className="px-2 py-1 text-xs font-semibold rounded-full bg-slate-500/10 text-slate-400 border border-slate-500/20">{status}</span>;
    }
  };

  return (
    <div className="p-6 space-y-6 text-slate-100 min-h-screen bg-slate-950">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight bg-gradient-to-r from-teal-400 to-emerald-400 bg-clip-text text-transparent">Response Effectiveness</h1>
          <p className="text-slate-400 text-sm mt-1">Measure security containment outcomes and analyze closed-loop operator feedback loop.</p>
        </div>
        <button 
          onClick={fetchAnalytics}
          className="flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 transition"
        >
          <RotateCw size={16} /> Refresh
        </button>
      </div>

      {error && (
        <div className="p-4 rounded border border-rose-500/30 bg-rose-500/10 text-rose-400 flex items-center gap-3">
          <AlertCircle size={20} />
          <span>{error}</span>
        </div>
      )}

      {/* Analytics Overview Cards */}
      {overview && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/50 backdrop-blur space-y-2">
            <div className="flex justify-between items-center text-slate-400">
              <span className="text-xs font-semibold uppercase tracking-wider">Mean Time to Respond (MTTR)</span>
              <Clock size={20} className="text-teal-400" />
            </div>
            <div className="text-2xl font-bold">{formatDuration(overview.mean_time_to_respond)}</div>
            <div className="text-xs text-slate-500">From detection to containment completion</div>
          </div>

          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/50 backdrop-blur space-y-2">
            <div className="flex justify-between items-center text-slate-400">
              <span className="text-xs font-semibold uppercase tracking-wider">Mean Time to Contain</span>
              <Activity size={20} className="text-emerald-400" />
            </div>
            <div className="text-2xl font-bold">{formatDuration(overview.mean_time_to_contain)}</div>
            <div className="text-xs text-slate-500">From orchestration request completion</div>
          </div>

          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/50 backdrop-blur space-y-2">
            <div className="flex justify-between items-center text-slate-400">
              <span className="text-xs font-semibold uppercase tracking-wider">SOAR Success Rate</span>
              <CheckCircle size={20} className="text-teal-400" />
            </div>
            <div className="text-2xl font-bold">{(overview.success_rate * 100).toFixed(1)}%</div>
            <div className="text-xs text-slate-500">Of dispatched playbook runs</div>
          </div>

          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/50 backdrop-blur space-y-2">
            <div className="flex justify-between items-center text-slate-400">
              <span className="text-xs font-semibold uppercase tracking-wider">Auto-Response Rate</span>
              <ShieldCheck size={20} className="text-emerald-400" />
            </div>
            <div className="text-2xl font-bold">{(overview.auto_response_percentage * 100).toFixed(1)}%</div>
            <div className="text-xs text-slate-500">Allowed without human review</div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-slate-850 gap-6">
        <button
          onClick={() => setActiveTab('outcomes')}
          className={`pb-3 font-semibold text-sm transition border-b-2 ${activeTab === 'outcomes' ? 'border-teal-400 text-teal-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
        >
          Response Outcomes Logs
        </button>
        <button
          onClick={() => setActiveTab('policies')}
          className={`pb-3 font-semibold text-sm transition border-b-2 ${activeTab === 'policies' ? 'border-teal-400 text-teal-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
        >
          Policy Version Tuning
        </button>
      </div>

      {/* Tab Contents */}
      {activeTab === 'outcomes' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Outcome Table */}
          <div className="lg:col-span-2 border border-slate-850 bg-slate-900/20 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-slate-850 bg-slate-900/40 flex justify-between items-center">
              <h2 className="font-semibold text-sm">Tracked Outcomes</h2>
              <span className="text-xs text-slate-500">Showing page {page}</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-850 text-slate-400 text-xs font-semibold bg-slate-950/40">
                    <th className="p-4">Action</th>
                    <th className="p-4">Status</th>
                    <th className="p-4">Mode</th>
                    <th className="p-4">Risk / Conf</th>
                    <th className="p-4">Feedback</th>
                    <th className="p-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-850 text-sm">
                  {loading ? (
                    <tr>
                      <td colSpan={6} className="p-8 text-center text-slate-500">Loading outcomes data...</td>
                    </tr>
                  ) : outcomes.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="p-8 text-center text-slate-500">No outcomes tracked yet.</td>
                    </tr>
                  ) : (
                    outcomes.map((ot) => (
                      <tr key={ot.outcome_id} className="hover:bg-slate-900/30 transition">
                        <td className="p-4">
                          <div className="font-medium text-slate-200">{ot.action}</div>
                          <div className="text-xs text-slate-500">{ot.playbook_name || 'No Playbook'}</div>
                        </td>
                        <td className="p-4">{getStatusBadge(ot.status)}</td>
                        <td className="p-4">
                          <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400">{ot.policy_decision_mode || 'N/A'}</span>
                        </td>
                        <td className="p-4">
                          <div className="text-xs">Risk: {ot.risk_score.toFixed(0)}</div>
                          <div className="text-xs text-slate-400">Conf: {ot.confidence_score.toFixed(0)}</div>
                        </td>
                        <td className="p-4">
                          {ot.feedback_status === 'REVIEWED' ? (
                            <span className="flex items-center gap-1.5 text-xs text-emerald-400 font-semibold">
                              <ThumbsUp size={12} /> {ot.feedback_classification}
                            </span>
                          ) : (
                            <span className="text-xs text-slate-500">Awaiting feedback</span>
                          )}
                        </td>
                        <td className="p-4 text-right">
                          <button
                            onClick={() => setSelectedOutcome(ot)}
                            className="px-3 py-1.5 text-xs font-semibold rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 transition"
                          >
                            Review
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="p-4 border-t border-slate-850 flex justify-between items-center text-xs">
              <button
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
                className="px-3 py-1.5 rounded border border-slate-850 hover:bg-slate-900 disabled:opacity-40 transition"
              >
                Previous Page
              </button>
              <button
                onClick={() => setPage(page + 1)}
                className="px-3 py-1.5 rounded border border-slate-850 hover:bg-slate-900 transition"
              >
                Next Page
              </button>
            </div>
          </div>

          {/* Feedback loop drawer */}
          <div className="border border-slate-850 bg-slate-900/20 rounded-xl overflow-hidden p-6 space-y-6">
            <h2 className="text-base font-bold text-slate-200">Feedback Loop</h2>
            
            {selectedOutcome ? (
              <form onSubmit={submitFeedback} className="space-y-4">
                <div className="space-y-1 p-4 rounded bg-slate-950 border border-slate-850 text-xs">
                  <div className="text-slate-400">Action: <span className="text-slate-200 font-bold">{selectedOutcome.action}</span></div>
                  <div className="text-slate-400">Outcome ID: <span className="text-slate-200">{selectedOutcome.outcome_id}</span></div>
                  <div className="text-slate-400">Policy Matched: <span className="text-slate-200 font-mono">{selectedOutcome.policy_id || 'Global Default'} v{selectedOutcome.policy_version || 1}</span></div>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-semibold text-slate-400 block">Outcome Classification</label>
                  <select
                    value={feedbackClass}
                    onChange={(e) => setFeedbackClass(e.target.value)}
                    className="w-full text-sm p-2 rounded border border-slate-800 bg-slate-950 focus:border-teal-400 transition"
                  >
                    <option value="CORRECT_RESPONSE">✓ Correct Response</option>
                    <option value="FALSE_POSITIVE">⚠ False Positive Activity</option>
                    <option value="INCORRECT_RESPONSE">✗ Incorrect Response Recommended</option>
                    <option value="INSUFFICIENT_EVIDENCE">⚠ Insufficient Evidence to fire</option>
                    <option value="POLICY_TOO_STRICT">🛡 Policy rules too strict</option>
                    <option value="POLICY_TOO_PERMISSIVE">🛡 Policy rules too permissive</option>
                    <option value="PLAYBOOK_FAILURE">✗ Playbook workflow failure</option>
                  </select>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-semibold text-slate-400 block">Comments</label>
                  <textarea
                    value={feedbackComment}
                    onChange={(e) => setFeedbackComment(e.target.value)}
                    placeholder="Enter context, adjustments, or rationale..."
                    rows={4}
                    className="w-full text-sm p-3 rounded border border-slate-800 bg-slate-950 focus:border-teal-400 transition text-slate-200"
                  />
                </div>

                <button
                  type="submit"
                  disabled={submitting}
                  className="w-full flex items-center justify-center gap-2 py-2 text-sm font-semibold rounded bg-teal-500 text-slate-950 hover:bg-teal-400 transition font-bold disabled:opacity-40"
                >
                  {submitting ? 'Submitting...' : <><Send size={16} /> Submit Feedback</>}
                </button>
              </form>
            ) : (
              <div className="h-48 flex flex-col items-center justify-center text-center text-slate-500 border border-dashed border-slate-850 rounded">
                <Info size={32} className="mb-2" />
                <p className="text-xs">Select a response outcome record from the table to submit closed-loop tuning feedback.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'policies' && (
        <div className="border border-slate-850 bg-slate-900/20 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-slate-850 bg-slate-900/40">
            <h2 className="font-semibold text-sm">Policy Version Effectiveness</h2>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-850 text-slate-400 text-xs font-semibold bg-slate-950/40">
                  <th className="p-4">Policy ID</th>
                  <th className="p-4">Version</th>
                  <th className="p-4 text-center">Evaluations</th>
                  <th className="p-4 text-center">Allowed</th>
                  <th className="p-4 text-center">Denied</th>
                  <th className="p-4 text-center">Success Actions</th>
                  <th className="p-4 text-center">False Positives</th>
                  <th className="p-4 text-center">Acceptance</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850 text-sm">
                {policies.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-8 text-center text-slate-500">No policy effectiveness records compiled yet.</td>
                  </tr>
                ) : (
                  policies.map((p) => {
                    const totalFeedback = p.analyst_accepted + p.analyst_rejected;
                    const acceptance = totalFeedback > 0 ? (p.analyst_accepted / totalFeedback) * 100 : 100.0;
                    
                    return (
                      <tr key={`${p.policy_id}:${p.version}`} className="hover:bg-slate-900/30 transition">
                        <td className="p-4 font-mono font-medium text-slate-200">{p.policy_id}</td>
                        <td className="p-4">v{p.version}</td>
                        <td className="p-4 text-center">{p.evaluations}</td>
                        <td className="p-4 text-center text-teal-400">{p.allowed}</td>
                        <td className="p-4 text-center text-amber-500">{p.denied}</td>
                        <td className="p-4 text-center text-emerald-400">{p.successful_actions}</td>
                        <td className="p-4 text-center text-rose-500">{p.false_positives}</td>
                        <td className="p-4 text-center font-bold">{acceptance.toFixed(1)}%</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

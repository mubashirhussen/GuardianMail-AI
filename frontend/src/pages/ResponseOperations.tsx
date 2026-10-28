import { useState, useEffect } from 'react';
import { 
  ShieldAlert, Play, RotateCw, Trash2, CheckCircle, XCircle, 
  Clock, AlertTriangle, AlertCircle,
  Activity, Lock
} from 'lucide-react';
import { api } from '../services/api';
import { useAuth } from '../contexts/AuthContext';

interface Execution {
  _id: string;
  execution_id: string;
  response_decision_id: string;
  incident_id?: string;
  approval_request_id?: string;
  authorization_reference?: string;
  playbook_id: string;
  playbook_name?: string;
  recommended_action: string;
  status: 'QUEUED' | 'VALIDATING' | 'RUNNING' | 'SUCCESS' | 'PARTIAL_SUCCESS' | 'FAILED' | 'RETRYING' | 'EXHAUSTED' | 'CANCELLED';
  requested_by?: string;
  approved_by?: string;
  attempt_count: number;
  max_attempts: number;
  duration_ms?: number;
  error_code?: string;
  error_message?: string;
  retryable: boolean;
  next_retry_at?: string;
  created_at: string;
  updated_at: string;
  result_reference?: string;
  last_error?: string;
  connector_reference?: string;
  failure_reason?: string;
}

interface TimelineEvent {
  stage: string;
  timestamp: string;
  title: string;
  details: string;
  reference_id?: string;
  reference_type?: string;
}

interface Metrics {
  total_executions: number;
  successful_executions: number;
  partial_executions: number;
  failed_executions: number;
  exhausted_executions: number;
  active_executions: number;
  retry_count: number;
  average_execution_duration: number;
  p95_execution_duration: number;
  connector_failures: number;
  kill_switch_blocks: number;
  rate_limit_blocks: number;
  authorization_failures: number;
}

export default function ResponseOperations() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin' || user?.role === 'soc_analyst' || user?.role === 'security_analyst';
  const [executions, setExecutions] = useState<Execution[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [selectedExec, setSelectedExec] = useState<Execution | null>(null);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const [retryingId, setRetryingId] = useState<string | null>(null);
  const limit = 10;

  const fetchHistoryAndMetrics = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // 1. Fetch paginated executions
      const historyRes = await api.get(`/response-operations/executions?page=${page}&limit=${limit}`);
      setExecutions(historyRes.data.results || []);
      setTotal(historyRes.data.total || 0);

      // 2. Fetch metrics
      const metricsRes = await api.get('/response-operations/metrics');
      setMetrics(metricsRes.data);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || 'Failed to load execution operations data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistoryAndMetrics();
  }, [page]);

  const selectExecution = async (exec: Execution) => {
    setSelectedExec(exec);
    setTimeline([]);
    try {
      setDetailLoading(true);
      
      // Fetch fresh details
      const detailRes = await api.get(`/response-operations/executions/${exec.execution_id}`);
      setSelectedExec(detailRes.data);

      // Fetch timeline
      const timelineRes = await api.get(`/response-operations/executions/${exec.execution_id}/timeline`);
      setTimeline(timelineRes.data || []);
    } catch (err: any) {
      console.error(err);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleCancel = async (execId: string) => {
    if (!confirm('Are you sure you want to cancel this SOAR execution request?')) return;
    try {
      setCancellingId(execId);
      await api.post(`/response-operations/executions/${execId}/cancel`);
      alert('Execution request successfully cancelled.');
      fetchHistoryAndMetrics();
      if (selectedExec && selectedExec.execution_id === execId) {
        selectExecution(selectedExec);
      }
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to cancel execution request.');
    } finally {
      setCancellingId(null);
    }
  };

  const handleRetry = async (execId: string) => {
    try {
      setRetryingId(execId);
      await api.post(`/response-operations/executions/${execId}/retry`);
      alert('Retry task successfully scheduled.');
      fetchHistoryAndMetrics();
      if (selectedExec && selectedExec.execution_id === execId) {
        selectExecution(selectedExec);
      }
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to trigger manual execution retry.');
    } finally {
      setRetryingId(null);
    }
  };

  // Status colors utility
  const getStatusBadge = (status: string) => {
    const maps = {
      QUEUED: 'bg-blue-500/10 text-blue-400 border border-blue-500/20',
      VALIDATING: 'bg-purple-500/10 text-purple-400 border border-purple-500/20',
      RUNNING: 'bg-amber-500/10 text-amber-400 border border-amber-500/20 animate-pulse',
      SUCCESS: 'bg-green-500/10 text-green-400 border border-green-500/20',
      PARTIAL_SUCCESS: 'bg-teal-500/10 text-teal-400 border border-teal-500/20',
      FAILED: 'bg-red-500/10 text-red-400 border border-red-500/20',
      RETRYING: 'bg-orange-500/10 text-orange-400 border border-orange-500/20',
      EXHAUSTED: 'bg-rose-950/20 text-rose-500 border border-rose-900/30',
      CANCELLED: 'bg-slate-800/50 text-slate-400 border border-slate-700/30'
    };
    return maps[status as keyof typeof maps] || 'bg-slate-800 text-slate-400';
  };

  return (
    <div className="space-y-6">
      {/* Header Title */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-cyan-400" />
            Response Operations Console
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Observe E6 SOAR execution lifecycles, govern retry parameters, and track compliance timelines.
          </p>
        </div>
        <button 
          onClick={fetchHistoryAndMetrics}
          className="flex items-center gap-2 px-4 py-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 text-sm font-medium rounded-lg transition-all"
        >
          <RotateCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {error && (
        <div className="p-4 bg-red-950/20 border border-red-900/50 text-red-400 text-sm rounded-lg flex items-center gap-3">
          <AlertCircle className="h-5 w-5" />
          {error}
        </div>
      )}

      {/* Observability Metrics Cards */}
      {metrics && (
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-2">
            <p className="text-xs text-slate-400 font-medium">Active Executions</p>
            <div className="flex justify-between items-end">
              <h3 className="text-2xl font-bold text-amber-400">{metrics.active_executions}</h3>
              <Activity className="h-4 w-4 text-slate-500" />
            </div>
          </div>
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-2">
            <p className="text-xs text-slate-400 font-medium">Successful Runs</p>
            <div className="flex justify-between items-end">
              <h3 className="text-2xl font-bold text-green-400">{metrics.successful_executions}</h3>
              <CheckCircle className="h-4 w-4 text-green-500" />
            </div>
          </div>
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-2">
            <p className="text-xs text-slate-400 font-medium">Failed Runs</p>
            <div className="flex justify-between items-end">
              <h3 className="text-2xl font-bold text-red-400">{metrics.failed_executions}</h3>
              <XCircle className="h-4 w-4 text-red-500" />
            </div>
          </div>
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-2">
            <p className="text-xs text-slate-400 font-medium">Partial/Exhausted</p>
            <div className="flex justify-between items-end">
              <h3 className="text-2xl font-bold text-rose-400">
                {metrics.partial_executions} / {metrics.exhausted_executions}
              </h3>
              <AlertTriangle className="h-4 w-4 text-rose-500" />
            </div>
          </div>
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-2">
            <p className="text-xs text-slate-400 font-medium">Retry Queue Runs</p>
            <div className="flex justify-between items-end">
              <h3 className="text-2xl font-bold text-cyan-400">{metrics.retry_count}</h3>
              <RotateCw className="h-4 w-4 text-cyan-500 animate-spin-slow" />
            </div>
          </div>
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-2">
            <p className="text-xs text-slate-400 font-medium">Avg / P95 Latency</p>
            <div className="flex justify-between items-end">
              <h3 className="text-md font-bold text-slate-200">
                {metrics.average_execution_duration}ms / {metrics.p95_execution_duration}ms
              </h3>
              <Clock className="h-4 w-4 text-slate-500" />
            </div>
          </div>
        </div>
      )}

      {/* Safety Indicators Bar */}
      {metrics && (
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex flex-wrap gap-6 items-center justify-between">
          <div className="flex items-center gap-3">
            <Lock className="h-5 w-5 text-cyan-500" />
            <h4 className="text-sm font-semibold text-slate-200">Execution Safety Controls:</h4>
          </div>
          <div className="flex flex-wrap gap-4 text-xs font-semibold">
            <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
              <span className="text-slate-500">Global SOAR Status:</span>
              <span className={metrics.kill_switch_blocks > 0 ? 'text-red-400' : 'text-green-400'}>
                {metrics.kill_switch_blocks > 0 ? 'KILL SWITCH ACTIVE' : 'OPERATIONAL'}
              </span>
            </div>
            <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
              <span className="text-slate-500">Rate Limiting:</span>
              <span className={metrics.rate_limit_blocks > 0 ? 'text-red-400' : 'text-green-400'}>
                {metrics.rate_limit_blocks > 0 ? 'LIMIT DEVIATED' : '10 EX/MIN ENFORCED'}
              </span>
            </div>
            <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
              <span className="text-slate-500">Authorization Token Audit:</span>
              <span className="text-cyan-400">ENFORCED</span>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Execution History List Table */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="p-5 border-b border-slate-800">
            <h3 className="text-md font-bold text-slate-200">Execution Journey History</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950 text-xs text-slate-400 uppercase border-b border-slate-800">
                <tr>
                  <th className="px-5 py-3.5">Execution ID</th>
                  <th className="px-5 py-3.5">Incident</th>
                  <th className="px-5 py-3.5">Action</th>
                  <th className="px-5 py-3.5">Playbook</th>
                  <th className="px-5 py-3.5">Status</th>
                  <th className="px-5 py-3.5">Attempts</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {loading ? (
                  [...Array(5)].map((_, idx) => (
                    <tr key={idx} className="animate-pulse">
                      <td className="px-5 py-4"><div className="h-4 bg-slate-800 rounded w-16"></div></td>
                      <td className="px-5 py-4"><div className="h-4 bg-slate-800 rounded w-12"></div></td>
                      <td className="px-5 py-4"><div className="h-4 bg-slate-800 rounded w-24"></div></td>
                      <td className="px-5 py-4"><div className="h-4 bg-slate-800 rounded w-20"></div></td>
                      <td className="px-5 py-4"><div className="h-4 bg-slate-800 rounded w-16"></div></td>
                      <td className="px-5 py-4"><div className="h-4 bg-slate-800 rounded w-12"></div></td>
                    </tr>
                  ))
                ) : executions.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-5 py-8 text-center text-slate-500">
                      No SOAR executions logged yet for this tenant.
                    </td>
                  </tr>
                ) : (
                  executions.map((exec) => (
                    <tr 
                      key={exec.execution_id} 
                      onClick={() => selectExecution(exec)}
                      className={`hover:bg-slate-800/40 cursor-pointer transition-colors ${
                        selectedExec?.execution_id === exec.execution_id ? 'bg-slate-800/30' : ''
                      }`}
                    >
                      <td className="px-5 py-4 font-mono text-xs text-cyan-400">
                        {exec.execution_id.slice(0, 8)}...
                      </td>
                      <td className="px-5 py-4 text-xs font-mono">{exec.incident_id || 'N/A'}</td>
                      <td className="px-5 py-4 font-medium text-slate-200">{exec.recommended_action}</td>
                      <td className="px-5 py-4 text-xs text-slate-400">{exec.playbook_id}</td>
                      <td className="px-5 py-4">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${getStatusBadge(exec.status)}`}>
                          {exec.status}
                        </span>
                      </td>
                      <td className="px-5 py-4 text-xs text-slate-400">
                        {exec.attempt_count} / {exec.max_attempts}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          {total > limit && (
            <div className="p-4 border-t border-slate-800 flex justify-between items-center text-xs">
              <span className="text-slate-400">
                Showing {limit * (page - 1) + 1} - {Math.min(limit * page, total)} of {total} records
              </span>
              <div className="flex gap-2">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage(page - 1)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 rounded-lg transition-all"
                >
                  Previous
                </button>
                <button
                  disabled={page * limit >= total}
                  onClick={() => setPage(page + 1)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 rounded-lg transition-all"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Selected Execution Details Panel */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-6">
          <div className="border-b border-slate-800 pb-4">
            <h3 className="text-md font-bold text-slate-200">Execution Inspector</h3>
            <p className="text-xs text-slate-500 mt-1">Select an execution to inspect detailed timeline, retries, and audits.</p>
          </div>

          {selectedExec ? (
            <div className="space-y-6">
              {/* Actions Section */}
              <div className="flex gap-3">
                {/* Cancel Trigger */}
                {['QUEUED', 'VALIDATING'].includes(selectedExec.status) && (
                  <button
                    disabled={cancellingId === selectedExec.execution_id || !canManage}
                    onClick={() => handleCancel(selectedExec.execution_id)}
                    className={`flex-1 flex justify-center items-center gap-2 py-2 bg-red-950/20 border border-red-900/50 hover:bg-red-900/20 text-red-400 font-semibold text-xs rounded-lg transition-all ${!canManage ? 'opacity-55 cursor-not-allowed' : ''}`}
                    title={!canManage ? "Permission Denied: SOAR management permissions required" : ""}
                  >
                    {!canManage ? <Lock className="h-3.5 w-3.5" /> : <Trash2 className="h-4 w-4" />}
                    {cancellingId === selectedExec.execution_id ? 'Cancelling...' : 'Cancel Request'}
                  </button>
                )}

                {/* Manual Retry Trigger */}
                {['FAILED', 'EXHAUSTED'].includes(selectedExec.status) && (
                  <button
                    disabled={retryingId === selectedExec.execution_id || !canManage}
                    onClick={() => handleRetry(selectedExec.execution_id)}
                    className={`flex-1 flex justify-center items-center gap-2 py-2 bg-cyan-950/20 border border-cyan-900/50 hover:bg-cyan-900/20 text-cyan-400 font-semibold text-xs rounded-lg transition-all ${!canManage ? 'opacity-55 cursor-not-allowed' : ''}`}
                    title={!canManage ? "Permission Denied: SOAR management permissions required" : ""}
                  >
                    {!canManage ? <Lock className="h-3.5 w-3.5" /> : <Play className="h-4 w-4" />}
                    {retryingId === selectedExec.execution_id ? 'Retrying...' : 'Trigger Retry'}
                  </button>
                )}
              </div>

              {/* Status and Parameters Metadata */}
              <div className="space-y-3 bg-slate-950 p-4 rounded-lg border border-slate-800 text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-400">Execution Status:</span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${getStatusBadge(selectedExec.status)}`}>
                    {selectedExec.status}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Action:</span>
                  <span className="font-semibold text-slate-200">{selectedExec.recommended_action}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Playbook Name:</span>
                  <span className="text-slate-300 font-semibold">{selectedExec.playbook_name || selectedExec.playbook_id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Duration (ms):</span>
                  <span className="text-slate-300">{selectedExec.duration_ms !== undefined ? `${selectedExec.duration_ms} ms` : 'In Progress'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Attempts Limit:</span>
                  <span className="text-slate-300">{selectedExec.attempt_count} / {selectedExec.max_attempts}</span>
                </div>
                {selectedExec.connector_reference && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">Active Connector:</span>
                    <span className="text-cyan-400 uppercase font-mono">{selectedExec.connector_reference}</span>
                  </div>
                )}
                {selectedExec.result_reference && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">Result Ticket ID:</span>
                    <span className="text-slate-300 font-mono">{selectedExec.result_reference}</span>
                  </div>
                )}
              </div>

              {/* Failure Inspector */}
              {selectedExec.status === 'FAILED' || selectedExec.status === 'EXHAUSTED' || selectedExec.error_code ? (
                <div className="p-4 bg-red-950/10 border border-red-900/30 rounded-lg space-y-2 text-xs">
                  <h4 className="font-bold text-red-400 flex items-center gap-1.5">
                    <AlertCircle className="h-4 w-4" />
                    Failure Details [{selectedExec.error_code || 'UNKNOWN_FAILURE'}]
                  </h4>
                  <p className="text-slate-300 italic">{selectedExec.error_message || selectedExec.failure_reason}</p>
                  <div className="pt-1 text-[10px] text-slate-500 font-medium">
                    Retry Eligibility: {selectedExec.retryable ? 'RETRYABLE (Transient Error)' : 'NON-RETRYABLE (Critical Safety/Param block)'}
                    {selectedExec.next_retry_at && ` (Next attempt: ${new Date(selectedExec.next_retry_at).toLocaleTimeString()})`}
                  </div>
                </div>
              ) : null}

              {/* Chronicles Chronological Timeline */}
              <div className="space-y-4">
                <h4 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Clock className="h-4 w-4 text-slate-400" />
                  Chronological Timeline
                </h4>

                {detailLoading ? (
                  <p className="text-xs text-slate-500 animate-pulse">Loading execution timeline events...</p>
                ) : (
                  <div className="border-l border-slate-800 pl-4 space-y-4 text-xs ml-2">
                    {timeline.map((event, idx) => (
                      <div key={idx} className="relative space-y-1">
                        {/* Dot indicator */}
                        <div className="absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full bg-cyan-400 border border-slate-900" />
                        <div className="flex justify-between items-start">
                          <span className="font-bold text-slate-200">{event.title}</span>
                          <span className="text-[10px] text-slate-500">
                            {new Date(event.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <p className="text-slate-400 text-[11px] leading-relaxed">{event.details}</p>
                        {event.reference_id && (
                          <div className="text-[10px] text-cyan-500/80 font-mono">
                            Ref: {event.reference_id} ({event.reference_type})
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-slate-500 text-xs">
              No execution item selected. Click on an item in the history journey to inspect.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

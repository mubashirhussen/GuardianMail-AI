import { useState, useEffect } from 'react';
import { 
  Activity, CheckCircle, XCircle, AlertTriangle, 
  Play, Check, X, Info, RotateCw, Layers, TrendingUp, ShieldCheck
} from 'lucide-react';
import { api } from '../services/api';

interface TuningRecommendation {
  _id: string;
  optimization_id: string;
  recommendation_type: string;
  target_type: string;
  target_id: string;
  current_configuration: Record<string, any>;
  proposed_configuration: Record<string, any>;
  reason: string;
  evidence: Record<string, any>;
  confidence: number;
  expected_impact: Record<string, any>;
  risk_level: string;
  affected_actions: string[];
  affected_playbooks: string[];
  affected_policies: string[];
  status: string;
  created_at: string;
  simulation_result?: Record<string, any>;
}

interface OptimizationRun {
  _id: string;
  status: string;
  optimization_type: string;
  source_window_start: string;
  source_window_end: string;
  metrics_snapshot: Record<string, any>;
  recommendation_count: number;
  simulation_status: string;
  approval_status: string;
  created_at: string;
}

export default function ResponseOptimization() {
  const [recommendations, setRecommendations] = useState<TuningRecommendation[]>([]);
  const [_runs, setRuns] = useState<OptimizationRun[]>([]);
  const [selectedRec, setSelectedRec] = useState<TuningRecommendation | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [simulating, setSimulating] = useState<string | null>(null);
  const [processingRec, setProcessingRec] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lookbackDays, setLookbackDays] = useState(30);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [recRes, runRes] = await Promise.all([
        api.get('/response-optimization/recommendations'),
        api.get('/response-optimization/optimizations')
      ]);
      setRecommendations(recRes.data);
      setRuns(runRes.data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to retrieve response optimization data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRunScan = async () => {
    try {
      setScanning(true);
      setError(null);
      const res = await api.post('/response-optimization/analyze', { time_window_days: lookbackDays });
      if (res.data.status === 'INSUFFICIENT_DATA') {
        alert('Insufficient historical outcome data found to generate new optimization recommendations (minimum 3 outcomes required).');
      } else {
        await fetchData();
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to run optimization scan.');
    } finally {
      setScanning(false);
    }
  };

  const handleSimulate = async (recId: string) => {
    try {
      setSimulating(recId);
      const res = await api.post(`/response-optimization/recommendations/${recId}/simulate`);
      // Update selected and list state
      setSelectedRec(res.data);
      setRecommendations(prev => prev.map(r => r._id === recId ? res.data : r));
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Tuning simulation failed.');
    } finally {
      setSimulating(null);
    }
  };

  const handleApprove = async (recId: string) => {
    if (!confirm('Are you sure you want to approve this recommendation? This will create and activate a new policy version.')) return;
    try {
      setProcessingRec(recId);
      const res = await api.post(`/response-optimization/recommendations/${recId}/approve`);
      setSelectedRec(res.data);
      setRecommendations(prev => prev.map(r => r._id === recId ? res.data : r));
      alert('Tuning recommendation approved and policy configuration updated successfully.');
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Failed to approve tuning recommendation.');
    } finally {
      setProcessingRec(null);
    }
  };

  const handleReject = async (recId: string) => {
    if (!confirm('Are you sure you want to dismiss this recommendation?')) return;
    try {
      setProcessingRec(recId);
      const res = await api.post(`/response-optimization/recommendations/${recId}/reject`);
      setSelectedRec(res.data);
      setRecommendations(prev => prev.map(r => r._id === recId ? res.data : r));
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Failed to dismiss recommendation.');
    } finally {
      setProcessingRec(null);
    }
  };

  const handleCancel = async (recId: string) => {
    try {
      setProcessingRec(recId);
      const res = await api.post(`/response-optimization/recommendations/${recId}/cancel`);
      setSelectedRec(res.data);
      setRecommendations(prev => prev.map(r => r._id === recId ? res.data : r));
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Failed to cancel recommendation.');
    } finally {
      setProcessingRec(null);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'APPROVED':
        return <span className="px-2.5 py-1 text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full flex items-center gap-1 w-fit"><CheckCircle className="w-3.5 h-3.5" /> Approved</span>;
      case 'REJECTED':
        return <span className="px-2.5 py-1 text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20 rounded-full flex items-center gap-1 w-fit"><XCircle className="w-3.5 h-3.5" /> Dismissed</span>;
      case 'CANCELLED':
        return <span className="px-2.5 py-1 text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20 rounded-full flex items-center gap-1 w-fit"><X className="w-3.5 h-3.5" /> Cancelled</span>;
      case 'SIMULATED':
        return <span className="px-2.5 py-1 text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20 rounded-full flex items-center gap-1 w-fit"><TrendingUp className="w-3.5 h-3.5" /> Simulated</span>;
      case 'SIMULATING':
        return <span className="px-2.5 py-1 text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-full flex items-center gap-1 w-fit animate-pulse"><RotateCw className="w-3.5 h-3.5 animate-spin" /> Simulating</span>;
      default:
        return <span className="px-2.5 py-1 text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 rounded-full flex items-center gap-1 w-fit"><Activity className="w-3.5 h-3.5" /> Proposed</span>;
    }
  };

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case 'HIGH':
        return <span className="px-2.5 py-0.5 text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/25 rounded-md">High</span>;
      case 'MEDIUM':
        return <span className="px-2.5 py-0.5 text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/25 rounded-md">Medium</span>;
      default:
        return <span className="px-2.5 py-0.5 text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/25 rounded-md">Low</span>;
    }
  };

  const getRecTypeLabel = (type: string) => {
    return type.replace('_', ' ');
  };

  return (
    <div className="p-6 space-y-6 text-slate-100 min-h-screen bg-slate-950">
      {/* Header Panel */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-900/40 p-5 rounded-xl border border-slate-800/80 backdrop-blur-md">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Activity className="text-indigo-400 w-7 h-7" /> Continuous Response Optimization
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Analyze execution outcomes, calculate policy version drifts, and simulate expected automation changes.
          </p>
        </div>

        <div className="flex items-center gap-3 bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-medium text-slate-400">Lookback Window:</span>
            <select 
              value={lookbackDays} 
              onChange={(e) => setLookbackDays(Number(e.target.value))}
              className="bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-md px-2 py-1 focus:ring-1 focus:ring-indigo-500"
            >
              <option value={7}>7 Days</option>
              <option value={30}>30 Days</option>
              <option value={90}>90 Days</option>
            </select>
          </div>

          <button
            onClick={handleRunScan}
            disabled={scanning}
            className="flex items-center gap-1.5 px-4 py-1.5 text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white rounded-md transition-colors disabled:opacity-50"
          >
            {scanning ? (
              <>
                <RotateCw className="w-3.5 h-3.5 animate-spin" /> Scanning...
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" /> Run Tuning Scan
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/25 rounded-lg text-rose-400 flex gap-2 items-start text-sm">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Layout Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Recommendations list (Left 2 cols) */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-slate-900/30 border border-slate-800/80 rounded-xl overflow-hidden backdrop-blur-sm">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center bg-slate-900/10">
              <h2 className="font-semibold text-white flex items-center gap-2">
                <Layers className="w-4 h-4 text-indigo-400" /> Active Tuning Proposals
              </h2>
              <span className="px-2 py-0.5 text-xs font-bold bg-slate-800 text-slate-300 rounded-full">
                {recommendations.length} total
              </span>
            </div>

            {loading ? (
              <div className="p-12 text-center text-slate-400 flex flex-col items-center gap-3">
                <RotateCw className="w-8 h-8 animate-spin text-indigo-400" />
                <span className="text-sm">Loading tuning recommendations database...</span>
              </div>
            ) : recommendations.length === 0 ? (
              <div className="p-12 text-center text-slate-500 flex flex-col items-center gap-2">
                <ShieldCheck className="w-12 h-12 text-slate-600" />
                <p className="text-sm font-medium">No tuning recommendations generated yet.</p>
                <p className="text-xs text-slate-600">Run a Tuning Scan using lookback data above to identify improvements.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm border-collapse">
                  <thead>
                    <tr className="bg-slate-900/20 text-slate-400 text-xs font-semibold border-b border-slate-800">
                      <th className="p-4">Type</th>
                      <th className="p-4">Target</th>
                      <th className="p-4 text-center">Confidence</th>
                      <th className="p-4 text-center">Risk</th>
                      <th className="p-4">Status</th>
                      <th className="p-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recommendations.map((rec) => (
                      <tr 
                        key={rec._id}
                        onClick={() => setSelectedRec(rec)}
                        className={`border-b border-slate-850 hover:bg-slate-900/40 cursor-pointer transition-colors ${selectedRec?._id === rec._id ? 'bg-slate-900/60' : ''}`}
                      >
                        <td className="p-4 font-semibold text-slate-200">
                          {getRecTypeLabel(rec.recommendation_type)}
                        </td>
                        <td className="p-4">
                          <code className="text-xs text-indigo-300 font-mono">{rec.target_id}</code>
                        </td>
                        <td className="p-4 text-center">
                          <div className="flex items-center justify-center gap-1.5">
                            <div className="w-12 bg-slate-800 rounded-full h-2 overflow-hidden border border-slate-700">
                              <div 
                                className={`h-full ${rec.confidence >= 75 ? 'bg-emerald-400' : rec.confidence >= 50 ? 'bg-amber-400' : 'bg-slate-500'}`}
                                style={{ width: `${rec.confidence}%` }}
                              />
                            </div>
                            <span className="text-xs font-semibold text-slate-300">{rec.confidence}%</span>
                          </div>
                        </td>
                        <td className="p-4 text-center">
                          {getRiskBadge(rec.risk_level)}
                        </td>
                        <td className="p-4">
                          {getStatusBadge(rec.status)}
                        </td>
                        <td className="p-4 text-right" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => setSelectedRec(rec)}
                            className="text-xs text-indigo-400 hover:text-indigo-300 font-medium hover:underline"
                          >
                            Review
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Details / Review Drawer (Right 1 col) */}
        <div className="lg:col-span-1">
          <div className="bg-slate-900/30 border border-slate-800/80 rounded-xl p-5 space-y-6 backdrop-blur-sm sticky top-6">
            <h2 className="font-semibold text-white border-b border-slate-800 pb-3 flex items-center gap-2">
              <Info className="w-4 h-4 text-indigo-400" /> Recommendation Detail
            </h2>

            {!selectedRec ? (
              <div className="py-20 text-center text-slate-500 text-xs">
                Select a tuning proposal from the table to review evidence, run dry-run simulations, and approve policy version shifts.
              </div>
            ) : (
              <div className="space-y-6 text-sm">
                
                {/* Header Context */}
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-slate-400 font-medium">Tuning Type</span>
                    <span className="text-xs font-semibold text-white uppercase">{getRecTypeLabel(selectedRec.recommendation_type)}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-slate-400 font-medium">Target ID</span>
                    <code className="text-xs text-indigo-300 font-mono bg-slate-950 px-2 py-0.5 rounded border border-slate-850">{selectedRec.target_id}</code>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-slate-400 font-medium">Recommendation Status</span>
                    {getStatusBadge(selectedRec.status)}
                  </div>
                </div>

                {/* Justification Text */}
                <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800">
                  <span className="text-xs text-indigo-400 font-bold block mb-1">PROPOSED ADJUSTMENT</span>
                  <p className="text-slate-200 text-xs font-medium leading-relaxed">{selectedRec.reason}</p>
                </div>

                {/* Parameters delta */}
                {(selectedRec.recommendation_type === 'POLICY_TUNING' || selectedRec.recommendation_type === 'AUTOMATION_TUNING') && (
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-850 grid grid-cols-2 gap-4 text-center font-mono">
                    <div className="border-r border-slate-800/80">
                      <span className="text-[10px] text-slate-500 block">CURRENT CONFIG</span>
                      <span className="text-xs font-bold text-rose-400 block mt-1">
                        {JSON.stringify(selectedRec.current_configuration)}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 block">PROPOSED CONFIG</span>
                      <span className="text-xs font-bold text-emerald-400 block mt-1">
                        {JSON.stringify(selectedRec.proposed_configuration)}
                      </span>
                    </div>
                  </div>
                )}

                {/* Evidence Facts */}
                <div className="space-y-2">
                  <span className="text-xs text-slate-400 font-bold block">EVALUATED EVIDENCE</span>
                  <div className="bg-slate-900/20 p-3 rounded-lg border border-slate-850 space-y-1.5 text-xs text-slate-300">
                    {Object.entries(selectedRec.evidence).map(([key, val]) => (
                      <div key={key} className="flex justify-between">
                        <span className="capitalize text-slate-400">{key.replace(/_/g, ' ')}:</span>
                        <span className="font-semibold">{typeof val === 'number' && val % 1 !== 0 ? val.toFixed(1) : String(val)}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Historical Simulation Panel */}
                <div className="space-y-3 border-t border-slate-800 pt-4">
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-slate-400 font-bold">HISTORICAL IMPACT SIMULATION</span>
                    {selectedRec.status === 'PROPOSED' && (selectedRec.recommendation_type === 'POLICY_TUNING' || selectedRec.recommendation_type === 'AUTOMATION_TUNING') && (
                      <button
                        onClick={() => handleSimulate(selectedRec._id)}
                        disabled={simulating !== null}
                        className="px-2.5 py-1 text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-750 rounded font-semibold transition-colors disabled:opacity-50 flex items-center gap-1"
                      >
                        {simulating === selectedRec._id ? (
                          <>
                            <RotateCw className="w-3 h-3 animate-spin" /> Simulating...
                          </>
                        ) : (
                          <>
                            <TrendingUp className="w-3 h-3" /> Simulate Impact
                          </>
                        )}
                      </button>
                    )}
                  </div>

                  {selectedRec.simulation_result ? (
                    <div className="bg-slate-900/40 p-3.5 rounded-lg border border-slate-800 space-y-3 text-xs">
                      <div className="flex justify-between items-center text-slate-300">
                        <span>Simulated Window Count:</span>
                        <span className="font-semibold text-white">{selectedRec.simulation_result.total_simulated} decisions</span>
                      </div>
                      
                      <div className="flex justify-between items-center text-slate-300">
                        <span>Estimated FP Prevention:</span>
                        <span className="font-semibold text-emerald-400 flex items-center gap-1">
                          <CheckCircle className="w-3.5 h-3.5" /> + {selectedRec.simulation_result.estimated_false_positive_reduction} prevented
                        </span>
                      </div>

                      <div className="flex justify-between items-center text-slate-300">
                        <span>Automation rate Delta:</span>
                        <span className={`font-semibold ${selectedRec.simulation_result.estimated_automation_delta >= 0 ? 'text-emerald-400' : 'text-slate-400'}`}>
                          {selectedRec.simulation_result.estimated_automation_delta >= 0 ? '+' : ''}{selectedRec.simulation_result.estimated_automation_delta.toFixed(1)}%
                        </span>
                      </div>

                      <div className="border-t border-slate-800/80 pt-2 space-y-1 text-[10px] text-slate-400 font-mono">
                        <span className="font-semibold text-slate-400 uppercase tracking-wider block mb-1">Verdict shifts:</span>
                        {Object.entries(selectedRec.simulation_result.verdict_changes).map(([shift, count]) => {
                          if (count === 0 || shift === 'NO_CHANGE') return null;
                          return (
                            <div key={shift} className="flex justify-between">
                              <span>{shift.replace(/_TO_/g, ' ➔ ')}:</span>
                              <span className="font-bold text-slate-300">{String(count)}</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ) : (
                    <div className="bg-slate-900/10 border border-slate-850 p-4 rounded-lg text-center text-slate-500 text-xs">
                      No simulation run yet. Click "Simulate Impact" to dry-run proposed settings over historical data.
                    </div>
                  )}
                </div>

                {/* Operations governance controls */}
                <div className="flex gap-2 border-t border-slate-800 pt-4">
                  {selectedRec.status !== 'APPROVED' && selectedRec.status !== 'REJECTED' && selectedRec.status !== 'CANCELLED' && (
                    <>
                      <button
                        onClick={() => handleApprove(selectedRec._id)}
                        disabled={processingRec !== null}
                        className="flex-1 py-2 text-xs bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg transition-colors flex items-center justify-center gap-1"
                      >
                        <Check className="w-3.5 h-3.5" /> Approve & Apply
                      </button>

                      <button
                        onClick={() => handleReject(selectedRec._id)}
                        disabled={processingRec !== null}
                        className="flex-1 py-2 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold rounded-lg transition-colors flex items-center justify-center gap-1"
                      >
                        <X className="w-3.5 h-3.5" /> Reject
                      </button>
                    </>
                  )}

                  {selectedRec.status === 'SIMULATING' && (
                    <button
                      onClick={() => handleCancel(selectedRec._id)}
                      disabled={processingRec !== null}
                      className="w-full py-2 text-xs bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded-lg transition-colors flex items-center justify-center gap-1"
                    >
                      <X className="w-3.5 h-3.5" /> Cancel Simulation
                    </button>
                  )}
                </div>

              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}

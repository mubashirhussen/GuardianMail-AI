import React, { useEffect, useState } from 'react';
import {
  Shield,
  Laptop,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  AlertCircle,
  Clock,
  ChevronRight
} from 'lucide-react';
import {
  grcService,
  type PostureScore,
  type ControlItem,
  type RiskItem,
  type EvidenceItem,
  type FindingItem,
  type AuditItem,
  type SyncStatusResponse
} from '../services/grc';
import { getErrorMessage } from '../utils/errors';

export default function Governance() {
  const [activeTab, setActiveTab] = useState<'posture' | 'risks' | 'evidence' | 'audits'>('posture');
  
  // Data states
  const [posture, setPosture] = useState<PostureScore | null>(null);
  const [controls, setControls] = useState<ControlItem[]>([]);
  const [risks, setRisks] = useState<RiskItem[]>([]);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [audits, setAudits] = useState<AuditItem[]>([]);
  
  // Execution states
  const [loading, setLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [isCollecting, setIsCollecting] = useState(false);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  
  // Status & Error banners
  const [syncStatus, setSyncStatus] = useState<SyncStatusResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [isAuthExpired, setIsAuthExpired] = useState(false);

  // Exception form state
  const [exceptionRiskId, setExceptionRiskId] = useState('');
  const [exceptionReason, setExceptionReason] = useState('');
  const [exceptionControls, setExceptionControls] = useState('');
  const [submittingException, setSubmittingException] = useState(false);

  // Manual evidence form state
  const [evControlId, setEvControlId] = useState('');
  const [evType, setEvType] = useState('config_snapshot');
  const [evSource, setEvSource] = useState('');
  const [evContent, setEvContent] = useState('');
  const [submittingEvidence, setSubmittingEvidence] = useState(false);

  // Verification results cache
  const [verificationMap, setVerificationMap] = useState<Record<string, { isValid: boolean; timestamp: string }>>({});

  const showToast = (msg: string) => {
    setSuccessMessage(msg);
    setTimeout(() => setSuccessMessage(null), 4500);
  };

  const fetchData = async () => {
    try {
      setLoading(true);
      setErrorMessage(null);
      setIsAuthExpired(false);

      const [resPosture, resControls, resRisks, resEvidence, resFindings, resAudits, resSync] = await Promise.all([
        grcService.getPosture().catch((err) => { throw err; }),
        grcService.getControls().catch(() => []),
        grcService.getRisks().catch(() => []),
        grcService.getEvidence().catch(() => []),
        grcService.getFindings().catch(() => []),
        grcService.getAudits().catch(() => []),
        grcService.getSyncStatus().catch(() => null),
      ]);

      setPosture(resPosture);
      setControls(resControls);
      setRisks(resRisks);
      setEvidence(resEvidence);
      setFindings(resFindings);
      setAudits(resAudits);
      if (resSync) setSyncStatus(resSync);
    } catch (err: any) {
      const status = err.response?.status;
      const detail = err.response?.data?.detail;

      if (status === 401 || (typeof detail === 'string' && detail.toLowerCase().includes('token'))) {
        setIsAuthExpired(true);
        setErrorMessage('Your session has expired. Please sign in again to continue.');
      } else if (status === 403) {
        setErrorMessage('You do not have permission to view Governance, Risk & Compliance metrics.');
      } else {
        setErrorMessage(getErrorMessage(err) || 'Failed to load enterprise compliance registry.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleSystemSync = async () => {
    if (isSyncing) return;
    try {
      setIsSyncing(true);
      setErrorMessage(null);
      const res = await grcService.triggerSystemSync();
      setSyncStatus(res);
      showToast(res.message || `System synchronized successfully (${res.items_synced ?? 0} items updated).`);
      await fetchData();
    } catch (err: any) {
      const status = err.response?.status;
      if (status === 401) {
        setIsAuthExpired(true);
        setErrorMessage('Your session has expired. Please sign in again.');
      } else {
        setErrorMessage('System synchronization could not be completed. Your previous data has been preserved.');
      }
    } finally {
      setIsSyncing(false);
    }
  };

  const handleCollectEvidence = async () => {
    if (isCollecting) return;
    try {
      setIsCollecting(true);
      setErrorMessage(null);
      const res = await grcService.triggerEvidenceCollection();
      showToast(`Automated evidence collection finished: ${res.length} snapshots certified & sealed.`);
      await fetchData();
    } catch (err: any) {
      const status = err.response?.status;
      if (status === 401) {
        setIsAuthExpired(true);
        setErrorMessage('Your session has expired. Please sign in again.');
      } else {
        setErrorMessage('Evidence collection failed. Review the available source status and try again.');
      }
    } finally {
      setIsCollecting(false);
    }
  };

  const handleVerifyEvidence = async (id: string) => {
    try {
      setVerifyingId(id);
      const res = await grcService.verifyEvidence(id);
      setVerificationMap((prev) => ({
        ...prev,
        [id]: { isValid: res.is_valid, timestamp: new Date(res.verified_at).toLocaleTimeString() }
      }));
      if (res.is_valid) {
        showToast(`Evidence verified: Cryptographic SHA-256 seal matches stored content.`);
      } else {
        setErrorMessage(`Tamper Alert: Stored signature does not match recomputed SHA-256 hash.`);
      }
    } catch (err: any) {
      setErrorMessage(getErrorMessage(err) || 'Failed to verify evidence hash.');
    } finally {
      setVerifyingId(null);
    }
  };

  const handleMitigateRisk = async (riskId: string) => {
    try {
      await grcService.mitigateRisk(riskId);
      showToast(`Risk ${riskId} status updated to MITIGATED.`);
      await fetchData();
    } catch (err) {
      setErrorMessage('Failed to update risk mitigation status.');
    }
  };

  const handleApplyException = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSubmittingException(true);
      await grcService.applyRiskException(exceptionRiskId, exceptionReason, exceptionControls, 30);
      showToast(`Risk Exception for ${exceptionRiskId} submitted successfully.`);
      setExceptionRiskId('');
      setExceptionReason('');
      setExceptionControls('');
      await fetchData();
    } catch (err) {
      setErrorMessage('Failed to apply risk exception.');
    } finally {
      setSubmittingException(false);
    }
  };

  const handleUploadEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSubmittingEvidence(true);
      await grcService.uploadEvidence({
        control_id: evControlId,
        evidence_type: evType,
        source: evSource,
        content: evContent
      });
      showToast(`Manual evidence file uploaded and sealed with SHA-256 signature.`);
      setEvControlId('');
      setEvSource('');
      setEvContent('');
      await fetchData();
    } catch (err) {
      setErrorMessage('Manual evidence upload failed.');
    } finally {
      setSubmittingEvidence(false);
    }
  };

  const handleExport = async (reportType: string, format: string) => {
    try {
      const blob = await grcService.exportReport(reportType, format);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `guardianmail_grc_${reportType}.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setErrorMessage('Failed to export compliance report document.');
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto p-4 md:p-6 text-slate-900 dark:text-slate-100">
      {/* Top Header Card */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-500/20">
              Enterprise GRC & Audit
            </span>
            {syncStatus?.synced_at && (
              <span className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-500 dark:text-slate-400">
                <Clock className="h-3 w-3" />
                Synced: {new Date(syncStatus.synced_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
              </span>
            )}
          </div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Governance, Risk & Compliance (GRC)
          </h1>
          <p className="text-xs md:text-sm text-slate-600 dark:text-slate-400 mt-1 max-w-2xl">
            Assess framework posture, map risk registers, and export certified evidence snapshots.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-3">
          {/* System Sync button */}
          <button
            type="button"
            onClick={handleSystemSync}
            disabled={isSyncing}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700 transition shadow-sm disabled:opacity-60 cursor-pointer"
            title="Synchronize baseline framework controls, telemetry status, and security posture"
          >
            <Laptop className={`h-4 w-4 text-cyan-600 dark:text-cyan-400 ${isSyncing ? 'animate-pulse' : ''}`} />
            <span>{isSyncing ? 'Syncing System...' : 'System Sync'}</span>
          </button>

          {/* Collect System Evidence button */}
          <button
            type="button"
            onClick={handleCollectEvidence}
            disabled={isCollecting}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white transition shadow-sm disabled:opacity-60 cursor-pointer"
          >
            <RefreshCw className={`h-4 w-4 ${isCollecting ? 'animate-spin' : ''}`} />
            <span>{isCollecting ? 'Collecting Evidence...' : 'Collect System Evidence'}</span>
          </button>
        </div>
      </div>

      {/* Success Notification Banner */}
      {successMessage && (
        <div className="flex items-center gap-3 p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800/50 text-emerald-800 dark:text-emerald-300 text-xs font-medium shadow-sm">
          <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
          <span className="flex-1">{successMessage}</span>
          <button onClick={() => setSuccessMessage(null)} className="text-emerald-600 hover:text-emerald-800 text-sm">✕</button>
        </div>
      )}

      {/* Error & Authentication Status Banner */}
      {errorMessage && (
        <div className="flex items-start gap-3 p-4 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/60 text-red-800 dark:text-red-300 text-xs shadow-sm">
          <AlertCircle className="h-4 w-4 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1">
            <p className="font-semibold">{errorMessage}</p>
            {isAuthExpired && (
              <div className="mt-2">
                <a
                  href="/auth"
                  className="inline-flex items-center gap-1 px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded-lg text-xs font-semibold transition"
                >
                  Sign In Again <ChevronRight className="h-3 w-3" />
                </a>
              </div>
            )}
          </div>
          <button onClick={() => setErrorMessage(null)} className="text-red-600 hover:text-red-800 text-sm">✕</button>
        </div>
      )}

      {/* Overview disclaimer */}
      {posture && (
        <div className="flex items-center gap-3 p-3.5 rounded-xl bg-blue-50/70 dark:bg-blue-950/20 border-l-4 border-l-blue-600 border border-blue-100 dark:border-slate-800 text-xs text-blue-900 dark:text-blue-300">
          <Shield className="h-4 w-4 text-blue-600 dark:text-blue-400 shrink-0" />
          <span>{posture.disclaimer}</span>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="flex border-b border-slate-200 dark:border-slate-800 gap-2 md:gap-6 overflow-x-auto">
        {[
          { key: 'posture', label: 'Readiness Posture' },
          { key: 'risks', label: 'Risk Register Matrix' },
          { key: 'evidence', label: 'Tamper-Evident Evidence' },
          { key: 'audits', label: 'Audit Projects & Findings' },
        ].map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as any)}
            className={`pb-3 pt-1 px-3 text-xs md:text-sm font-semibold border-b-2 transition whitespace-nowrap cursor-pointer ${
              activeTab === tab.key
                ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {loading && (
        <div className="p-12 text-center text-slate-500 dark:text-slate-400 text-sm flex flex-col items-center justify-center gap-3">
          <RefreshCw className="h-6 w-6 animate-spin text-blue-600" />
          <span>Loading enterprise compliance registry...</span>
        </div>
      )}

      {!loading && (
        <>
          {/* TAB 1: READINESS POSTURE */}
          {activeTab === 'posture' && posture && (
            <div className="space-y-6">
              {/* Posture Scoreboard Card */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex flex-col items-center justify-center text-center shadow-sm">
                  <div className="relative w-28 h-28 rounded-full border-8 border-blue-600/20 dark:border-blue-500/20 flex flex-col items-center justify-center mb-3">
                    <div
                      className="absolute inset-0 rounded-full border-8 border-blue-600 dark:border-blue-500"
                      style={{ clipPath: `polygon(0 0, 100% 0, 100% ${posture.posture_score}%, 0 ${posture.posture_score}%)` }}
                    />
                    <span className="text-2xl font-black text-slate-900 dark:text-slate-100">
                      {posture.posture_score}%
                    </span>
                  </div>
                  <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                    {posture.posture_rating} Posture
                  </h2>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                    {posture.metrics.total_controls > 0
                      ? `${posture.metrics.total_controls} Framework controls evaluated`
                      : 'Not configured — Run System Sync to map baseline'}
                  </p>
                </div>

                <div className="md:col-span-2 p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                    Breakdown by Security Vector
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    {Object.entries(posture.category_posture).map(([vector, val]) => (
                      <div key={vector} className="space-y-1.5">
                        <div className="flex justify-between text-xs">
                          <span className="text-slate-600 dark:text-slate-400 capitalize">
                            {vector.replace('_', ' ')}
                          </span>
                          <span className="font-bold text-slate-900 dark:text-slate-200">{val}%</span>
                        </div>
                        <div className="h-2 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-blue-600 rounded-full transition-all duration-500"
                            style={{ width: `${val}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Controls Checklist Table */}
              <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                      Mapped Framework Controls ({controls.length})
                    </h3>
                    <p className="text-xs text-slate-500">
                      SOC 2, ISO 27001, and NIST CSF verified control statuses
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleExport('posture', 'csv')}
                      className="px-3 py-1.5 text-xs font-semibold bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-lg border border-slate-200 dark:border-slate-700 transition"
                    >
                      Export CSV
                    </button>
                    <button
                      onClick={() => handleExport('posture', 'json')}
                      className="px-3 py-1.5 text-xs font-semibold bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-lg border border-slate-200 dark:border-slate-700 transition"
                    >
                      Export JSON
                    </button>
                  </div>
                </div>

                {controls.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 dark:text-slate-400 text-xs">
                    No framework controls mapped yet. Click <span className="font-semibold text-blue-600">System Sync</span> above to initialize baseline standards.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 uppercase text-[10px] font-semibold">
                          <th className="py-2.5 px-3">Control ID</th>
                          <th className="py-2.5 px-3">Framework</th>
                          <th className="py-2.5 px-3">Description</th>
                          <th className="py-2.5 px-3">Risk Level</th>
                          <th className="py-2.5 px-3">Frequency</th>
                          <th className="py-2.5 px-3">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                        {controls.map((c) => (
                          <tr key={c.control_id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition">
                            <td className="py-3 px-3 font-mono font-bold text-slate-900 dark:text-slate-100">{c.control_id}</td>
                            <td className="py-3 px-3">
                              <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                                {c.framework_name}
                              </span>
                            </td>
                            <td className="py-3 px-3 text-slate-600 dark:text-slate-300 max-w-md">{c.description}</td>
                            <td className="py-3 px-3 capitalize">
                              <span className={c.risk_level === 'critical' || c.risk_level === 'high' ? 'text-red-600 font-semibold' : 'text-slate-600 dark:text-slate-400'}>
                                {c.risk_level}
                              </span>
                            </td>
                            <td className="py-3 px-3 text-slate-500">{c.review_frequency}</td>
                            <td className="py-3 px-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                c.status === 'PASS'
                                  ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/40'
                                  : c.status === 'FAIL'
                                  ? 'bg-red-50 dark:bg-red-950/40 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-800/40'
                                  : 'bg-amber-50 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-800/40'
                              }`}>
                                {c.status}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: RISK REGISTER MATRIX */}
          {activeTab === 'risks' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                      Organizational Risk Register ({risks.length})
                    </h3>
                    <p className="text-xs text-slate-500">Calibrated likelihood and inherent impact ratings</p>
                  </div>
                  <button
                    onClick={() => handleExport('risks', 'csv')}
                    className="px-3 py-1.5 text-xs font-semibold bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-lg border border-slate-200 dark:border-slate-700 transition"
                  >
                    Export Risk CSV
                  </button>
                </div>

                {risks.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 text-xs">
                    No active risks registered. Click <span className="font-semibold text-blue-600">System Sync</span> to evaluate threat vector risks.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 uppercase text-[10px] font-semibold">
                          <th className="py-2.5 px-3">Risk ID</th>
                          <th className="py-2.5 px-3">Title</th>
                          <th className="py-2.5 px-3">Category</th>
                          <th className="py-2.5 px-3">Score</th>
                          <th className="py-2.5 px-3">Treatment</th>
                          <th className="py-2.5 px-3">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                        {risks.map((r) => (
                          <tr key={r.risk_id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition">
                            <td className="py-3 px-3 font-mono font-bold">{r.risk_id}</td>
                            <td className="py-3 px-3 text-slate-900 dark:text-slate-100 font-medium">{r.title}</td>
                            <td className="py-3 px-3 text-slate-500">{r.category}</td>
                            <td className="py-3 px-3 font-bold">
                              <span className={r.inherent_risk_score >= 16 ? 'text-red-600' : r.inherent_risk_score >= 9 ? 'text-amber-500' : 'text-slate-500'}>
                                {r.inherent_risk_score} / 25
                              </span>
                            </td>
                            <td className="py-3 px-3">
                              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                                {r.treatment_status}
                              </span>
                            </td>
                            <td className="py-3 px-3">
                              {r.status !== 'MITIGATED' ? (
                                <button
                                  onClick={() => handleMitigateRisk(r.risk_id)}
                                  className="px-2.5 py-1 text-[11px] font-semibold bg-emerald-600 hover:bg-emerald-700 text-white rounded transition shadow-sm cursor-pointer"
                                >
                                  Mitigate
                                </button>
                              ) : (
                                <span className="text-emerald-600 font-semibold text-[11px]">Mitigated</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Request Temporary Exception Form */}
              <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
                <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                  Request Temporary Exemption
                </h3>
                <form onSubmit={handleApplyException} className="space-y-3.5 text-xs">
                  <div>
                    <label className="block text-slate-600 dark:text-slate-400 mb-1 font-medium">Target Risk ID</label>
                    <input
                      type="text"
                      value={exceptionRiskId}
                      onChange={(e) => setExceptionRiskId(e.target.value)}
                      required
                      placeholder="e.g. RISK-MFA-ADMIN"
                      className="w-full px-3 py-2 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-600 dark:text-slate-400 mb-1 font-medium">Business Reason</label>
                    <textarea
                      value={exceptionReason}
                      onChange={(e) => setExceptionReason(e.target.value)}
                      required
                      rows={2}
                      placeholder="Justify operational requirement"
                      className="w-full px-3 py-2 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-600 dark:text-slate-400 mb-1 font-medium">Compensating Controls</label>
                    <textarea
                      value={exceptionControls}
                      onChange={(e) => setExceptionControls(e.target.value)}
                      required
                      rows={2}
                      placeholder="What alternative safeguards are applied?"
                      className="w-full px-3 py-2 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={submittingException}
                    className="w-full py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition shadow-sm disabled:opacity-60 cursor-pointer"
                  >
                    {submittingException ? 'Submitting...' : 'Submit Exception Request'}
                  </button>
                </form>
              </div>
            </div>
          )}

          {/* TAB 3: TAMPER-EVIDENT EVIDENCE */}
          {activeTab === 'evidence' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                      Tamper-Evident Evidence Ledger ({evidence.length})
                    </h3>
                    <p className="text-xs text-slate-500">Cryptographically sealed with SHA-256 integrity hashes</p>
                  </div>
                  <button
                    onClick={() => handleExport('evidence', 'csv')}
                    className="px-3 py-1.5 text-xs font-semibold bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-lg border border-slate-200 dark:border-slate-700 transition"
                  >
                    Export CSV
                  </button>
                </div>

                {evidence.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 text-xs">
                    No evidence records gathered yet. Click <span className="font-semibold text-blue-600">Collect System Evidence</span> above.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 uppercase text-[10px] font-semibold">
                          <th className="py-2.5 px-3">Control</th>
                          <th className="py-2.5 px-3">Source Description</th>
                          <th className="py-2.5 px-3">SHA-256 Hash</th>
                          <th className="py-2.5 px-3">Collected</th>
                          <th className="py-2.5 px-3">Integrity</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                        {evidence.map((e, idx) => {
                          const evId = e._id || e.control_id;
                          const vStatus = verificationMap[evId];
                          return (
                            <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition">
                              <td className="py-3 px-3 font-mono font-bold text-slate-900 dark:text-slate-100">{e.control_id}</td>
                              <td className="py-3 px-3 text-slate-700 dark:text-slate-300">{e.source}</td>
                              <td className="py-3 px-3">
                                <span className="font-mono text-[11px] text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-200 dark:border-emerald-800/30">
                                  🔒 {e.content_hash.slice(0, 14)}...
                                </span>
                              </td>
                              <td className="py-3 px-3 text-slate-500">{new Date(e.collected_at).toLocaleDateString()}</td>
                              <td className="py-3 px-3">
                                {vStatus ? (
                                  <span className={`inline-flex items-center gap-1 text-[11px] font-semibold ${vStatus.isValid ? 'text-emerald-600' : 'text-red-600'}`}>
                                    {vStatus.isValid ? <CheckCircle2 className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}
                                    {vStatus.isValid ? 'Verified' : 'Tampered'}
                                  </span>
                                ) : (
                                  <button
                                    onClick={() => handleVerifyEvidence(evId)}
                                    disabled={verifyingId === evId}
                                    className="px-2 py-0.5 text-[11px] font-medium bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded border border-slate-300 dark:border-slate-700 transition cursor-pointer"
                                  >
                                    {verifyingId === evId ? 'Verifying...' : 'Verify Seal'}
                                  </button>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Upload Manual Evidence */}
              <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
                <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                  Upload Manual Evidence File
                </h3>
                <form onSubmit={handleUploadEvidence} className="space-y-3.5 text-xs">
                  <div>
                    <label className="block text-slate-600 dark:text-slate-400 mb-1 font-medium">Target Control ID</label>
                    <input
                      type="text"
                      value={evControlId}
                      onChange={(e) => setEvControlId(e.target.value)}
                      required
                      placeholder="e.g. SOC2-CC6.1"
                      className="w-full px-3 py-2 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-600 dark:text-slate-400 mb-1 font-medium">Evidence Type</label>
                    <select
                      value={evType}
                      onChange={(e) => setEvType(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none"
                    >
                      <option value="config_snapshot">Configuration Snapshot</option>
                      <option value="audit_log">Audit Log Snap</option>
                      <option value="security_report">Compliance Report Doc</option>
                      <option value="screenshot">Remediation Screenshot</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-slate-600 dark:text-slate-400 mb-1 font-medium">Source Description</label>
                    <input
                      type="text"
                      value={evSource}
                      onChange={(e) => setEvSource(e.target.value)}
                      required
                      placeholder="e.g. Admin access log screenshot"
                      className="w-full px-3 py-2 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-600 dark:text-slate-400 mb-1 font-medium">Content Payload</label>
                    <textarea
                      value={evContent}
                      onChange={(e) => setEvContent(e.target.value)}
                      required
                      rows={3}
                      placeholder="Paste snapshot JSON config details or verification logs text"
                      className="w-full px-3 py-2 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-blue-500 font-mono text-[11px]"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={submittingEvidence}
                    className="w-full py-2 bg-emerald-600 hover:bg-emerald-700 text-white font-semibold rounded-lg transition shadow-sm disabled:opacity-60 cursor-pointer"
                  >
                    {submittingEvidence ? 'Sealing...' : 'Upload & Seal Hash'}
                  </button>
                </form>
              </div>
            </div>
          )}

          {/* TAB 4: AUDIT PROJECTS & FINDINGS */}
          {activeTab === 'audits' && (
            <div className="space-y-6">
              {/* Audit Timelines */}
              <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Audit Project Timelines ({audits.length})
                </h3>
                {audits.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 text-xs">
                    No active audit projects registered.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 uppercase text-[10px] font-semibold">
                          <th className="py-2.5 px-3">Audit ID</th>
                          <th className="py-2.5 px-3">Scope Summary</th>
                          <th className="py-2.5 px-3">Standard</th>
                          <th className="py-2.5 px-3">Assessor</th>
                          <th className="py-2.5 px-3">Timeline</th>
                          <th className="py-2.5 px-3">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                        {audits.map((a) => (
                          <tr key={a.audit_id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition">
                            <td className="py-3 px-3 font-mono font-bold">{a.audit_id}</td>
                            <td className="py-3 px-3 text-slate-900 dark:text-slate-100 font-medium">{a.scope}</td>
                            <td className="py-3 px-3">{a.framework_name}</td>
                            <td className="py-3 px-3 text-slate-500">{a.auditor}</td>
                            <td className="py-3 px-3 text-slate-500">
                              {new Date(a.start_date).toLocaleDateString()} - {new Date(a.end_date).toLocaleDateString()}
                            </td>
                            <td className="py-3 px-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                a.status === 'COMPLETED' ? 'text-emerald-600 bg-emerald-50 dark:bg-emerald-950/40' : 'text-amber-600 bg-amber-50 dark:bg-amber-950/40'
                              }`}>
                                {a.status}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Remediation Findings Register */}
              <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Remediation Findings Register ({findings.length})
                </h3>
                {findings.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 text-xs">
                    No open audit defects or remediation findings recorded.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 uppercase text-[10px] font-semibold">
                          <th className="py-2.5 px-3">Finding ID</th>
                          <th className="py-2.5 px-3">Severity</th>
                          <th className="py-2.5 px-3">Control</th>
                          <th className="py-2.5 px-3">Detected Defect</th>
                          <th className="py-2.5 px-3">Recommended Mitigation</th>
                          <th className="py-2.5 px-3">State</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                        {findings.map((f) => (
                          <tr key={f.finding_id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition">
                            <td className="py-3 px-3 font-mono font-bold">{f.finding_id}</td>
                            <td className="py-3 px-3">
                              <span className={`uppercase font-bold text-[10px] ${
                                f.severity === 'critical' || f.severity === 'high' ? 'text-red-600' : 'text-amber-600'
                              }`}>
                                {f.severity}
                              </span>
                            </td>
                            <td className="py-3 px-3 font-mono">{f.control_id}</td>
                            <td className="py-3 px-3 text-slate-900 dark:text-slate-100 font-medium">{f.description}</td>
                            <td className="py-3 px-3 text-slate-600 dark:text-slate-300">{f.remediation_plan}</td>
                            <td className="py-3 px-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                                f.status === 'CLOSED' || f.status === 'REMEDIATED'
                                  ? 'text-emerald-600 bg-emerald-50 dark:bg-emerald-950/40'
                                  : 'text-amber-600 bg-amber-50 dark:bg-amber-950/40'
                              }`}>
                                {f.status}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

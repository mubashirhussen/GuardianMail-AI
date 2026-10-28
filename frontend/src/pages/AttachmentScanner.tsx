import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { useQuery } from '@tanstack/react-query';
import {
  UploadCloud,
  FileText,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  X,
  RefreshCw,
  FileSearch,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import { attachmentsService } from '../services/attachments';
import type { AttachmentScanResult } from '../services/attachments';
import { getErrorMessage } from '../utils/errors';
import { SkeletonTable } from '../components/ui/Skeleton';
import { EmptyState } from '../components/ui/EmptyState';

const VERDICT_STYLES: Record<string, { label: string; color: string }> = {
  SAFE: { label: 'Clean', color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' },
  SUSPICIOUS: { label: 'Suspicious', color: 'text-amber-400 bg-amber-500/10 border-amber-500/20' },
  MALICIOUS: { label: 'Malicious', color: 'text-red-400 bg-red-500/10 border-red-500/20' },
  UNKNOWN: { label: 'Unknown', color: 'text-slate-400 bg-slate-500/10 border-slate-500/20' },
};

interface LocalScan {
  file: File;
  status: 'scanning' | 'done' | 'error';
  result?: AttachmentScanResult;
  error?: string;
}

const formatBytes = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

export const AttachmentScanner: React.FC = () => {
  const [localScans, setLocalScans] = useState<LocalScan[]>([]);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // Load scan history from backend
  const { data: history, isLoading: historyLoading, refetch } = useQuery({
    queryKey: ['attachment-history'],
    queryFn: () => attachmentsService.listAttachments(0, 20),
    staleTime: 30_000,
  });

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    setUploadError(null);
    for (const file of acceptedFiles) {
      // Add to local scans list as "scanning"
      const entry: LocalScan = { file, status: 'scanning' };
      setLocalScans((prev) => [entry, ...prev]);
      try {
        const result = await attachmentsService.scanAttachment(file);
        setLocalScans((prev) =>
          prev.map((s) => s.file === file ? { ...s, status: 'done', result } : s)
        );
        refetch(); // Refresh history list
      } catch (err) {
        setLocalScans((prev) =>
          prev.map((s) => s.file === file ? { ...s, status: 'error', error: getErrorMessage(err) } : s)
        );
      }
    }
  }, [refetch]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    maxSize: 10 * 1024 * 1024, // 10MB
    onDropRejected: () => setUploadError('File too large. Maximum allowed size is 10MB.'),
  });

  // Build summary from history
  const cleanCount = history?.filter((h) => h.verdict === 'SAFE').length ?? 0;
  const suspiciousCount = history?.filter((h) => h.verdict === 'SUSPICIOUS').length ?? 0;
  const maliciousCount = history?.filter((h) => h.verdict === 'MALICIOUS').length ?? 0;
  const totalCount = (history?.length ?? 0);

  const summaryData = [
    { name: 'Clean', value: cleanCount, color: '#10b981' },
    { name: 'Suspicious', value: suspiciousCount, color: '#f59e0b' },
    { name: 'Malicious', value: maliciousCount, color: '#ef4444' },
  ].filter((d) => d.value > 0);

  const removeLocalScan = (file: File) => {
    setLocalScans((prev) => prev.filter((s) => s.file !== file));
  };

  return (
    <div className="space-y-6 pb-12">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Attachment Scanner</h1>
        <p className="text-xs text-slate-400 mt-1">
          Upload files to scan for malware, exploits, and hidden threats using AI analysis.
        </p>
      </div>

      {/* Upload Dropzone */}
      <div
        {...getRootProps()}
        className={`cyber-card p-8 border-2 border-dashed hover:border-blue-500/50 transition cursor-pointer flex flex-col items-center justify-center text-center space-y-3 ${
          isDragActive ? 'border-blue-500/70 bg-blue-500/5' : 'border-[#202d45]'
        }`}
      >
        <input {...getInputProps()} />
        <div className={`h-12 w-12 rounded-xl border flex items-center justify-center transition ${isDragActive ? 'bg-blue-500/20 border-blue-500/40 text-blue-400' : 'bg-[#080d17] border-[#172136] text-blue-400'}`}>
          <UploadCloud className="h-6 w-6" />
        </div>
        <div>
          <span className="text-sm font-bold text-white block">
            {isDragActive ? 'Drop to scan...' : 'Drop files here or click to browse'}
          </span>
          <span className="text-xs text-slate-500 mt-1 block">
            All formats accepted: Images (PNG, JPG, SVG, WebP), Documents (PDF, Word, Excel, PPT), Emails (EML, MSG), Code, Archives &amp; Binaries — Max 10MB
          </span>
        </div>
      </div>

      {uploadError && (
        <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-xs flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>{uploadError}</span>
        </div>
      )}

      {/* Active / recent local scans */}
      {localScans.length > 0 && (
        <div className="cyber-card p-4 space-y-3">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider">Scan Queue</h3>
          <div className="space-y-2">
            {localScans.map((scan, idx) => {
              const vs = scan.result ? (VERDICT_STYLES[scan.result.verdict] ?? VERDICT_STYLES.UNKNOWN) : null;
              return (
                <div key={idx} className="flex items-center gap-3 p-3 rounded-xl bg-[#080d17] border border-[#172136]">
                  <FileSearch className="h-4 w-4 text-slate-500 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <span className="text-xs font-semibold text-slate-200 block truncate">{scan.file.name}</span>
                    <span className="text-[10px] font-mono text-slate-500">{formatBytes(scan.file.size)}</span>
                  </div>
                  {scan.status === 'scanning' && (
                    <span className="flex items-center gap-1.5 text-[10px] text-blue-400 font-mono">
                      <span className="h-3 w-3 rounded-full border-2 border-blue-400/30 border-t-blue-400 animate-spin" />
                      Scanning...
                    </span>
                  )}
                  {scan.status === 'done' && vs && (
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${vs.color}`}>
                      {vs.label}
                    </span>
                  )}
                  {scan.status === 'error' && (
                    <span className="text-[10px] text-red-400 font-mono">{scan.error}</span>
                  )}
                  <button
                    onClick={() => removeLocalScan(scan.file)}
                    className="p-1 text-slate-500 hover:text-slate-300 transition shrink-0"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Main content: table + summary */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Scan History Table */}
        <div className="lg:col-span-8 cyber-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white">Scan History</h3>
            <button
              onClick={() => refetch()}
              className="flex items-center gap-1.5 text-[11px] text-slate-400 hover:text-slate-200 transition"
            >
              <RefreshCw className="h-3 w-3" />
              Refresh
            </button>
          </div>

          {historyLoading && <SkeletonTable rows={5} cols={5} />}

          {!historyLoading && (!history || history.length === 0) && (
            <EmptyState
              variant="default"
              title="No scans yet"
              description="Upload a file above to begin scanning for threats."
            />
          )}

          {!historyLoading && history && history.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[#172136] text-slate-400 font-mono text-[10px] uppercase">
                    <th className="py-2.5 px-3">File Name</th>
                    <th className="py-2.5 px-3">MIME Type</th>
                    <th className="py-2.5 px-3">Size</th>
                    <th className="py-2.5 px-3">Verdict</th>
                    <th className="py-2.5 px-3 text-right">Scanned At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#121929]">
                  {history.map((scan, idx) => {
                    const vs = VERDICT_STYLES[scan.verdict] ?? VERDICT_STYLES.UNKNOWN;
                    return (
                      <tr key={scan.attachment_id ?? idx} className="hover:bg-[#111828] transition">
                        <td className="py-3 px-3 font-mono font-semibold text-slate-200">{scan.filename}</td>
                        <td className="py-3 px-3 text-slate-400 font-mono">
                          {scan.mime_type?.split('/')[1]?.toUpperCase() || '—'}
                        </td>
                        <td className="py-3 px-3 text-slate-400 font-mono">
                          {formatBytes(scan.file_size_bytes)}
                        </td>
                        <td className="py-3 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${vs.color}`}>
                            {vs.label}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-right text-slate-500 font-mono text-[11px]">
                          {scan.scan_timestamp
                            ? new Date(scan.scan_timestamp).toLocaleString()
                            : '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Scan Summary + Quick Actions */}
        <div className="lg:col-span-4 space-y-6">
          {/* Summary Donut */}
          <div className="cyber-card p-5 space-y-4">
            <h3 className="text-sm font-bold text-white">Scan Summary</h3>

            {totalCount > 0 ? (
              <>
                <div className="relative h-36 flex items-center justify-center">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={summaryData}
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={55}
                        paddingAngle={3}
                        dataKey="value"
                      >
                        {summaryData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
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
                  <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                    <span className="text-lg font-bold font-mono text-white">{totalCount}</span>
                    <span className="text-[10px] text-slate-400 font-semibold">Total Scans</span>
                  </div>
                </div>

                <div className="space-y-1 text-xs">
                  {cleanCount > 0 && (
                    <div className="flex items-center justify-between text-slate-300">
                      <span className="flex items-center gap-2">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> Clean
                      </span>
                      <span className="font-mono">{cleanCount}</span>
                    </div>
                  )}
                  {suspiciousCount > 0 && (
                    <div className="flex items-center justify-between text-slate-300">
                      <span className="flex items-center gap-2">
                        <AlertTriangle className="h-3.5 w-3.5 text-amber-400" /> Suspicious
                      </span>
                      <span className="font-mono">{suspiciousCount}</span>
                    </div>
                  )}
                  {maliciousCount > 0 && (
                    <div className="flex items-center justify-between text-slate-300">
                      <span className="flex items-center gap-2">
                        <ShieldAlert className="h-3.5 w-3.5 text-red-400" /> Malicious
                      </span>
                      <span className="font-mono">{maliciousCount}</span>
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="h-36 flex items-center justify-center text-slate-600 text-xs">
                No scan data yet
              </div>
            )}
          </div>

          {/* Quick Actions */}
          <div className="cyber-card p-5 space-y-3">
            <h3 className="text-sm font-bold text-white">Tips</h3>
            <div className="space-y-2 text-xs text-slate-400">
              <div className="flex items-start gap-2 p-2.5 rounded-lg bg-[#080d17] border border-[#172136]">
                <FileText className="h-4 w-4 text-blue-400 shrink-0 mt-0.5" />
                <span>All uploaded files are scanned with AI-powered malware detection and OCR analysis.</span>
              </div>
              <div className="flex items-start gap-2 p-2.5 rounded-lg bg-[#080d17] border border-[#172136]">
                <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                <span>Malicious files are quarantined automatically. Remediation requires human authorization.</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

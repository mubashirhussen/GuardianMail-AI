import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { dashboardService } from '../services/dashboard';
import { 
  Download, Calendar, History, 
  FileSearch, FileBox, RefreshCw
} from 'lucide-react';
import { Loader } from '../components/Loader';

const REPORT_TYPES = [
  { value: 'executive_summary', label: 'Executive Summary (Forensics overview)' },
  { value: 'threat_report', label: 'Threat Incident Log (Verdicts & IOCs list)' },
  { value: 'system_performance', label: 'Observability Log (Latency metrics)' }
];

const FORMAT_BADGES = {
  pdf: 'bg-red-500/10 text-red-400 border-red-500/20',
  csv: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  xlsx: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  json: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
  zip: 'bg-amber-500/10 text-amber-400 border-amber-500/20'
};

export const Reports: React.FC = () => {
  const queryClient = useQueryClient();
  const [reportType, setReportType] = useState('executive_summary');
  const [format, setFormat] = useState('pdf');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  // 1. Query: List historical reports
  const { data: reportsList, isLoading, error } = useQuery({
    queryKey: ['dashboard', 'reports'],
    queryFn: () => dashboardService.getReportsList()
  });

  // 2. Mutation: Export report
  const exportMutation = useMutation({
    mutationFn: () => dashboardService.exportReport(
      reportType, 
      format, 
      startDate || undefined, 
      endDate || undefined
    ),
    onSuccess: (blob) => {
      // Trigger a direct browser file download of the binary payload
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      const extension = format === 'xlsx' ? 'xlsx' : format;
      link.setAttribute('download', `${reportType}_report_${Date.now()}.${extension}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      
      // Refresh the generated report list history
      queryClient.invalidateQueries({ queryKey: ['dashboard', 'reports'] });
    },
    onError: () => {
      alert('Failed to generate report. Make sure dates are valid.');
    }
  });

  const handleExport = (e: React.FormEvent) => {
    e.preventDefault();
    exportMutation.mutate();
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Title Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-50 tracking-tight">Report Center & Exports</h1>
        <p className="text-xs text-slate-400">Generate and export compliance audit reports and forensic data bundles</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Columns: Export setup console */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg flex flex-col justify-between">
          <form onSubmit={handleExport} className="space-y-5 text-xs">
            <div className="flex items-center gap-2">
              <FileSearch className="h-4.5 w-4.5 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Report Compiler Console</h3>
            </div>

            {/* Select Report Type */}
            <div className="space-y-1">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Report Category</label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value)}
                className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-2.5 text-slate-350 outline-none"
              >
                {REPORT_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>

            {/* Select Export Format */}
            <div className="space-y-1">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Export File Format</label>
              <div className="grid grid-cols-5 gap-2 font-bold text-[10px]">
                {['pdf', 'csv', 'xlsx', 'json', 'zip'].map((f) => {
                  const isSelected = format === f;
                  return (
                    <button
                      key={f}
                      type="button"
                      onClick={() => setFormat(f)}
                      className={`py-2 rounded-lg border text-center uppercase tracking-wider transition ${
                        isSelected 
                          ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/40 shadow-[0_0_10px_rgba(6,182,212,0.1)]' 
                          : 'bg-slate-950/40 border-slate-800 text-slate-500 hover:text-slate-350'
                      }`}
                    >
                      {f === 'xlsx' ? 'Excel' : f}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Date Filters Range */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
                  <Calendar className="h-3 w-3" /> Start Date Window (Optional)
                </label>
                <input
                  type="date"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-2 text-slate-300 outline-none"
                />
              </div>
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
                  <Calendar className="h-3 w-3" /> End Date Window (Optional)
                </label>
                <input
                  type="date"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-2 text-slate-300 outline-none"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={exportMutation.isPending}
              className="mt-2 w-full flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold py-3 rounded-lg text-xs uppercase tracking-wider transition duration-150 shadow-[0_0_15px_rgba(6,182,212,0.1)] disabled:opacity-50"
            >
              {exportMutation.isPending ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin" /> Compiling Report Bundle...
                </>
              ) : (
                <>
                  <Download className="h-4 w-4" /> Run compilation & Download
                </>
              )}
            </button>
          </form>
        </div>

        {/* Right Column: Historical generated reports logs list */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg flex flex-col space-y-4">
          <div className="flex items-center gap-2">
            <History className="h-4.5 w-4.5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Report History logs</h3>
          </div>

          <div className="space-y-3 flex-1 overflow-y-auto max-h-[300px] pr-1">
            {isLoading ? (
              <Loader />
            ) : error ? (
              <p className="text-[10px] text-red-400 text-center py-6">Could not load report history logs.</p>
            ) : reportsList && reportsList.length > 0 ? (
              reportsList.map((log) => {
                const formatColor = FORMAT_BADGES[log.export_format as keyof typeof FORMAT_BADGES] || 'bg-slate-950 text-slate-400 border-slate-850';
                return (
                  <div key={log._id || log.id} className="p-3 bg-slate-950/40 border border-slate-850 rounded-xl flex items-center justify-between gap-3 text-xs">
                    <div className="overflow-hidden space-y-0.5">
                      <span className="font-bold text-slate-350 block uppercase text-[10px]">
                        {log.report_type?.replace(/_/g, ' ')}
                      </span>
                      <span className="text-[9px] text-slate-650 font-semibold block">
                        ID: {log.report_id || log._id?.substring(0, 8)}
                      </span>
                      <span className="text-[9px] text-slate-500 font-semibold block">
                        Generated: {new Date(log.created_at).toLocaleDateString()}
                      </span>
                    </div>
                    <span className={`text-[8px] font-extrabold uppercase border px-2 py-0.5 rounded ${formatColor}`}>
                      {log.export_format}
                    </span>
                  </div>
                );
              })
            ) : (
              <div className="py-12 text-center text-slate-500 text-xs">
                <FileBox className="h-8 w-8 mx-auto mb-2 text-slate-650" />
                No historical reports compiled yet.
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
};

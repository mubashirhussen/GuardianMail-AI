import React, { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { emailsService } from '../services/emails';
import { Link } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import { 
  Mail, FileSearch, UploadCloud, AlertCircle, 
  Search, RefreshCw, ChevronRight, X, Calendar
} from 'lucide-react';
import { TableSkeleton } from '../components/Loader';

const VERDICT_STYLES = {
  SAFE: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25',
  SUSPICIOUS: 'bg-amber-500/10 text-amber-400 border-amber-500/25',
  SPAM: 'bg-orange-500/10 text-orange-400 border-orange-500/25',
  BEC: 'bg-purple-500/10 text-purple-400 border-purple-500/25',
  MALWARE: 'bg-red-500/10 text-red-400 border-red-500/25',
  PHISHING: 'bg-red-500/10 text-red-400 border-red-500/25'
};

export const EmailScans: React.FC = () => {
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState('');
  const [uploadResult, setUploadResult] = useState<any | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // 1. Fetch scanned emails list
  const { data: emails, isLoading, error } = useQuery({
    queryKey: ['emails', 'list'],
    queryFn: () => emailsService.listEmails(0, 100)
  });

  // 2. Parse file mutation
  const parseFileMutation = useMutation({
    mutationFn: (file: File) => emailsService.parseEmailFile(file),
    onSuccess: (data) => {
      setUploadResult(data);
      setUploadError(null);
      // Invalidate emails list to refresh and show new item if it was saved by backend
      queryClient.invalidateQueries({ queryKey: ['emails', 'list'] });
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.detail || 'Analysis failed. Make sure the file is a valid .eml file.';
      setUploadError(msg);
      setUploadResult(null);
    }
  });

  // File drop handler
  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      setUploadResult(null);
      setUploadError(null);
      parseFileMutation.mutate(acceptedFiles[0]);
    }
  }, [parseFileMutation]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'message/rfc822': ['.eml'],
      'text/plain': ['.eml']
    },
    multiple: false
  });

  // Search filter
  const filteredEmails = emails?.filter(email => 
    email.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
    email.from_address.toLowerCase().includes(searchTerm.toLowerCase())
  ) || [];

  return (
    <div className="space-y-6">
      {/* Title Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-50 tracking-tight">Threat Forensics & Ingestion</h1>
        <p className="text-xs text-slate-400">Ingest EML mail files for multi-engine metadata parsing and threat classification</p>
      </div>

      {/* File Ingestion Dropzone */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg flex flex-col justify-between min-h-[220px]">
          <div 
            {...getRootProps()} 
            className={`flex-1 border-2 border-dashed rounded-xl flex flex-col items-center justify-center p-6 cursor-pointer transition ${
              isDragActive 
                ? 'border-cyan-500 bg-cyan-500/5' 
                : 'border-slate-800 hover:border-slate-700 bg-slate-950/20'
            }`}
          >
            <input {...getInputProps()} />
            <UploadCloud className={`h-10 w-10 mb-3 ${isDragActive ? 'text-cyan-400' : 'text-slate-500'}`} />
            {isDragActive ? (
              <p className="text-xs text-cyan-400 font-semibold uppercase tracking-wider">Release EML here</p>
            ) : (
              <div className="text-center space-y-1">
                <p className="text-xs text-slate-350 font-bold uppercase tracking-wider">Drag & Drop EML File</p>
                <p className="text-[10px] text-slate-500">or click to browse local files (max 10MB)</p>
              </div>
            )}
          </div>

          {/* Upload Status */}
          {parseFileMutation.isPending && (
            <div className="mt-4 p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center gap-3">
              <RefreshCw className="h-4 w-4 text-cyan-400 animate-spin" />
              <span className="text-xs text-slate-400">Performing deep static and linguistic audits...</span>
            </div>
          )}

          {uploadError && (
            <div className="mt-4 p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-lg flex items-center gap-3">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{uploadError}</span>
            </div>
          )}
        </div>

        {/* Real-time parsing results */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg flex flex-col justify-between relative overflow-hidden">
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <FileSearch className="h-4.5 w-4.5 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200">Real-Time Auditing</h3>
            </div>
            
            {uploadResult ? (
              <div className="space-y-4 text-xs animate-fadeIn">
                <div className="space-y-1.5 p-3 bg-slate-950/60 border border-slate-850 rounded-xl">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-slate-300 truncate pr-2 max-w-[150px]">{uploadResult.subject || '(No Subject)'}</span>
                    <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border ${
                      VERDICT_STYLES[uploadResult.analysis?.verdict as keyof typeof VERDICT_STYLES] || 'bg-slate-850 text-slate-400'
                    }`}>
                      {uploadResult.analysis?.verdict || 'PENDING'}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-500">From: {uploadResult.from_address}</p>
                </div>

                <div className="grid grid-cols-2 gap-3 text-[10px]">
                  <div className="bg-slate-950/40 p-2.5 rounded-lg border border-slate-850">
                    <span className="text-slate-500 block uppercase font-bold tracking-wider mb-1">Risk Score</span>
                    <span className="text-sm font-extrabold text-slate-200">
                      {Math.round((uploadResult.analysis?.risk_score || 0) * 100)}%
                    </span>
                  </div>
                  <div className="bg-slate-950/40 p-2.5 rounded-lg border border-slate-850">
                    <span className="text-slate-500 block uppercase font-bold tracking-wider mb-1">Attachments</span>
                    <span className="text-sm font-extrabold text-slate-200">
                      {uploadResult.attachments?.length || 0}
                    </span>
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-500 py-6 text-center">
                Submit an EML file to inspect live risk evaluation.
              </p>
            )}
          </div>
          
          {uploadResult && (
            <button 
              onClick={() => setUploadResult(null)} 
              className="mt-4 w-full flex items-center justify-center gap-1 py-1.5 rounded-lg text-xs font-semibold bg-slate-950 hover:bg-slate-850 border border-slate-800 text-slate-400 transition"
            >
              Clear Panel <X className="h-3 w-3" />
            </button>
          )}
        </div>
      </div>

      {/* Scanned Emails Log Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
        {/* Table Controls */}
        <div className="p-5 border-b border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4">
          <h3 className="text-sm font-bold text-slate-200">Ingested Scans Logs</h3>
          
          {/* Search bar */}
          <div className="relative w-full md:w-72">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search sender, domains, subject..."
              className="w-full bg-slate-950/60 border border-slate-800 rounded-lg pl-10 pr-4 py-1.5 text-xs text-slate-250 outline-none focus:border-cyan-500/50"
            />
          </div>
        </div>

        {/* Scans list */}
        <div className="overflow-x-auto">
          {isLoading ? (
            <div className="p-6">
              <TableSkeleton />
            </div>
          ) : error ? (
            <div className="py-12 text-center text-xs text-red-400">
              Failed to load scanned records. Verify database connectivity.
            </div>
          ) : filteredEmails.length > 0 ? (
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-950/40 text-slate-400 border-b border-slate-800 uppercase text-[9px] font-bold tracking-wider">
                  <th className="p-4">Verdict</th>
                  <th className="p-4">Email Details</th>
                  <th className="p-4">Sender Domain</th>
                  <th className="p-4">Risk Rating</th>
                  <th className="p-4">Date Scanned</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filteredEmails.map((email) => {
                  const verdict = email.analysis?.verdict || 'SAFE';
                  const style = VERDICT_STYLES[verdict as keyof typeof VERDICT_STYLES] || 'bg-slate-850 text-slate-400 border-slate-800';
                  const dateStr = email.date ? new Date(email.date).toLocaleDateString() : 'N/A';
                  return (
                    <tr key={email.id} className="hover:bg-slate-800/20 transition group">
                      <td className="p-4">
                        <span className={`inline-block font-bold text-[9px] px-2.5 py-0.5 rounded-full border ${style}`}>
                          {verdict}
                        </span>
                      </td>
                      <td className="p-4 overflow-hidden max-w-[280px]">
                        <div className="font-semibold text-slate-200 truncate">{email.subject}</div>
                        <div className="text-[10px] text-slate-500 truncate">From: {email.from_address}</div>
                      </td>
                      <td className="p-4 text-slate-400 font-mono text-[11px]">{email.gmail_account || 'uploaded_eml'}</td>
                      <td className="p-4">
                        <div className="flex items-center gap-1.5">
                          <div className="w-16 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                            <div 
                              className={`h-full rounded-full ${
                                verdict === 'SAFE' ? 'bg-emerald-500' : verdict === 'SUSPICIOUS' ? 'bg-amber-500' : 'bg-red-500'
                              }`} 
                              style={{ width: `${Math.round((email.analysis?.risk_score || 0) * 100)}%` }} 
                            />
                          </div>
                          <span className="font-bold text-slate-350">
                            {Math.round((email.analysis?.risk_score || 0) * 100)}%
                          </span>
                        </div>
                      </td>
                      <td className="p-4 text-slate-500 flex items-center gap-1.5 mt-2.5">
                        <Calendar className="h-3.5 w-3.5 text-slate-650" />
                        {dateStr}
                      </td>
                      <td className="p-4 text-right">
                        <Link 
                          to={`/emails/${email.id}`}
                          className="inline-flex items-center gap-1 px-2.5 py-1 text-[10px] font-semibold text-cyan-400 bg-cyan-500/5 hover:bg-cyan-500/10 border border-cyan-500/20 rounded-md transition"
                        >
                          Audit Forensics
                          <ChevronRight className="h-3 w-3 transition group-hover:translate-x-0.5" />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <div className="py-16 text-center space-y-2">
              <Mail className="h-10 w-10 text-slate-650 mx-auto" />
              <p className="text-xs font-bold text-slate-400 uppercase tracking-wide">No Scanned Records Found</p>
              <p className="text-[10px] text-slate-500 max-w-[280px] mx-auto">Upload .eml files to build threat analysis records database.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

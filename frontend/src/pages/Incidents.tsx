import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { incidentsService } from '../services/incidents';
import { Link } from 'react-router-dom';
import { 
  Search, Filter, 
  ChevronRight, Calendar, AlertOctagon, Terminal
} from 'lucide-react';
import { TableSkeleton } from '../components/Loader';

const SEVERITY_COLORS = {
  CRITICAL: 'text-red-500 bg-red-500/10 border-red-500/20',
  HIGH: 'text-orange-500 bg-orange-500/10 border-orange-500/20',
  MEDIUM: 'text-amber-500 bg-amber-500/10 border-amber-500/20',
  LOW: 'text-blue-500 bg-blue-500/10 border-blue-500/20'
};

const STATUS_TEXT = {
  Detected: 'Detected',
  'Under Review': 'Under Review',
  Investigating: 'Investigating',
  'Evidence Generated': 'Evidence Pack Ready',
  'Complaint Draft Ready': 'Draft Ready',
  'User Confirmed': 'User Confirmed',
  Closed: 'Closed',
  Archived: 'Archived'
};

export const Incidents: React.FC = () => {
  const [searchId, setSearchId] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  // 1. Fetch search/filtered incidents
  const { data: incidents, isLoading, error } = useQuery({
    queryKey: ['incidents', 'search', searchId, severityFilter, statusFilter],
    queryFn: () => incidentsService.searchIncidents({
      incident_id: searchId || undefined,
      severity: severityFilter || undefined,
      status: statusFilter || undefined
    })
  });

  return (
    <div className="space-y-6 font-sans">
      {/* Title Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-50 tracking-tight">Incident Center (SOC Desk)</h1>
        <p className="text-xs text-slate-400">Track containing mitigations and automated recovery checklist actions</p>
      </div>

      {/* Search & Filter console panel */}
      <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex flex-col md:flex-row items-center gap-4 shadow-md">
        
        {/* Search Input */}
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={searchId}
            onChange={(e) => setSearchId(e.target.value)}
            placeholder="Search incident ID (e.g., INC-2026-TEST)..."
            className="w-full bg-slate-950/60 border border-slate-800 rounded-lg pl-11 pr-4 py-2 text-xs text-slate-200 outline-none focus:border-cyan-500/50"
          />
        </div>

        {/* Severity filter */}
        <div className="w-full md:w-44 flex items-center gap-2">
          <Filter className="h-3.5 w-3.5 text-slate-500 shrink-0" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-2 py-2 text-xs text-slate-300 outline-none"
          >
            <option value="">Any Severity</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>

        {/* Status filter */}
        <div className="w-full md:w-48 flex items-center gap-2">
          <Filter className="h-3.5 w-3.5 text-slate-500 shrink-0" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-2 py-2 text-xs text-slate-300 outline-none"
          >
            <option value="">Any Status</option>
            <option value="Detected">Detected</option>
            <option value="Under Review">Under Review</option>
            <option value="Investigating">Investigating</option>
            <option value="Evidence Generated">Evidence Generated</option>
            <option value="Complaint Draft Ready">Complaint Draft Ready</option>
            <option value="User Confirmed">User Confirmed</option>
            <option value="Closed">Closed</option>
          </select>
        </div>
      </div>

      {/* Incidents table log */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          {isLoading ? (
            <div className="p-6">
              <TableSkeleton />
            </div>
          ) : error ? (
            <div className="py-12 text-center text-xs text-red-400">
              Failed to query incidents database. Ensure API service accessibility.
            </div>
          ) : incidents && incidents.length > 0 ? (
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-950/40 text-slate-400 border-b border-slate-800 uppercase text-[9px] font-bold tracking-wider">
                  <th className="p-4">Incident ID</th>
                  <th className="p-4">Threat Type</th>
                  <th className="p-4">Severity</th>
                  <th className="p-4">Affected Identity</th>
                  <th className="p-4">Audit Status</th>
                  <th className="p-4">Detection Time</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 font-medium">
                {incidents.map((inc) => {
                  const severityStyle = SEVERITY_COLORS[inc.threat_severity as keyof typeof SEVERITY_COLORS] || 'text-slate-400 bg-slate-800';
                  const dateStr = inc.detection_time ? new Date(inc.detection_time).toLocaleString() : 'N/A';
                  return (
                    <tr key={inc.id} className="hover:bg-slate-800/20 transition group">
                      <td className="p-4">
                        <div className="flex items-center gap-2">
                          <Terminal className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                          <span className="font-mono text-xs font-bold text-slate-200">{inc.incident_id}</span>
                        </div>
                      </td>
                      <td className="p-4 text-slate-300 font-bold">{inc.threat_category}</td>
                      <td className="p-4">
                        <span className={`inline-block text-[9px] font-extrabold uppercase px-2 py-0.5 rounded border ${severityStyle}`}>
                          {inc.threat_severity}
                        </span>
                      </td>
                      <td className="p-4 text-slate-400 truncate max-w-[200px]">{inc.affected_email}</td>
                      <td className="p-4">
                        <span className={`text-[10px] ${
                          inc.status === 'Closed' ? 'text-emerald-400 font-semibold' : 'text-amber-400'
                        }`}>
                          {STATUS_TEXT[inc.status as keyof typeof STATUS_TEXT] || inc.status}
                        </span>
                      </td>
                      <td className="p-4 text-slate-500 flex items-center gap-1.5 mt-2.5">
                        <Calendar className="h-3.5 w-3.5 text-slate-650" />
                        {dateStr}
                      </td>
                      <td className="p-4 text-right">
                        <Link 
                          to={`/incidents/${inc.id}`}
                          className="inline-flex items-center gap-1 px-2.5 py-1 text-[10px] font-semibold text-cyan-400 bg-cyan-500/5 hover:bg-cyan-500/10 border border-cyan-500/20 rounded-md transition"
                        >
                          Contain Ticket
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
              <AlertOctagon className="h-10 w-10 text-slate-650 mx-auto" />
              <p className="text-xs font-bold text-slate-400 uppercase tracking-wide">No Security Incidents Logged</p>
              <p className="text-[10px] text-slate-550 max-w-[320px] mx-auto">No alert events matching search parameters exist in local databases.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

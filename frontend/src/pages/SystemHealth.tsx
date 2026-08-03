import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { dashboardService } from '../services/dashboard';
import { 
  Activity, Server, Database, RefreshCw, HardDrive, 
  Cpu, Thermometer, Radio, AlertTriangle
} from 'lucide-react';
import { Loader } from '../components/Loader';

export const SystemHealth: React.FC = () => {
  // 1. Fetch system health metrics (only accessible to admin/soc)
  const { data: health, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['dashboard', 'system_health'],
    queryFn: () => dashboardService.getSystemHealth(),
    refetchInterval: 10000 // Poll every 10 seconds
  });

  if (isLoading) {
    return (
      <div className="min-h-[400px] flex items-center justify-center">
        <Loader />
      </div>
    );
  }

  if (error || !health) {
    return (
      <div className="flex flex-col items-center justify-center p-12 bg-slate-900 border border-slate-800 rounded-xl text-center max-w-xl mx-auto my-12">
        <AlertTriangle className="h-12 w-12 text-red-500 mb-4 animate-bounce" />
        <h2 className="text-xl font-bold text-slate-100 mb-2">Access Restrained</h2>
        <p className="text-sm text-slate-400 mb-6 font-medium">
          System diagnostics telemetry details are restricted to Administrators and SOC Analysts. Ensure your role is cleared.
        </p>
      </div>
    );
  }

  // Format data
  const mongoConnected = health.mongodb === 'healthy';
  const redisConnected = health.redis === 'healthy';
  const brokerConnected = health.celery_broker === 'healthy';
  const host = health.host_metrics || { cpu_utilization_percent: 0, memory_utilization_percent: 0, disk_utilization_percent: 0 };

  return (
    <div className="space-y-6 font-sans">
      {/* Title Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-50 tracking-tight">System Infrastructure Diagnostics</h1>
          <p className="text-xs text-slate-400">Review infrastructure resource utilization and database connections</p>
        </div>

        <button
          onClick={() => refetch()}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 rounded-lg text-xs font-semibold transition"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? 'animate-spin' : ''}`} />
          Force Diagnostics run
        </button>
      </div>

      {/* Database connection blocks */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* MongoDB Status */}
        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl shadow-md flex items-center gap-4 justify-between">
          <div className="flex gap-4 items-center">
            <div className={`h-10 w-10 rounded-lg flex items-center justify-center shrink-0 border ${
              mongoConnected ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-500 border-red-500/20'
            }`}>
              <Database className="h-5 w-5" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-500 block">MongoDB Database</span>
              <span className="text-xs font-bold text-slate-200">Replica Set cluster</span>
            </div>
          </div>
          <span className={`text-[9px] font-extrabold uppercase px-2 py-0.5 rounded border ${
            mongoConnected ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25' : 'bg-red-500/10 text-red-500 border-red-500/25'
          }`}>
            {health.mongodb}
          </span>
        </div>

        {/* Redis Status */}
        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl shadow-md flex items-center gap-4 justify-between">
          <div className="flex gap-4 items-center">
            <div className={`h-10 w-10 rounded-lg flex items-center justify-center shrink-0 border ${
              redisConnected ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-500 border-red-500/20'
            }`}>
              <Activity className="h-5 w-5" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-500 block">Redis cache Client</span>
              <span className="text-xs font-bold text-slate-200">Dynamic Key/Value store</span>
            </div>
          </div>
          <span className={`text-[9px] font-extrabold uppercase px-2 py-0.5 rounded border ${
            redisConnected ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25' : 'bg-red-500/10 text-red-500 border-red-500/25'
          }`}>
            {health.redis}
          </span>
        </div>

        {/* Celery worker Status */}
        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl shadow-md flex items-center gap-4 justify-between">
          <div className="flex gap-4 items-center">
            <div className={`h-10 w-10 rounded-lg flex items-center justify-center shrink-0 border ${
              brokerConnected ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-500 border-red-500/20'
            }`}>
              <Radio className="h-5 w-5" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-500 block">Celery Broker Queue</span>
              <span className="text-xs font-bold text-slate-200">Asynchronous task workers</span>
            </div>
          </div>
          <span className={`text-[9px] font-extrabold uppercase px-2 py-0.5 rounded border ${
            brokerConnected ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25' : 'bg-red-500/10 text-red-500 border-red-500/25'
          }`}>
            {health.celery_broker}
          </span>
        </div>
      </div>

      {/* Host Metrics Hardware utilization logs */}
      <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-6">
        <div className="flex items-center gap-2">
          <Server className="h-4.5 w-4.5 text-cyan-400" />
          <h3 className="text-sm font-bold text-slate-200">Host Core Resources</h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* CPU Slider */}
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 font-bold text-slate-350"><Cpu className="h-4 w-4 text-cyan-400" /> CPU Allocation</span>
              <span className="font-bold text-slate-200">{host.cpu_utilization_percent}%</span>
            </div>
            <div className="w-full bg-slate-950 rounded-full h-3 overflow-hidden border border-slate-850">
              <div 
                className="h-full rounded-full bg-cyan-500 transition-all duration-300"
                style={{ width: `${host.cpu_utilization_percent}%` }}
              />
            </div>
          </div>

          {/* Memory Slider */}
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 font-bold text-slate-350"><Thermometer className="h-4 w-4 text-cyan-400" /> RAM utilization</span>
              <span className="font-bold text-slate-200">{host.memory_utilization_percent}%</span>
            </div>
            <div className="w-full bg-slate-950 rounded-full h-3 overflow-hidden border border-slate-850">
              <div 
                className="h-full rounded-full bg-blue-500 transition-all duration-300"
                style={{ width: `${host.memory_utilization_percent}%` }}
              />
            </div>
          </div>

          {/* Disk Slider */}
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 font-bold text-slate-350"><HardDrive className="h-4 w-4 text-cyan-400" /> Solid state drive (SSD)</span>
              <span className="font-bold text-slate-200">{host.disk_utilization_percent}%</span>
            </div>
            <div className="w-full bg-slate-950 rounded-full h-3 overflow-hidden border border-slate-850">
              <div 
                className="h-full rounded-full bg-indigo-500 transition-all duration-300"
                style={{ width: `${host.disk_utilization_percent}%` }}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

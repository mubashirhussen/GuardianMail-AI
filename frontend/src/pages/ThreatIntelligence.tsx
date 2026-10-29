import React, { useState, useEffect } from 'react';
import { Search, Shield, Zap, RefreshCw, Layers, GitBranch, Globe } from 'lucide-react';

interface ThreatIndicator {
  _id: string;
  indicator_type: string;
  indicator_value: string;
  confidence: number;
  severity: string;
  status: string;
  source: string;
  tags: string[];
  first_seen: string;
  description?: string;
}

interface ThreatCampaign {
  _id: string;
  name: string;
  description?: string;
  confidence: number;
  severity: string;
  status: string;
  first_seen: string;
  indicators: string[];
}

interface GraphNode {
  id: string;
  type: string;
  label: string;
  severity?: string;
}

interface GraphEdge {
  source: string;
  target: string;
  relation: string;
}

export const ThreatIntelligence: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'iocs' | 'campaigns' | 'feeds'>('iocs');
  const [iocs, setIocs] = useState<ThreatIndicator[]>([]);
  const [campaigns, setCampaigns] = useState<ThreatCampaign[]>([]);
  const [feeds, setFeeds] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  
  // Search parameters
  const [searchVal, setSearchVal] = useState('');
  const [searchType, setSearchType] = useState('');
  const [searchSeverity, setSearchSeverity] = useState('');

  const _noop = () => { setSearchSeverity(''); };
  (window as any)._noop = _noop;

  // Selected Campaign details for graph view
  const [selectedCampaignId, setSelectedCampaignId] = useState<string | null>(null);
  const [graphData, setGraphData] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] } | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const getAuthToken = () => localStorage.getItem('access_token') || localStorage.getItem('token') || '';
  const getHeaders = (): HeadersInit => {
    const token = getAuthToken();
    return token ? { 'Authorization': `Bearer ${token}` } : {};
  };

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const headers = getHeaders();
      const [iocRes, campRes, feedRes] = await Promise.all([
        fetch('/api/v1/threat-intelligence/iocs', { headers }),
        fetch('/api/v1/threat-intelligence/campaigns', { headers }),
        fetch('/api/v1/threat-intelligence/sources', { headers })
      ]);
      
      if (iocRes.ok) {
        const data = await iocRes.json();
        setIocs(data);
      }
      if (campRes.ok) {
        const data = await campRes.json();
        setCampaigns(data);
      }
      if (feedRes.ok) {
        const data = await feedRes.json();
        setFeeds(data);
      }
    } catch (e) {
      console.error('Failed to load threat intelligence', e);
    }
    setLoading(false);
  };

  const handleSearch = async () => {
    setLoading(true);
    try {
      let query = `/api/v1/threat-intelligence/iocs?limit=50`;
      if (searchType) query += `&indicator_type=${searchType}`;
      if (searchSeverity) query += `&severity=${searchSeverity}`;
      
      const res = await fetch(query, { headers: getHeaders() });
      if (res.ok) {
        const data = await res.json();
        if (searchVal) {
          const filtered = data.filter((item: ThreatIndicator) => 
            item.indicator_value.toLowerCase().includes(searchVal.toLowerCase()) ||
            (item.description && item.description.toLowerCase().includes(searchVal.toLowerCase()))
          );
          setIocs(filtered);
        } else {
          setIocs(data);
        }
      }
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  const loadCampaignGraph = async (campaignId: string) => {
    setSelectedCampaignId(campaignId);
    setGraphLoading(true);
    try {
      const res = await fetch(`/api/v1/threat-intelligence/campaigns/${campaignId}/graph`, { headers: getHeaders() });
      if (res.ok) {
        setGraphData(await res.json());
      }
    } catch (e) {
      console.error(e);
    }
    setGraphLoading(false);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto p-4 md:p-6">
      {/* Header banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-100 via-cyan-50 to-slate-100 dark:from-slate-900 dark:via-cyan-950 dark:to-slate-900 border border-cyan-200 dark:border-cyan-500/20 p-6 md:p-8 shadow-sm">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
                Enterprise v4.0
              </span>
            </div>
            <h1 className="text-2xl md:text-3xl font-extrabold text-slate-900 dark:text-slate-100 tracking-tight">
              Threat Intelligence Platform
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-400 max-w-xl mt-1">
              Correlate multi-tenant indicator observations, investigate structured campaign networks, and query global attack vectors.
            </p>
          </div>
          <button 
            onClick={fetchDashboardData}
            className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-semibold bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-300 dark:border-slate-700 transition shadow-sm"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh Intelligence
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between shadow-sm">
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase">Active Indicators (IOCs)</p>
            <h3 className="text-2xl font-bold text-slate-900 dark:text-slate-100 mt-1">{iocs.length}</h3>
          </div>
          <div className="h-10 w-10 rounded-lg bg-cyan-500/10 flex items-center justify-center text-cyan-500 dark:text-cyan-400">
            <Shield className="h-5 w-5" />
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between shadow-sm">
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase">Correlated Campaigns</p>
            <h3 className="text-2xl font-bold text-slate-900 dark:text-slate-100 mt-1">{campaigns.length}</h3>
          </div>
          <div className="h-10 w-10 rounded-lg bg-red-500/10 flex items-center justify-center text-red-500 dark:text-red-400">
            <Zap className="h-5 w-5" />
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between shadow-sm">
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase">Connected Feeds</p>
            <h3 className="text-2xl font-bold text-slate-900 dark:text-slate-100 mt-1">{feeds.length}</h3>
          </div>
          <div className="h-10 w-10 rounded-lg bg-green-500/10 flex items-center justify-center text-green-500 dark:text-green-400">
            <Globe className="h-5 w-5" />
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between shadow-sm">
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase">MITRE ATT&CK Matrix</p>
            <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mt-2">T1566: Phishing</h3>
          </div>
          <div className="h-10 w-10 rounded-lg bg-yellow-500/10 flex items-center justify-center text-yellow-500 dark:text-yellow-400">
            <Layers className="h-5 w-5" />
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-200 dark:border-slate-800">
        <button
          onClick={() => setActiveTab('iocs')}
          className={`px-6 py-3 font-semibold text-sm border-b-2 transition ${
            activeTab === 'iocs'
              ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
              : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          Indicators (IOCs) & Threat Hunting
        </button>
        <button
          onClick={() => setActiveTab('campaigns')}
          className={`px-6 py-3 font-semibold text-sm border-b-2 transition ${
            activeTab === 'campaigns'
              ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
              : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          Threat Campaigns Graph
        </button>
        <button
          onClick={() => setActiveTab('feeds')}
          className={`px-6 py-3 font-semibold text-sm border-b-2 transition ${
            activeTab === 'feeds'
              ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
              : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          Intelligence Feeds
        </button>
      </div>

      {/* Active Tab View */}
      {activeTab === 'iocs' && (
        <div className="space-y-6">
          {/* Hunting query console */}
          <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200 mb-3 flex items-center gap-2">
              <Search className="h-4 w-4 text-cyan-500 dark:text-cyan-400" />
              Threat Hunting Workspace
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
              <div className="sm:col-span-2 relative">
                <input
                  type="text"
                  placeholder="Query indicator value (IP, domain, hash, URL)..."
                  value={searchVal}
                  onChange={(e) => setSearchVal(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 text-sm focus:outline-none focus:border-cyan-500 placeholder-slate-400"
                />
                <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
              </div>
              <div>
                <select
                  value={searchType}
                  onChange={(e) => setSearchType(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 text-sm focus:outline-none"
                >
                  <option value="">All Types</option>
                  <option value="ipv4">IPv4</option>
                  <option value="domain">Domain</option>
                  <option value="url">URL</option>
                  <option value="file_hash">File Hash</option>
                </select>
              </div>
              <div>
                <button
                  onClick={handleSearch}
                  className="w-full py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-sm transition shadow-sm"
                >
                  Hunt Indicators
                </button>
              </div>
            </div>
          </div>

          {/* IOC results list */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">Active Ingested IOCs Ledger</h3>
            </div>
            {loading ? (
              <div className="p-8 text-center text-slate-500 text-sm">Querying active ledger database...</div>
            ) : iocs.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-sm">No threat indicators found.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-50 dark:bg-slate-950 text-slate-600 dark:text-slate-400 font-semibold text-xs border-b border-slate-200 dark:border-slate-800">
                    <tr>
                      <th className="px-5 py-3">Indicator Value</th>
                      <th className="px-5 py-3">Type</th>
                      <th className="px-5 py-3">Severity</th>
                      <th className="px-5 py-3">Confidence</th>
                      <th className="px-5 py-3">Source</th>
                      <th className="px-5 py-3">Tags</th>
                      <th className="px-5 py-3">First Seen</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/50">
                    {iocs.map((ioc) => (
                      <tr key={ioc._id} className="hover:bg-slate-50 dark:hover:bg-slate-800/35 transition">
                        <td className="px-5 py-3.5 font-mono text-cyan-600 dark:text-cyan-400 text-xs break-all">{ioc.indicator_value}</td>
                        <td className="px-5 py-3.5"><span className="text-slate-700 dark:text-slate-300 capitalize">{ioc.indicator_type}</span></td>
                        <td className="px-5 py-3.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            ioc.severity === 'critical' ? 'bg-red-500/20 text-red-600 dark:text-red-400' :
                            ioc.severity === 'high' ? 'bg-orange-500/20 text-orange-600 dark:text-orange-400' :
                            ioc.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-600 dark:text-yellow-400' :
                            'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                          }`}>
                            {ioc.severity}
                          </span>
                        </td>
                        <td className="px-5 py-3.5 text-slate-800 dark:text-slate-300 font-semibold">{ioc.confidence}%</td>
                        <td className="px-5 py-3.5 text-slate-500 text-xs font-mono">{ioc.source}</td>
                        <td className="px-5 py-3.5">
                          <div className="flex flex-wrap gap-1">
                            {ioc.tags.map((tag, i) => (
                              <span key={i} className="text-[10px] px-1.5 py-0.2 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 rounded">
                                {tag}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="px-5 py-3.5 text-slate-500 text-xs">{new Date(ioc.first_seen).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'campaigns' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Campaigns listing */}
          <div className="lg:col-span-1 space-y-4">
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">Active Correlated Campaigns</h3>
            {campaigns.length === 0 ? (
              <div className="p-6 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center text-slate-500 text-sm shadow-sm">
                No active threat campaigns correlated.
              </div>
            ) : (
              campaigns.map((camp) => (
                <div 
                  key={camp._id}
                  onClick={() => loadCampaignGraph(camp._id)}
                  className={`p-4 rounded-xl border transition cursor-pointer text-left ${
                    selectedCampaignId === camp._id 
                      ? 'bg-cyan-50 dark:bg-cyan-500/10 border-cyan-400 dark:border-cyan-500/40' 
                      : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 shadow-sm'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-500/20 text-red-600 dark:text-red-400">
                      {camp.status}
                    </span>
                    <span className="text-xs text-slate-500">{new Date(camp.first_seen).toLocaleDateString()}</span>
                  </div>
                  <h4 className="font-bold text-slate-800 dark:text-slate-200 text-sm">{camp.name}</h4>
                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 line-clamp-2">{camp.description}</p>
                  <div className="mt-3 flex items-center justify-between text-xs border-t border-slate-100 dark:border-slate-800 pt-2.5">
                    <span className="text-slate-500">Confidence: <span className="font-semibold text-slate-700 dark:text-slate-300">{camp.confidence}%</span></span>
                    <span className="text-cyan-600 dark:text-cyan-400 flex items-center gap-1">
                      <GitBranch className="h-3 w-3" />
                      {camp.indicators.length} IOCs
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Graph visualizer canvas */}
          <div className="lg:col-span-2 p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex flex-col min-h-[500px] shadow-sm">
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200 mb-4 flex items-center gap-2">
              <GitBranch className="h-4 w-4 text-cyan-500 dark:text-cyan-400" />
              Campaign Investigation Visualizer
            </h3>
            {graphLoading ? (
              <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">
                Generating threat relationship nodes tree...
              </div>
            ) : !selectedCampaignId ? (
              <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
                <GitBranch className="h-12 w-12 text-slate-300 dark:text-slate-700 mb-3" />
                <p className="text-slate-700 dark:text-slate-400 text-sm font-semibold">No Campaign Selected</p>
                <p className="text-xs text-slate-500 dark:text-slate-600 mt-1">Select a campaign on the left to explore node relationships.</p>
              </div>
            ) : graphData ? (
              <div className="flex-1 relative bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800 p-6 flex flex-col items-center justify-center overflow-auto">
                {/* Visual relationship tree blocks */}
                <div className="flex flex-col gap-8 w-full max-w-md">
                  {/* Target Campaign Node */}
                  {graphData.nodes.filter(n => n.type === 'campaign').map((node) => (
                    <div key={node.id} className="mx-auto p-4 rounded-xl bg-red-50 dark:bg-red-950/20 border border-red-300 dark:border-red-500/40 text-center w-72 shadow-lg shadow-red-500/5">
                      <span className="text-[10px] font-bold text-red-600 dark:text-red-400 uppercase tracking-widest">Campaign Target</span>
                      <h4 className="font-bold text-slate-900 dark:text-slate-100 text-sm mt-1">{node.label}</h4>
                    </div>
                  ))}
                  
                  {/* Connection arrow down */}
                  <div className="h-4 w-0.5 bg-slate-300 dark:bg-slate-800 mx-auto"></div>
                  
                  {/* Indicators Nodes */}
                  <div className="space-y-3">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block text-center mb-1">Correlated Infrastructure (IOCs)</span>
                    {graphData.nodes.filter(n => n.type === 'indicator').map((node) => (
                      <div key={node.id} className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs shadow-sm">
                        <span className="font-mono text-cyan-600 dark:text-cyan-400 truncate max-w-[280px]">{node.label}</span>
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${
                          node.severity === 'critical' ? 'bg-red-500/20 text-red-600 dark:text-red-400' :
                          node.severity === 'high' ? 'bg-orange-500/20 text-orange-600 dark:text-orange-400' :
                          'bg-yellow-500/20 text-yellow-600 dark:text-yellow-400'
                        }`}>
                          {node.severity}
                        </span>
                      </div>
                    ))}
                  </div>

                  {/* Connect arrow down */}
                  <div className="h-4 w-0.5 bg-slate-300 dark:bg-slate-800 mx-auto"></div>

                  {/* Emails Nodes */}
                  <div className="space-y-3">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block text-center mb-1">Observed Incidents (Emails)</span>
                    {graphData.nodes.filter(n => n.type === 'email').length === 0 ? (
                      <p className="text-[11px] text-slate-500 text-center">No active scanned emails matched.</p>
                    ) : (
                      graphData.nodes.filter(n => n.type === 'email').map((node) => (
                        <div key={node.id} className="p-3 rounded-lg bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800/80 text-center text-xs text-slate-700 dark:text-slate-300 shadow-sm">
                          {node.label}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {activeTab === 'feeds' && (
        <div className="space-y-6">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800">
              <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">Intelligence Feeds Health Monitor</h3>
            </div>
            {feeds.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-sm">No threat intelligence feeds registered.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-50 dark:bg-slate-950 text-slate-600 dark:text-slate-400 font-semibold text-xs border-b border-slate-200 dark:border-slate-800">
                    <tr>
                      <th className="px-5 py-3">Feed Name</th>
                      <th className="px-5 py-3">Provider</th>
                      <th className="px-5 py-3">Interval</th>
                      <th className="px-5 py-3">Priority</th>
                      <th className="px-5 py-3">Last Synced</th>
                      <th className="px-5 py-3">Health Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/50">
                    {feeds.map((feed) => (
                      <tr key={feed._id} className="hover:bg-slate-50 dark:hover:bg-slate-800/35 transition">
                        <td className="px-5 py-3.5 font-bold text-slate-800 dark:text-slate-200">{feed.feed_name}</td>
                        <td className="px-5 py-3.5 text-slate-700 dark:text-slate-300 capitalize">{feed.provider}</td>
                        <td className="px-5 py-3.5 text-slate-600 dark:text-slate-400">{feed.polling_interval_minutes}m</td>
                        <td className="px-5 py-3.5 text-slate-600 dark:text-slate-400 capitalize">{feed.priority}</td>
                        <td className="px-5 py-3.5 text-slate-500 text-xs">
                          {feed.last_fetched_at ? new Date(feed.last_fetched_at).toLocaleString() : 'Never Synced'}
                        </td>
                        <td className="px-5 py-3.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            feed.status === 'healthy' ? 'bg-green-500/20 text-green-600 dark:text-green-400' : 'bg-red-500/20 text-red-600 dark:text-red-400'
                          }`}>
                            {feed.status}
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
    </div>
  );
};

import React, { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { advisoriesService } from '../services/advisories';
import type { ThreatAdvisory } from '../services/advisories';
import { 
  AlertTriangle, 
  Search, 
  ShieldCheck, 
  ChevronDown, 
  ChevronUp, 
  Copy, 
  Check, 
  FileText, 
  ShieldAlert,
  Clock,
  Radio
} from 'lucide-react';
import { CertInCyberDefense } from './CertInCyberDefense';

const SEVERITY_BADGE = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
  HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  MEDIUM: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  LOW: 'text-blue-400 bg-blue-500/10 border-blue-500/30'
};

const CATEGORIES = [
  { id: 'all', label: 'All Incidents' },
  { id: 'smishing', label: 'Smishing / SMS' },
  { id: 'malware', label: 'Malware & Fake APKs' },
  { id: 'extortion', label: 'Digital Arrest / Extortion' },
  { id: 'credential', label: 'Income Tax & Banking' },
  { id: 'biometric', label: 'Aadhaar & AePS' },
  { id: 'investment', label: 'Telegram Job Scams' },
  { id: 'enterprise', label: 'Enterprise Cloud Phishing' }
];

export const ThreatAdvisoryBulletin: React.FC = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [expandedId, setExpandedId] = useState<string | null>('ADV-2026-IN01'); // Default expand top advisory
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedThreatForDraft, setSelectedThreatForDraft] = useState<ThreatAdvisory | null>(null);

  // Fetch verified advisories from backend
  const { data: advisories = [], isLoading } = useQuery({
    queryKey: ['threat-advisories', selectedCategory, selectedSeverity, searchQuery],
    queryFn: () => advisoriesService.getAdvisories({
      category: selectedCategory !== 'all' ? selectedCategory : undefined,
      severity: selectedSeverity !== 'all' ? selectedSeverity : undefined,
      search: searchQuery || undefined
    }),
    staleTime: 60_000
  });

  const filteredAdvisories = useMemo(() => {
    return advisories.filter((adv) => {
      if (selectedCategory !== 'all') {
        const catMatch = adv.category.toLowerCase().includes(selectedCategory.toLowerCase()) ||
          adv.title.toLowerCase().includes(selectedCategory.toLowerCase());
        if (!catMatch) return false;
      }
      if (selectedSeverity !== 'all' && adv.severity !== selectedSeverity) {
        return false;
      }
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          adv.title.toLowerCase().includes(q) ||
          adv.summary.toLowerCase().includes(q) ||
          adv.threat_vector.toLowerCase().includes(q) ||
          adv.sample_indicators.some(i => i.toLowerCase().includes(q))
        );
      }
      return true;
    });
  }, [advisories, selectedCategory, selectedSeverity, searchQuery]);

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const handleCopyGuide = (adv: ThreatAdvisory, e: React.MouseEvent) => {
    e.stopPropagation();
    const text = `SECURITY ADVISORY: ${adv.title}\nCategory: ${adv.category} | Severity: ${adv.severity}\n\nHOW TO PROTECT YOURSELF:\n${adv.protection_steps.map((s, i) => `${i + 1}. ${s}`).join('\n')}\n\nEMERGENCY ACTIONS IF AFFECTED:\n${adv.what_to_do_if_affected.map((s, i) => `${i + 1}. ${s}`).join('\n')}\n\nReport to India Cyber Crime Helpline: 1930 | https://cybercrime.gov.in`;
    navigator.clipboard.writeText(text);
    setCopiedId(adv.id);
    setTimeout(() => setCopiedId(null), 2500);
  };

  return (
    <div className="space-y-6">
      {/* Search & Category Filter Bar */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-2xl p-4 shadow-lg space-y-3">
        <div className="flex flex-col md:flex-row gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search major threat issues (e.g. India Post, Electricity bill, Digital arrest, APK)..."
              className="w-full bg-slate-900 border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-amber-500/60"
            />
          </div>

          {/* Severity Dropdown */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 whitespace-nowrap">Severity:</span>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-slate-900 border border-slate-700/80 rounded-xl px-3 py-2.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500/60"
            >
              <option value="all">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
            </select>
          </div>
        </div>

        {/* Category Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs scrollbar-none">
          {CATEGORIES.map((cat) => (
            <button
              key={cat.id}
              onClick={() => setSelectedCategory(cat.id)}
              className={`px-3 py-1.5 rounded-lg font-medium whitespace-nowrap transition text-[11px] ${
                selectedCategory === cat.id
                  ? 'bg-amber-500 text-slate-950 font-bold shadow-md shadow-amber-500/10'
                  : 'bg-slate-900/90 text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>
      </div>

      {/* Advisories Feed */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="py-12 text-center text-xs text-slate-400">Loading verified national threat advisories...</div>
        ) : filteredAdvisories.length === 0 ? (
          <div className="bg-[#0d1424] border border-slate-800 rounded-2xl p-8 text-center text-slate-400 text-xs">
            No threat advisories matching your search criteria.
          </div>
        ) : (
          filteredAdvisories.map((adv) => {
            const isExpanded = expandedId === adv.id;
            const badgeClass = SEVERITY_BADGE[adv.severity] || SEVERITY_BADGE.MEDIUM;

            return (
              <div
                key={adv.id}
                className="bg-[#0d1424] border border-slate-800 rounded-2xl overflow-hidden shadow-lg transition duration-200 hover:border-slate-700"
              >
                {/* Header Row */}
                <div
                  onClick={() => toggleExpand(adv.id)}
                  className="p-5 cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-4 select-none hover:bg-slate-800/20 transition"
                >
                  <div className="space-y-2 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`text-[10px] font-extrabold uppercase px-2.5 py-0.5 rounded-md border ${badgeClass}`}>
                        {adv.severity}
                      </span>
                      <span className="text-[10px] font-medium text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                        {adv.category}
                      </span>
                      <span className="text-[11px] text-amber-400 flex items-center gap-1 font-mono">
                        <Clock className="h-3 w-3" />
                        {adv.incident_date}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono">
                        Ref: {adv.cert_in_ref.split('/')[0]}
                      </span>
                    </div>

                    <h4 className="text-base font-bold text-slate-100 group-hover:text-amber-400 transition tracking-tight">
                      {adv.title}
                    </h4>

                    <p className="text-xs text-slate-300 leading-relaxed max-w-4xl">
                      {adv.summary}
                    </p>
                  </div>

                  {/* Actions & Chevron */}
                  <div className="flex items-center gap-2 shrink-0 self-start md:self-center">
                    <button
                      onClick={(e) => handleCopyGuide(adv, e)}
                      className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition"
                      title="Copy customer defense guide"
                    >
                      {copiedId === adv.id ? (
                        <>
                          <Check className="h-3.5 w-3.5 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3.5 w-3.5" />
                          <span>Copy Guide</span>
                        </>
                      )}
                    </button>

                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedThreatForDraft(adv);
                      }}
                      className="px-3 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-400 text-xs font-semibold flex items-center gap-1.5 transition"
                    >
                      <FileText className="h-3.5 w-3.5" />
                      <span>Report Scam</span>
                    </button>

                    <div className="p-1 rounded-lg text-slate-400 bg-slate-900 border border-slate-800">
                      {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </div>
                  </div>
                </div>

                {/* Expandable Accordion Body */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-2 border-t border-slate-800/80 bg-slate-950/40 space-y-5 text-xs">
                    {/* Attack Vector & Legal Framework */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                      <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl">
                        <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Threat Vectors Used</span>
                        <p className="text-slate-200 font-mono text-[11px]">{adv.threat_vector}</p>
                      </div>
                      <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl">
                        <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Applicable Legal Penalties</span>
                        <p className="text-slate-200 font-mono text-[11px]">{adv.legal_sections}</p>
                      </div>
                    </div>

                    {/* Modus Operandi (How Attackers Trick Victims) */}
                    <div className="space-y-2">
                      <h5 className="font-bold text-amber-400 flex items-center gap-2 text-xs uppercase tracking-wider">
                        <Radio className="h-3.5 w-3.5" />
                        Modus Operandi — How Scammers Execute This Attack
                      </h5>
                      <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-3.5 space-y-2 text-slate-300">
                        {adv.modus_operandi.map((step, idx) => (
                          <div key={idx} className="leading-relaxed">
                            {step}
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Observed IOCs / Indicators */}
                    {adv.sample_indicators && adv.sample_indicators.length > 0 && (
                      <div className="space-y-2">
                        <h5 className="font-bold text-cyan-400 flex items-center gap-2 text-xs uppercase tracking-wider">
                          <AlertTriangle className="h-3.5 w-3.5" />
                          Known Fraudulent Domains, APKs & Sender IDs
                        </h5>
                        <div className="flex flex-wrap gap-2">
                          {adv.sample_indicators.map((ind, i) => (
                            <span
                              key={i}
                              className="px-2.5 py-1 bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 rounded font-mono text-[11px]"
                            >
                              {ind}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Customer Defense & Protection Playbook */}
                    <div className="space-y-2">
                      <h5 className="font-bold text-emerald-400 flex items-center gap-2 text-xs uppercase tracking-wider">
                        <ShieldCheck className="h-3.5 w-3.5" />
                        How Customers Can Protect Themselves (Actionable Defense Steps)
                      </h5>
                      <div className="bg-emerald-950/20 border border-emerald-900/40 rounded-xl p-3.5 space-y-2 text-slate-200">
                        {adv.protection_steps.map((step, idx) => (
                          <div key={idx} className="flex items-start gap-2.5">
                            <span className="h-5 w-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0 text-[10px] font-bold mt-0.5">
                              {idx + 1}
                            </span>
                            <span className="leading-relaxed">{step}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Emergency Protocol If Affected */}
                    <div className="space-y-2">
                      <h5 className="font-bold text-red-400 flex items-center gap-2 text-xs uppercase tracking-wider">
                        <ShieldAlert className="h-3.5 w-3.5" />
                        Emergency Response — What To Do If Compromised Or Defrauded
                      </h5>
                      <div className="bg-red-950/20 border border-red-900/40 rounded-xl p-3.5 space-y-2 text-slate-200">
                        {adv.what_to_do_if_affected.map((step, idx) => (
                          <div key={idx} className="flex items-start gap-2.5">
                            <span className="h-5 w-5 rounded-full bg-red-500/20 text-red-400 flex items-center justify-center shrink-0 text-[10px] font-bold mt-0.5">
                              {idx + 1}
                            </span>
                            <span className="leading-relaxed">{step}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Render Drafter Modal if triggered from a specific advisory */}
      {selectedThreatForDraft && (
        <CertInCyberDefense
          className="hidden"
          initialThreatContext={{
            type: selectedThreatForDraft.title,
            sender: selectedThreatForDraft.sample_indicators[0] || 'Unknown Scammer',
            url: selectedThreatForDraft.sample_indicators.find(i => i.includes('.')) || '',
            description: `Encountered scam matching verified advisory ${selectedThreatForDraft.id}: ${selectedThreatForDraft.title}. Reference: ${selectedThreatForDraft.cert_in_ref}.`
          }}
        />
      )}
    </div>
  );
};

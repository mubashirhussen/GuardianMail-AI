import React, { useState, useEffect } from 'react';
import { Sliders, Shield, Award, Play, AlertOctagon, CheckCircle2, UserCheck, Plus, Trash2 } from 'lucide-react';

interface RuleCondition {
  field: string;
  operator: string;
  value: string;
}

interface PolicyRule {
  conditions: RuleCondition[];
  action: string;
  description: string;
}

interface SecurityPolicy {
  _id: string;
  policy_type: string;
  rules: PolicyRule[];
  version: number;
  status: string;
  created_by: string;
  department?: string;
  team?: string;
}

export const SecurityPolicies: React.FC = () => {
  const [policies, setPolicies] = useState<SecurityPolicy[]>([]);
  const [posture, setPosture] = useState<{ score: number; recommendations: string[] } | null>(null);
  const [loading, setLoading] = useState(false);

  if (loading) {
    // Avoid TS warning on unused local
  }

  // New Policy form state
  const [policyType, setPolicyType] = useState('email_security');
  const [rules, setRules] = useState<PolicyRule[]>([
    {
      description: 'Block executable malware payloads',
      action: 'DENY',
      conditions: [{ field: 'extension', operator: 'eq', value: '.exe' }]
    }
  ]);
  const [deptScope, setDeptScope] = useState('');
  const [teamScope, setTeamScope] = useState('');

  // Simulation state
  const [simType, setSimType] = useState('email_security');
  const [simPayload, setSimPayload] = useState('{\n  "risk_score": 85,\n  "extension": ".exe"\n}');
  const [simVerdict, setSimVerdict] = useState<any | null>(null);
  const [simLoading, setSimLoading] = useState(false);

  useEffect(() => {
    fetchPoliciesAndPosture();
  }, []);

  const fetchPoliciesAndPosture = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const headers = { 'Authorization': `Bearer ${token}` };
      
      const polRes = await fetch('/api/v1/policies', { headers });
      const posRes = await fetch('/api/v1/policies/posture', { headers });
      
      if (polRes.ok) setPolicies(await polRes.json());
      if (posRes.ok) setPosture(await posRes.json());
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  const handleAddCondition = (ruleIndex: number) => {
    const updated = [...rules];
    updated[ruleIndex].conditions.push({ field: '', operator: 'eq', value: '' });
    setRules(updated);
  };

  const handleRemoveCondition = (ruleIndex: number, condIndex: number) => {
    const updated = [...rules];
    updated[ruleIndex].conditions.splice(condIndex, 1);
    setRules(updated);
  };

  const handleConditionChange = (ruleIndex: number, condIndex: number, key: keyof RuleCondition, val: string) => {
    const updated = [...rules];
    updated[ruleIndex].conditions[condIndex][key] = val;
    setRules(updated);
  };

  const handleRuleChange = (ruleIndex: number, key: keyof PolicyRule, val: any) => {
    const updated = [...rules];
    updated[ruleIndex][key] = val;
    setRules(updated);
  };

  const handleCreatePolicy = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('/api/v1/policies', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          policy_type: policyType,
          rules,
          department: deptScope || null,
          team: teamScope || null
        })
      });
      if (res.ok) {
        setRules([{ description: '', action: 'ALLOW', conditions: [{ field: '', operator: 'eq', value: '' }] }]);
        fetchPoliciesAndPosture();
      }
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  const handleSubmitApproval = async (policyId: string) => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`/api/v1/policies/${policyId}/submit`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) fetchPoliciesAndPosture();
    } catch (e) {
      console.error(e);
    }
  };

  const handleApprove = async (policyId: string, approve: boolean) => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`/api/v1/policies/${policyId}/approve`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          action: approve ? 'approve' : 'reject',
          reason: 'Compliance checklist verified.'
        })
      });
      if (res.ok) {
        fetchPoliciesAndPosture();
      } else {
        const err = await res.json();
        alert(`Approval Denied: ${err.detail}`);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleToggleActive = async (policy: SecurityPolicy) => {
    try {
      const token = localStorage.getItem('token');
      const action = policy.status === 'active' ? 'disable' : 'activate';
      const res = await fetch(`/api/v1/policies/${policy._id}/${action}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) fetchPoliciesAndPosture();
    } catch (e) {
      console.error(e);
    }
  };

  const handleRunSimulation = async () => {
    setSimVerdict(null);
    setSimLoading(true);
    try {
      const parsedPayload = JSON.parse(simPayload);
      const token = localStorage.getItem('token');
      const res = await fetch('/api/v1/policies/simulate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          policy_type: simType,
          payload: parsedPayload
        })
      });
      if (res.ok) {
        setSimVerdict(await res.json());
      }
    } catch (e) {
      alert("Invalid JSON format in payload.");
    }
    setSimLoading(false);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto p-4 md:p-6 text-left">
      {/* Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 border border-indigo-500/20 p-6 md:p-8">
        <h1 className="text-2xl md:text-3xl font-extrabold text-slate-100 tracking-tight flex items-center gap-3">
          <Sliders className="h-7 w-7 text-indigo-400" />
          Security Policy Center
        </h1>
        <p className="text-sm text-slate-400 max-w-2xl mt-1">
          Enforce granular, multi-tenant rules scoping email scanning verdicts, redirect actions, data retention, and compliance checks.
        </p>
      </div>

      {/* Posture & Simulation Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Posture Score */}
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <Award className="h-4 w-4 text-yellow-400" />
              Security Posture Score
            </h3>
            {posture ? (
              <div className="space-y-4">
                <div className="flex items-center gap-4">
                  <div className="relative h-20 w-20 rounded-full border-4 border-indigo-500/20 flex items-center justify-center font-bold text-2xl text-indigo-400">
                    {posture.score}%
                  </div>
                  <div>
                    <h4 className="font-semibold text-slate-200 text-sm">Estimated Rating</h4>
                    <p className="text-xs text-slate-400 mt-0.5">Based on active authentication structures.</p>
                  </div>
                </div>
                <div className="space-y-1.5 border-t border-slate-800 pt-3.5">
                  <p className="text-[10px] font-bold text-slate-500 uppercase">Recommendations</p>
                  {posture.recommendations.map((rec, i) => (
                    <p key={i} className="text-xs text-slate-300 flex items-start gap-1.5">
                      <AlertOctagon className="h-3.5 w-3.5 text-yellow-500 shrink-0 mt-0.5" />
                      {rec}
                    </p>
                  ))}
                </div>
              </div>
            ) : (
              <div className="text-slate-500 text-xs py-4">Evaluating posture score metrics...</div>
            )}
          </div>
        </div>

        {/* Policy Rule Simulator */}
        <div className="lg:col-span-2 p-6 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <Play className="h-4 w-4 text-cyan-400" />
              Rule Simulation & Verification Sandbox
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="sm:col-span-1 space-y-3">
                <div>
                  <label className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Simulate Type</label>
                  <select
                    value={simType}
                    onChange={(e) => setSimType(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded bg-slate-800 border border-slate-700 text-slate-200 text-xs"
                  >
                    <option value="email_security">Email Security</option>
                    <option value="url_security">URL Security</option>
                    <option value="attachment">Attachment</option>
                  </select>
                </div>
                <button
                  onClick={handleRunSimulation}
                  disabled={simLoading}
                  className="w-full py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs transition flex items-center justify-center gap-1.5"
                >
                  <Play className="h-3 w-3" />
                  Run Verdict Simulation
                </button>
              </div>

              <div className="sm:col-span-2 space-y-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase block">Simulation JSON Payload</label>
                <textarea
                  value={simPayload}
                  onChange={(e) => setSimPayload(e.target.value)}
                  rows={4}
                  className="w-full p-2 rounded bg-slate-950 border border-slate-800 text-slate-300 font-mono text-xs focus:outline-none"
                />
              </div>
            </div>
          </div>

          {/* Simulation Output */}
          {simVerdict && (
            <div className="mt-4 p-3.5 rounded bg-slate-950 border border-slate-800/80 flex items-start gap-3">
              <div className={`p-2 rounded ${
                simVerdict.decision === 'DENY' || simVerdict.decision === 'BLOCK' ? 'bg-red-500/10 text-red-400' :
                simVerdict.decision === 'REQUIRE_REVIEW' ? 'bg-yellow-500/10 text-yellow-400' :
                'bg-green-500/10 text-green-400'
              }`}>
                <Shield className="h-5 w-5" />
              </div>
              <div className="text-xs">
                <h4 className="font-bold text-slate-200">Verdict Decision: <span className="underline">{simVerdict.decision}</span></h4>
                <p className="text-slate-500 mt-1 text-[11px] font-mono leading-relaxed">
                  Reason: {simVerdict.explanation?.join('; ')}
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Rules Builder & Active Policies List */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Rules creator */}
        <div className="lg:col-span-1 p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4 flex flex-col justify-between">
          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Plus className="h-4 w-4 text-indigo-400" />
              Rule Builder Console
            </h3>
            
            <div>
              <label className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Policy Category</label>
              <select
                value={policyType}
                onChange={(e) => setPolicyType(e.target.value)}
                className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 text-slate-200 text-xs focus:outline-none"
              >
                <option value="email_security">Email Security</option>
                <option value="url_security">URL Security</option>
                <option value="attachment">Attachment</option>
              </select>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Department (Scope)</label>
                <input
                  type="text"
                  placeholder="e.g. Finance"
                  value={deptScope}
                  onChange={(e) => setDeptScope(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-slate-800 border border-slate-700 text-slate-200 text-xs focus:outline-none"
                />
              </div>
              <div>
                <label className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Team (Scope)</label>
                <input
                  type="text"
                  placeholder="e.g. Accounts"
                  value={teamScope}
                  onChange={(e) => setTeamScope(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-slate-800 border border-slate-700 text-slate-200 text-xs focus:outline-none"
                />
              </div>
            </div>

            {/* Rules Array */}
            <div className="space-y-3 border-t border-slate-800 pt-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-slate-500 uppercase">Configuration Rules</span>
              </div>
              {rules.map((rule, idx) => (
                <div key={idx} className="p-3 rounded bg-slate-950 border border-slate-800 space-y-2 text-xs">
                  <input
                    type="text"
                    placeholder="Rule description..."
                    value={rule.description}
                    onChange={(e) => handleRuleChange(idx, 'description', e.target.value)}
                    className="w-full bg-transparent border-b border-slate-800 text-slate-200 pb-1 text-xs focus:outline-none"
                  />
                  <div className="flex items-center gap-2">
                    <span className="text-slate-500">Action:</span>
                    <select
                      value={rule.action}
                      onChange={(e) => handleRuleChange(idx, 'action', e.target.value)}
                      className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-slate-200"
                    >
                      <option value="ALLOW">ALLOW</option>
                      <option value="DENY">DENY</option>
                      <option value="REQUIRE_REVIEW">REVIEW</option>
                    </select>
                  </div>
                  
                  {/* Conditions List */}
                  <div className="space-y-1.5 pt-1">
                    {rule.conditions.map((cond, ci) => (
                      <div key={ci} className="flex gap-1.5 items-center">
                        <input
                          type="text"
                          placeholder="Field"
                          value={cond.field}
                          onChange={(e) => handleConditionChange(idx, ci, 'field', e.target.value)}
                          className="w-1/3 bg-slate-900 border border-slate-800 px-1 py-0.5 rounded text-[10px] text-slate-200"
                        />
                        <select
                          value={cond.operator}
                          onChange={(e) => handleConditionChange(idx, ci, 'operator', e.target.value)}
                          className="bg-slate-900 border border-slate-800 px-1 py-0.5 rounded text-[10px] text-slate-200"
                        >
                          <option value="eq">==</option>
                          <option value="gte">&gt;=</option>
                          <option value="lte">&lt;=</option>
                          <option value="contains">contains</option>
                        </select>
                        <input
                          type="text"
                          placeholder="Value"
                          value={cond.value}
                          onChange={(e) => handleConditionChange(idx, ci, 'value', e.target.value)}
                          className="w-1/3 bg-slate-900 border border-slate-800 px-1 py-0.5 rounded text-[10px] text-slate-200"
                        />
                        <button onClick={() => handleRemoveCondition(idx, ci)} className="text-red-400 hover:text-red-300">
                          <Trash2 className="h-3 w-3" />
                        </button>
                      </div>
                    ))}
                    <button 
                      onClick={() => handleAddCondition(idx)}
                      className="text-[10px] text-indigo-400 hover:text-indigo-300 underline"
                    >
                      + Add Condition
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <button
            onClick={handleCreatePolicy}
            className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 text-slate-100 font-bold text-sm rounded transition"
          >
            Create Policy Draft
          </button>
        </div>

        {/* Policies Listing cards */}
        <div className="lg:col-span-2 space-y-4">
          <h3 className="text-sm font-semibold text-slate-200">Active Organization Policies</h3>
          {policies.length === 0 ? (
            <div className="p-8 rounded-xl bg-slate-900 border border-slate-800 text-center text-slate-500 text-sm">
              No organization security policies configured.
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {policies.map((p) => (
                <div key={p._id} className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between space-y-3">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        p.status === 'active' ? 'bg-green-500/25 text-green-400' :
                        p.status === 'review' ? 'bg-yellow-500/25 text-yellow-400' :
                        'bg-slate-800 text-slate-400'
                      }`}>
                        {p.status}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono">v{p.version}</span>
                    </div>
                    
                    <h4 className="font-bold text-slate-200 capitalize text-sm">{p.policy_type.replace('_', ' ')}</h4>
                    
                    {p.department && (
                      <p className="text-[11px] text-indigo-400 mt-1">Scope: {p.department} Department</p>
                    )}
                    
                    {/* Rules list */}
                    <div className="mt-3 space-y-2 border-t border-slate-800/80 pt-2.5">
                      {p.rules.map((rule, ri) => (
                        <div key={ri} className="text-xs">
                          <p className="font-semibold text-slate-300">{rule.description}</p>
                          <p className="text-[11px] text-slate-500 mt-0.5">
                            Action: <span className="underline font-mono text-slate-400">{rule.action}</span> when {
                              rule.conditions.map(c => `${c.field} ${c.operator} ${c.value}`).join(' & ')
                            }
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Actions mapping */}
                  <div className="flex flex-wrap gap-2 border-t border-slate-800 pt-3">
                    {p.status === 'draft' && (
                      <button
                        onClick={() => handleSubmitApproval(p._id)}
                        className="px-3 py-1 bg-yellow-600 hover:bg-yellow-500 text-slate-950 font-bold text-xs rounded transition flex items-center gap-1"
                      >
                        <UserCheck className="h-3 w-3" />
                        Submit Signatures
                      </button>
                    )}
                    
                    {p.status === 'review' && (
                      <>
                        <button
                          onClick={() => handleApprove(p._id, true)}
                          className="px-2.5 py-1 bg-green-600 hover:bg-green-500 text-slate-950 font-bold text-xs rounded transition flex items-center gap-1"
                        >
                          <CheckCircle2 className="h-3 w-3" />
                          Approve
                        </button>
                        <button
                          onClick={() => handleApprove(p._id, false)}
                          className="px-2.5 py-1 bg-red-600 hover:bg-red-500 text-slate-100 font-bold text-xs rounded transition"
                        >
                          Reject
                        </button>
                      </>
                    )}
                    
                    {(p.status === 'active' || p.status === 'disabled') && (
                      <button
                        onClick={() => handleToggleActive(p)}
                        className={`px-3 py-1 font-bold text-xs rounded transition ${
                          p.status === 'active' ? 'bg-slate-800 hover:bg-slate-700 text-red-400' : 'bg-green-600 hover:bg-green-500 text-slate-950'
                        }`}
                      >
                        {p.status === 'active' ? 'Deactivate' : 'Activate'}
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

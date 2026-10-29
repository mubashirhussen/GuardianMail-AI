import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Phone, 
  Mail, 
  ExternalLink, 
  Copy, 
  Check, 
  FileText, 
  X, 
  Send,
  AlertCircle
} from 'lucide-react';
import { advisoriesService } from '../services/advisories';

interface CertInCyberDefenseProps {
  className?: string;
  initialThreatContext?: {
    type?: string;
    sender?: string;
    url?: string;
    description?: string;
  };
}

export const CertInCyberDefense: React.FC<CertInCyberDefenseProps> = ({
  className = '',
  initialThreatContext
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [generatedDraft, setGeneratedDraft] = useState<string | null>(null);

  // Modal form states
  const [incidentType, setIncidentType] = useState(initialThreatContext?.type || 'Phishing / SMS Fraud');
  const [suspectDetails, setSuspectDetails] = useState(initialThreatContext?.sender || initialThreatContext?.url || '');
  const [incidentDescription, setIncidentDescription] = useState(
    initialThreatContext?.description || 'Received fraudulent message attempting to extract credentials.'
  );
  const [financialLoss, setFinancialLoss] = useState<string>('0');
  const [transactionId, setTransactionId] = useState('');
  const [bankName, setBankName] = useState('');

  const handleCopy = (text: string, key: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => {
      setCopiedKey(null);
    }, 2000);
  };

  const handleGenerateDraft = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const parsedLoss = parseFloat(financialLoss) || 0;
      const res = await advisoriesService.draftCertInComplaint({
        incident_type: incidentType,
        suspect_details: suspectDetails,
        incident_description: incidentDescription,
        financial_loss: parsedLoss,
        transaction_id: transactionId || undefined,
        bank_name: bankName || undefined,
        evidence_urls: suspectDetails.startsWith('http') ? [suspectDetails] : undefined
      });
      setGeneratedDraft(res.draft_text);
    } catch {
      // Fallback local formatter if offline or session error
      const nowStr = new Date().toISOString();
      setGeneratedDraft(
        `OFFICIAL CYBERCRIME & CERT-IN REPORT DRAFT\nTimestamp: ${nowStr}\nHelpline: 1930 | Portal: https://cybercrime.gov.in\n\nIncident Type: ${incidentType}\nSuspect/Sender: ${suspectDetails}\nAmount Defrauded: ₹${financialLoss}\nTransaction ID: ${transactionId || 'N/A'}\n\nDescription:\n${incidentDescription}\n\nSubmitted via MailGuard Cyber Defence Hub`
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {/* Main CERT-In Cyber Defence Container */}
      <div
        className={`bg-[#0d1424] text-slate-200 border border-slate-800/80 rounded-2xl p-5 shadow-xl transition duration-200 relative overflow-hidden ${className}`}
      >
        {/* Subtle background glow */}
        <div className="absolute -top-12 -right-12 w-32 h-32 bg-amber-500/5 rounded-full blur-2xl pointer-events-none" />

        {/* Header */}
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 shrink-0">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <h3 className="font-bold text-base text-slate-100 tracking-tight flex items-center gap-2">
              India CERT-In — Cyber Defence
            </h3>
          </div>
          <button
            onClick={() => setModalOpen(true)}
            className="text-[11px] font-semibold text-amber-400 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 px-2.5 py-1 rounded-lg transition flex items-center gap-1.5"
            title="Draft official complaint file"
          >
            <FileText className="h-3.5 w-3.5" />
            <span>Draft Complaint</span>
          </button>
        </div>

        {/* Nodal Agency Description */}
        <p className="text-xs text-slate-400 leading-relaxed mb-4">
          The Indian Computer Emergency Response Team (CERT-In) under MeitY is India's national nodal agency for
          responding to cyber security incidents. Report phishing, fraud and malware to them.
        </p>

        {/* Contacts & Helplines List */}
        <div className="space-y-3 text-xs">
          {/* National cyber-crime helpline: 1930 */}
          <div className="flex items-start gap-2.5 group">
            <Phone className="h-4 w-4 text-orange-400 shrink-0 mt-0.5" />
            <div className="flex-1 flex flex-wrap items-baseline gap-x-2">
              <span className="text-slate-400">National cyber-crime helpline:</span>
              <a
                href="tel:1930"
                className="font-mono font-bold text-slate-100 underline hover:text-amber-400 transition"
              >
                1930
              </a>
              <span className="text-[11px] text-slate-500">(24×7, toll-free)</span>
            </div>
            <button
              onClick={(e) => handleCopy('1930', '1930', e)}
              className="opacity-60 hover:opacity-100 text-slate-400 p-1 rounded hover:bg-slate-800 transition"
              title="Copy Helpline 1930"
            >
              {copiedKey === '1930' ? (
                <Check className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </button>
          </div>

          {/* CERT-In Incident Response Helpdesk: 1800-11-4949 */}
          <div className="flex items-start gap-2.5 group">
            <Phone className="h-4 w-4 text-orange-400 shrink-0 mt-0.5" />
            <div className="flex-1 flex flex-wrap items-baseline gap-x-2">
              <span className="text-slate-400">CERT-In Incident Response Helpdesk:</span>
              <a
                href="tel:1800114949"
                className="font-mono font-bold text-slate-100 underline hover:text-amber-400 transition"
              >
                1800-11-4949
              </a>
              <span className="text-[11px] text-slate-500">(24×7, toll-free)</span>
            </div>
            <button
              onClick={(e) => handleCopy('1800-11-4949', 'certin_phone', e)}
              className="opacity-60 hover:opacity-100 text-slate-400 p-1 rounded hover:bg-slate-800 transition"
              title="Copy CERT-In Toll-Free"
            >
              {copiedKey === 'certin_phone' ? (
                <Check className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </button>
          </div>

          {/* Phishing reports: report@phishing.gov.in */}
          <div className="flex items-start gap-2.5 group">
            <Mail className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
            <div className="flex-1 flex flex-wrap items-baseline gap-x-2">
              <span className="text-slate-400">Phishing reports:</span>
              <a
                href="mailto:report@phishing.gov.in"
                className="font-mono font-medium text-slate-100 underline hover:text-emerald-400 transition break-all"
              >
                report@phishing.gov.in
              </a>
            </div>
            <button
              onClick={(e) => handleCopy('report@phishing.gov.in', 'phish_mail', e)}
              className="opacity-60 hover:opacity-100 text-slate-400 p-1 rounded hover:bg-slate-800 transition"
              title="Copy Phishing Email"
            >
              {copiedKey === 'phish_mail' ? (
                <Check className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </button>
          </div>

          {/* Incidents: incident@cert-in.org.in */}
          <div className="flex items-start gap-2.5 group">
            <Mail className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
            <div className="flex-1 flex flex-wrap items-baseline gap-x-2">
              <span className="text-slate-400">Incidents:</span>
              <a
                href="mailto:incident@cert-in.org.in"
                className="font-mono font-medium text-slate-100 underline hover:text-emerald-400 transition break-all"
              >
                incident@cert-in.org.in
              </a>
            </div>
            <button
              onClick={(e) => handleCopy('incident@cert-in.org.in', 'incident_mail', e)}
              className="opacity-60 hover:opacity-100 text-slate-400 p-1 rounded hover:bg-slate-800 transition"
              title="Copy Incident Email"
            >
              {copiedKey === 'incident_mail' ? (
                <Check className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </button>
          </div>

          {/* File a complaint: cybercrime.gov.in · Women / child: report anonymously */}
          <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-baseline gap-x-2 gap-y-1 text-slate-300">
            <span className="text-slate-400">File a complaint:</span>
            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-cyan-400 underline hover:text-cyan-300 transition inline-flex items-center gap-1"
            >
              cybercrime.gov.in
              <ExternalLink className="h-3 w-3" />
            </a>
            <span className="text-slate-600">·</span>
            <span className="text-slate-400">Women / child:</span>
            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-cyan-400 underline hover:text-cyan-300 transition"
            >
              report anonymously
            </a>
          </div>

          {/* Advisories: cert-in.org.in · Sachet (RBI): sachet.rbi.org.in */}
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-slate-300">
            <span className="text-slate-400">Advisories:</span>
            <a
              href="https://cert-in.org.in"
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-cyan-400 underline hover:text-cyan-300 transition inline-flex items-center gap-1"
            >
              cert-in.org.in
              <ExternalLink className="h-3 w-3" />
            </a>
            <span className="text-slate-600">·</span>
            <span className="text-slate-400">Sachet (RBI):</span>
            <a
              href="https://sachet.rbi.org.in"
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-cyan-400 underline hover:text-cyan-300 transition inline-flex items-center gap-1"
            >
              sachet.rbi.org.in
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </div>
      </div>

      {/* Complaint Draft Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="bg-[#0f172a] border border-slate-700/80 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
              <div className="flex items-center gap-2.5">
                <ShieldCheck className="h-5 w-5 text-amber-400" />
                <h3 className="font-bold text-slate-100 text-sm">
                  Official CERT-In & Cybercrime Incident Draft Generator
                </h3>
              </div>
              <button
                onClick={() => {
                  setModalOpen(false);
                  setGeneratedDraft(null);
                }}
                className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 overflow-y-auto space-y-4 text-xs">
              {!generatedDraft ? (
                <form onSubmit={handleGenerateDraft} className="space-y-4">
                  <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-start gap-2.5">
                    <AlertCircle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                    <p className="text-[11px] text-amber-200/90 leading-relaxed">
                      This generator packages your indicators, evidence, and narrative into the exact format requested
                      by India's National Cyber Crime Portal (1930) and CERT-In.
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-slate-300 font-semibold mb-1">Incident Category</label>
                      <select
                        value={incidentType}
                        onChange={(e) => setIncidentType(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-slate-200 text-xs focus:ring-1 focus:ring-amber-500"
                      >
                        <option value="India Post Failed Delivery Smishing">India Post SMS Delivery Scam</option>
                        <option value="Electricity Bill Disconnection APK Scam">Electricity Bill Disconnection Scam</option>
                        <option value="Income Tax Refund Credential Phishing">Income Tax Refund Phishing</option>
                        <option value="Digital Arrest / Extortion Video Scam">Digital Arrest & Extortion Scam</option>
                        <option value="Aadhaar AePS Biometric Withdrawal">Aadhaar AePS Biometric Fraud</option>
                        <option value="Part-Time Telegram Job Investment Fraud">Telegram Part-Time Job / Review Scam</option>
                        <option value="Enterprise M365 Session Hijack / AiTM">Enterprise Cloud Phishing</option>
                        <option value="General Phishing / Malicious Link">General Phishing / Suspicious URL</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-slate-300 font-semibold mb-1">
                        Suspect Identifier (URL / Phone / Email)
                      </label>
                      <input
                        type="text"
                        value={suspectDetails}
                        onChange={(e) => setSuspectDetails(e.target.value)}
                        placeholder="e.g. CP-INDPOST / indiapost-parcel.top / +91 9876543210"
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-slate-200 text-xs focus:ring-1 focus:ring-amber-500"
                        required
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div>
                      <label className="block text-slate-300 font-semibold mb-1">Financial Loss (₹ if any)</label>
                      <input
                        type="number"
                        value={financialLoss}
                        onChange={(e) => setFinancialLoss(e.target.value)}
                        placeholder="0"
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-slate-200 text-xs focus:ring-1 focus:ring-amber-500"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-300 font-semibold mb-1">Transaction Ref / UPI ID</label>
                      <input
                        type="text"
                        value={transactionId}
                        onChange={(e) => setTransactionId(e.target.value)}
                        placeholder="e.g. UPI/328491823901"
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-slate-200 text-xs focus:ring-1 focus:ring-amber-500"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-300 font-semibold mb-1">Debited Bank Name</label>
                      <input
                        type="text"
                        value={bankName}
                        onChange={(e) => setBankName(e.target.value)}
                        placeholder="e.g. State Bank of India"
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-slate-200 text-xs focus:ring-1 focus:ring-amber-500"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-slate-300 font-semibold mb-1">Incident Summary & Narrative</label>
                    <textarea
                      value={incidentDescription}
                      onChange={(e) => setIncidentDescription(e.target.value)}
                      rows={4}
                      placeholder="Explain what happened: what message was received, what links were clicked, and what information or funds were transferred..."
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-slate-200 text-xs focus:ring-1 focus:ring-amber-500"
                      required
                    />
                  </div>

                  <div className="flex justify-end gap-2.5 pt-2">
                    <button
                      type="button"
                      onClick={() => setModalOpen(false)}
                      className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={loading}
                      className="px-5 py-2 rounded-lg bg-amber-500 hover:bg-amber-600 text-slate-950 font-bold flex items-center gap-2 transition disabled:opacity-50"
                    >
                      {loading ? 'Bundling Evidence...' : 'Generate Official Report Draft'}
                    </button>
                  </div>
                </form>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                      <Check className="h-4 w-4" /> Ready for submission
                    </span>
                    <button
                      onClick={() => handleCopy(generatedDraft, 'full_draft')}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded-lg font-semibold text-slate-200 flex items-center gap-1.5 transition"
                    >
                      {copiedKey === 'full_draft' ? (
                        <>
                          <Check className="h-3.5 w-3.5 text-emerald-400" />
                          <span>Copied to Clipboard!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3.5 w-3.5" />
                          <span>Copy Formal Complaint</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* Preformatted complaint text */}
                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-[11px] text-slate-300 whitespace-pre-wrap select-all max-h-72 overflow-y-auto leading-relaxed">
                    {generatedDraft}
                  </div>

                  {/* Direct portal links */}
                  <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
                    <div className="font-semibold text-slate-300 text-xs">Direct Filing Portals:</div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                      <a
                        href="https://cybercrime.gov.in"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-2.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 flex items-center justify-between"
                      >
                        <span>Submit to cybercrime.gov.in</span>
                        <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                      <a
                        href={`mailto:incident@cert-in.org.in?subject=CYBER%20SECURITY%20INCIDENT%20REPORT&body=${encodeURIComponent(
                          generatedDraft.slice(0, 1500)
                        )}`}
                        className="p-2.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 flex items-center justify-between"
                      >
                        <span>Email to incident@cert-in.org.in</span>
                        <Send className="h-3.5 w-3.5" />
                      </a>
                    </div>
                  </div>

                  <div className="flex justify-between items-center pt-2">
                    <button
                      onClick={() => setGeneratedDraft(null)}
                      className="text-xs text-slate-400 hover:text-slate-200 underline"
                    >
                      ← Edit Parameters
                    </button>
                    <button
                      onClick={() => {
                        setModalOpen(false);
                        setGeneratedDraft(null);
                      }}
                      className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg"
                    >
                      Close
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
};

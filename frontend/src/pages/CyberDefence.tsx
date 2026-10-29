import React from 'react';
import { CertInCyberDefense } from '../components/CertInCyberDefense';
import { ThreatAdvisoryBulletin } from '../components/ThreatAdvisoryBulletin';
import { 
  PhoneCall, 
  Clock, 
  ExternalLink, 
  Lock, 
  Sparkles
} from 'lucide-react';

export const CyberDefence: React.FC = () => {
  return (
    <div className="space-y-8 font-sans max-w-7xl mx-auto pb-12">
      {/* Page Title & Emergency Alert Header */}
      <div className="bg-gradient-to-r from-amber-500/10 via-slate-900 to-cyan-500/10 border border-amber-500/30 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30 font-bold text-[10px] uppercase tracking-wider flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
                National Cyber Incident Response & Defence Hub
              </span>
            </div>
            <h1 className="text-2xl md:text-3xl font-extrabold text-slate-50 tracking-tight">
              India CERT-In & National Threat Defence
            </h1>
            <p className="text-xs text-slate-300 max-w-2xl leading-relaxed">
              Official Indian nodal security reporting channels, emergency 24×7 financial fraud helplines,
              and curated threat advisories from recent days to protect consumers and organizations.
            </p>
          </div>

          {/* Quick Emergency Action Callouts */}
          <div className="flex flex-wrap items-center gap-3">
            <a
              href="tel:1930"
              className="px-4 py-2.5 rounded-xl bg-orange-600 hover:bg-orange-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg shadow-orange-600/20 transition transform hover:-translate-y-0.5"
            >
              <PhoneCall className="h-4 w-4" />
              <span>Dial 1930 (Helpline)</span>
            </a>
            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noopener noreferrer"
              className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs flex items-center gap-2 transition"
            >
              <span>cybercrime.gov.in</span>
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </div>
        </div>
      </div>

      {/* Two Column Grid: CERT-In Card + Golden Hour Security Guide */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Pixel-perfect CERT-In Cyber Defence Card */}
        <div className="lg:col-span-6 xl:col-span-5">
          <CertInCyberDefense className="w-full" />
        </div>

        {/* Right Column: Customer Awareness & Golden Hour Protocol */}
        <div className="lg:col-span-6 xl:col-span-7 space-y-4">
          {/* Golden Hour Fraud Freeze Banner */}
          <div className="bg-[#0d1424] border border-amber-500/20 rounded-2xl p-5 shadow-lg space-y-3">
            <div className="flex items-center gap-2.5 text-amber-400">
              <Clock className="h-5 w-5" />
              <h3 className="font-bold text-sm text-slate-100">
                The "Golden Hour" Financial Fraud Protocol
              </h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              If you or an employee lost money to phishing, UPI fraud, or remote APK trojans, calling{' '}
              <strong className="text-amber-400 font-mono">1930</strong> within the first{' '}
              <strong className="text-slate-100">2 to 3 hours</strong> allows the Citizen Financial Cyber Fraud Reporting
              and Management System (CFCFRMS) to freeze the stolen funds before the scammer can withdraw them at an ATM.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1 text-xs">
              <div className="p-2.5 bg-slate-900/80 border border-slate-800 rounded-xl">
                <span className="font-bold text-amber-400 block mb-0.5">Step 1: Dial 1930</span>
                <span className="text-[11px] text-slate-400">Provide bank name, account number, and UPI transaction ID.</span>
              </div>
              <div className="p-2.5 bg-slate-900/80 border border-slate-800 rounded-xl">
                <span className="font-bold text-amber-400 block mb-0.5">Step 2: Auto SMS</span>
                <span className="text-[11px] text-slate-400">You will receive an acknowledgment SMS with a complaint token.</span>
              </div>
              <div className="p-2.5 bg-slate-900/80 border border-slate-800 rounded-xl">
                <span className="font-bold text-amber-400 block mb-0.5">Step 3: Portal Log</span>
                <span className="text-[11px] text-slate-400">Upload transaction screenshots within 24 hours to finalize.</span>
              </div>
            </div>
          </div>

          {/* Customer Protection Quick Checklist */}
          <div className="bg-[#0d1424] border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
            <div className="flex items-center gap-2.5 text-cyan-400">
              <Lock className="h-5 w-5" />
              <h3 className="font-bold text-sm text-slate-100">
                Customer Core Defense Checklist
              </h3>
            </div>
            <ul className="space-y-2 text-xs text-slate-300">
              <li className="flex items-start gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                <span>
                  <strong>Lock Aadhaar Biometrics:</strong> Use the mAadhaar app to lock biometric verification, blocking
                  unauthorized AePS micro-ATM cash withdrawals.
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                <span>
                  <strong>Never Install APKs via WhatsApp:</strong> Electricity boards and courier services never distribute
                  APK files to resolve bill or delivery issues.
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                <span>
                  <strong>"Digital Arrest" Does Not Exist:</strong> Indian law enforcement agencies never conduct arrests or
                  demand escrow money over video calls.
                </span>
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Major Recent Threat Advisories Archive & Bulletin */}
      <div className="space-y-4 pt-2">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-amber-400" />
              Major Recent Cyber Threat Advisories & Incident Bulletin
            </h2>
            <p className="text-xs text-slate-400">
              Verified real-world threat campaigns seen in recent days. Review modus operandi and follow actionable protection guides.
            </p>
          </div>
          <span className="text-xs text-slate-500 font-mono">
            Updated regularly from CERT-In & MHA feeds
          </span>
        </div>

        <ThreatAdvisoryBulletin />
      </div>
    </div>
  );
};
export default CyberDefence;

import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { 
  Laptop, ShieldAlert, Key, CheckCircle2, 
  ArrowRight, UserPlus 
} from 'lucide-react';

export const Devices: React.FC = () => {
  const { user } = useAuth();
  const [sessions, setSessions] = useState([
    { id: '1', name: 'Chrome · Windows', detail: 'This device · started just now', isCurrent: true, date: 'just now' },
    { id: '2', name: 'Chrome · Windows', detail: 'This device · started 16d ago', isCurrent: false, date: '16d ago' },
    { id: '3', name: 'Chrome · Windows', detail: 'This device · started 21d ago', isCurrent: false, date: '21d ago' },
    { id: '4', name: 'Chrome · Windows', detail: 'This device · started 34d ago', isCurrent: false, date: '34d ago' },
  ]);
  const [signingOut, setSigningOut] = useState(false);
  const [signedOutOther, setSignedOutOther] = useState(false);

  const userName = user?.full_name?.split(' ')[0] || user?.email?.split('@')[0] || 'User';
  const userEmail = user?.email || 'user@guardianmail.ai';

  const handleSignOutOthers = async () => {
    setSigningOut(true);
    await new Promise((r) => setTimeout(r, 600));
    setSessions((prev) => prev.filter((s) => s.isCurrent));
    setSignedOutOther(true);
    setSigningOut(false);
  };

  const loginEvents = [
    { id: 'e1', name: 'Chrome · Windows', location: 'This device · local', date: 'just now' },
    { id: 'e2', name: 'Chrome · Windows', location: 'This device · local', date: '16d ago' },
    { id: 'e3', name: 'Chrome · Windows', location: 'This device · local', date: '21d ago' },
    { id: 'e4', name: 'Chrome · Windows', location: 'This device · local', date: '34d ago' },
    { id: 'e5', name: 'Chrome · Windows', location: 'This device · local', date: '45d ago' },
    { id: 'e6', name: 'Chrome · Windows', location: 'This device · local', date: '60d ago' },
  ];

  return (
    <div className="space-y-6 max-w-5xl pb-16">
      {/* 1. Top User Summary Header matching Screenshot 3 */}
      <div className="p-5 rounded-2xl bg-[#0f1523] border border-[#1b2638] flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="h-12 w-12 rounded-2xl bg-[#2563eb] text-white font-bold text-lg flex items-center justify-center shadow-md">
            {userName[0]?.toUpperCase() || 'M'}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-white">{userName}</h2>
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400">
                Member
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">{userEmail}</p>
          </div>
        </div>

        <button className="px-3.5 py-1.5 rounded-xl bg-[#080d17] hover:bg-[#141e30] border border-[#1c273a] text-slate-200 text-xs font-semibold flex items-center gap-1.5 transition">
          <UserPlus className="h-3.5 w-3.5" />
          <span>Switch / Add</span>
        </button>
      </div>

      {/* 2. Three Metric Boxes matching Screenshot 3 */}
      <div className="grid grid-cols-3 gap-4">
        <div className="p-4 rounded-2xl bg-[#0f1523] border border-[#1b2638] text-center space-y-1">
          <ArrowRight className="h-4 w-4 text-blue-400 mx-auto" />
          <span className="text-2xl font-bold font-mono text-white block">8</span>
          <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block">Logins</span>
        </div>

        <div className="p-4 rounded-2xl bg-[#0f1523] border border-[#1b2638] text-center space-y-1">
          <ShieldAlert className="h-4 w-4 text-rose-400 mx-auto" />
          <span className="text-2xl font-bold font-mono text-white block">0</span>
          <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block">Blocked</span>
        </div>

        <div className="p-4 rounded-2xl bg-[#0f1523] border border-[#1b2638] text-center space-y-1">
          <CheckCircle2 className="h-4 w-4 text-emerald-400 mx-auto" />
          <span className="text-2xl font-bold font-mono text-white block">8</span>
          <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block">Verified</span>
        </div>
      </div>

      {/* 3. ACTIVE SESSIONS Section matching Screenshot 3 */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400 font-bold">
            ACTIVE SESSIONS
          </span>

          <button
            onClick={handleSignOutOthers}
            disabled={signingOut || signedOutOther}
            className="text-xs font-semibold text-amber-400 hover:text-amber-300 flex items-center gap-1.5 transition"
          >
            <Key className="h-3.5 w-3.5" />
            <span>{signingOut ? 'Signing out...' : signedOutOther ? 'Other devices removed' : 'Sign out other devices'}</span>
          </button>
        </div>

        <div className="space-y-2">
          {sessions.map((sess) => (
            <div
              key={sess.id}
              className="p-4 rounded-2xl bg-[#0f1523] border border-[#1b2638] flex items-center justify-between gap-4"
            >
              <div className="flex items-center gap-3.5">
                <Laptop className="h-5 w-5 text-emerald-400 shrink-0" />
                <div>
                  <span className="text-xs font-bold text-white block">{sess.name}</span>
                  <span className="text-[11px] text-slate-400 block">{sess.detail}</span>
                </div>
              </div>

              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                sess.isCurrent ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-800 text-slate-400'
              }`}>
                {sess.isCurrent ? 'This device' : 'Other'}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* 4. RECENT LOGIN ACTIVITY matching Screenshot 3 */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400 font-bold">
            RECENT LOGIN ACTIVITY
          </span>
          <span className="text-[11px] text-slate-500 font-mono">Last 6 events</span>
        </div>

        <div className="space-y-2">
          {loginEvents.map((evt) => (
            <div
              key={evt.id}
              className="p-3.5 rounded-2xl bg-[#0f1523] border border-[#1b2638] flex items-center justify-between gap-4"
            >
              <div className="flex items-center gap-3.5">
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                <div>
                  <span className="text-xs font-bold text-white block">{evt.name}</span>
                  <span className="text-[11px] text-slate-400 block">{evt.location}</span>
                </div>
              </div>

              <span className="text-[11px] font-mono font-bold text-emerald-400">
                {evt.date}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

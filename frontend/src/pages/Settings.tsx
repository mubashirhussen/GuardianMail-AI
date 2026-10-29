import React, { useState } from 'react';
import { useTheme } from '../contexts/ThemeContext';
import { 
  Sun, Moon, Laptop, Bell, Shield, Sliders
} from 'lucide-react';

export const Settings: React.FC = () => {
  const { theme, setTheme } = useTheme();
  
  // Local state for mock preferences
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [desktopAlerts, setDesktopAlerts] = useState(true);
  const [slackAlerts, setSlackAlerts] = useState(false);
  const [retentionDays, setRetentionDays] = useState('90');

  return (
    <div className="space-y-6 font-sans">
      {/* Title Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-50 tracking-tight">Console Preferences</h1>
        <p className="text-xs text-slate-400">Configure theme modes, logging retainment details, and notifications alerts</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Columns: Config panel */}
        <div className="lg:col-span-2 space-y-6">
          {/* Display settings */}
          <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-4 text-xs">
            <div className="flex items-center gap-2">
              <Sliders className="h-4.5 w-4.5 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200">Appearance & Theme</h3>
            </div>

            <div className="grid grid-cols-3 gap-3 font-semibold text-[10px]">
              {/* Dark mode */}
              <button
                type="button"
                onClick={() => setTheme('dark')}
                className={`flex flex-col items-center gap-2 p-4 rounded-xl border transition ${
                  theme === 'dark' 
                    ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/40 shadow-sm' 
                    : 'bg-slate-950/40 border-slate-800 text-slate-500 hover:text-slate-350'
                }`}
              >
                <Moon className="h-5 w-5" />
                <span>Cyber Dark</span>
              </button>

              {/* Light mode */}
              <button
                type="button"
                onClick={() => setTheme('light')}
                className={`flex flex-col items-center gap-2 p-4 rounded-xl border transition ${
                  theme === 'light' 
                    ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/40 shadow-sm' 
                    : 'bg-slate-950/40 border-slate-800 text-slate-500 hover:text-slate-350'
                }`}
              >
                <Sun className="h-5 w-5" />
                <span>Modern Light</span>
              </button>

              {/* System default */}
              <button
                type="button"
                onClick={() => setTheme('system')}
                className={`flex flex-col items-center gap-2 p-4 rounded-xl border transition ${
                  theme === 'system'
                    ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/40 shadow-sm'
                    : 'bg-slate-950/40 border-slate-800 text-slate-500 hover:text-slate-350'
                }`}
              >
                <Laptop className="h-5 w-5" />
                <span>System Sync</span>
              </button>
            </div>
          </div>

          {/* Incident Alerts triggers */}
          <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-4 text-xs font-semibold">
            <div className="flex items-center gap-2">
              <Bell className="h-4.5 w-4.5 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200">Notification Alerts Routing</h3>
            </div>

            <div className="space-y-3">
              {/* Email Alerts toggle */}
              <div className="flex items-center justify-between p-3.5 bg-slate-950/60 border border-slate-850 rounded-xl">
                <div className="space-y-0.5">
                  <span className="text-slate-300 block text-xs">Email Security Alerts</span>
                  <span className="text-[9px] text-slate-500 block font-medium">Forward high risk flags to security aliases</span>
                </div>
                <input
                  type="checkbox"
                  checked={emailAlerts}
                  onChange={() => setEmailAlerts(!emailAlerts)}
                  className="h-4 w-4 bg-slate-950 border border-slate-800 rounded text-cyan-500 focus:ring-cyan-500"
                />
              </div>

              {/* Desktop Alerts toggle */}
              <div className="flex items-center justify-between p-3.5 bg-slate-950/60 border border-slate-850 rounded-xl">
                <div className="space-y-0.5">
                  <span className="text-slate-300 block text-xs">Real-Time Desktop Banners</span>
                  <span className="text-[9px] text-slate-500 block font-medium">Render browser notification popups on malware scans</span>
                </div>
                <input
                  type="checkbox"
                  checked={desktopAlerts}
                  onChange={() => setDesktopAlerts(!desktopAlerts)}
                  className="h-4 w-4 bg-slate-950 border border-slate-800 rounded text-cyan-500 focus:ring-cyan-500"
                />
              </div>

              {/* Slack webhook alert */}
              <div className="flex items-center justify-between p-3.5 bg-slate-950/60 border border-slate-850 rounded-xl">
                <div className="space-y-0.5">
                  <span className="text-slate-300 block text-xs">Slack Webhook alerts</span>
                  <span className="text-[9px] text-slate-500 block font-medium">Broadcast alerts payload to #soc-channel</span>
                </div>
                <input
                  type="checkbox"
                  checked={slackAlerts}
                  onChange={() => setSlackAlerts(!slackAlerts)}
                  className="h-4 w-4 bg-slate-950 border border-slate-800 rounded text-cyan-500 focus:ring-cyan-500"
                />
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Logging details policy configuration */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl shadow-lg space-y-4 text-xs">
          <div className="flex items-center gap-2">
            <Shield className="h-4.5 w-4.5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Logging Policy</h3>
          </div>
          
          <div className="space-y-4 font-medium">
            <div className="space-y-1">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Forensics Retention Period</label>
              <select
                value={retentionDays}
                onChange={(e) => setRetentionDays(e.target.value)}
                className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-2 py-2 text-xs text-slate-300 outline-none"
              >
                <option value="30">30 Days (Standard Sandbox)</option>
                <option value="90">90 Days (Enterprise compliance)</option>
                <option value="365">1 Year (Long-term audit logs)</option>
              </select>
            </div>
            <p className="text-slate-500 leading-relaxed text-[11px]">
              Logs details exceeding retention values are permanently soft-deleted and archived from MongoDB pools to save on database storage costs.
            </p>
          </div>
        </div>

      </div>
    </div>
  );
};

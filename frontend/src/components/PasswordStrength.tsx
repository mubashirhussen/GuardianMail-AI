import React from 'react';
import { Check, X } from 'lucide-react';

interface PasswordStrengthProps {
  password: string;
}

export const PasswordStrength: React.FC<PasswordStrengthProps> = ({ password }) => {
  const criteria = [
    { label: 'At least 8 characters', met: password.length >= 8 },
    { label: 'Contains uppercase letter (A-Z)', met: /[A-Z]/.test(password) },
    { label: 'Contains lowercase letter (a-z)', met: /[a-z]/.test(password) },
    { label: 'Contains number (0-9)', met: /[0-9]/.test(password) },
    { label: 'Contains special character (!@#$%^&*)', met: /[^A-Za-z0-9]/.test(password) },
  ];

  const score = criteria.filter((c) => c.met).length;

  const getStrengthLabel = () => {
    if (!password) return { label: 'Empty', color: 'text-slate-500', barBg: 'bg-slate-800' };
    if (score <= 2) return { label: 'Weak', color: 'text-rose-400', barBg: 'bg-rose-500' };
    if (score === 3) return { label: 'Fair', color: 'text-amber-400', barBg: 'bg-amber-500' };
    if (score === 4) return { label: 'Strong', color: 'text-cyan-400', barBg: 'bg-cyan-500' };
    return { label: 'Very Strong', color: 'text-emerald-400', barBg: 'bg-emerald-500' };
  };

  const strength = getStrengthLabel();

  return (
    <div className="space-y-3 pt-2">
      {/* Strength Bar */}
      <div className="space-y-1.5">
        <div className="flex justify-between items-center text-xs">
          <span className="text-[11px] uppercase font-bold text-slate-400">Password Entropy</span>
          <span className={`font-bold font-mono text-xs ${strength.color}`}>{strength.label}</span>
        </div>
        <div className="grid grid-cols-5 gap-1.5 h-1.5">
          {[1, 2, 3, 4, 5].map((level) => (
            <div
              key={level}
              className={`h-full rounded-full transition-all duration-300 ${
                score >= level ? strength.barBg : 'bg-slate-800'
              }`}
            />
          ))}
        </div>
      </div>

      {/* Criteria Checklist */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-1">
        {criteria.map((item, idx) => (
          <div key={idx} className="flex items-center gap-1.5 text-[11px]">
            {item.met ? (
              <Check className="h-3 w-3 text-emerald-400 shrink-0" />
            ) : (
              <X className="h-3 w-3 text-slate-600 shrink-0" />
            )}
            <span className={item.met ? 'text-slate-300 font-medium' : 'text-slate-500'}>
              {item.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

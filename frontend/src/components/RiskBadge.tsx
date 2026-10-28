import React from 'react';
import { ShieldAlert, AlertTriangle, ShieldCheck, Info } from 'lucide-react';

interface RiskBadgeProps {
  score?: number;
  level?: string;
  showScore?: boolean;
}

interface BadgeConfig {
  bg: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
}

const BADGE_MAP: Record<string, BadgeConfig> = {
  CRITICAL: {
    bg: 'bg-rose-500/15 text-rose-400 border-rose-500/30 shadow-[0_0_10px_rgba(244,63,94,0.15)]',
    icon: ShieldAlert,
    label: 'CRITICAL',
  },
  HIGH: {
    bg: 'bg-orange-500/15 text-orange-400 border-orange-500/30 shadow-[0_0_10px_rgba(249,115,22,0.15)]',
    icon: AlertTriangle,
    label: 'HIGH',
  },
  MEDIUM: {
    bg: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    icon: AlertTriangle,
    label: 'MEDIUM',
  },
  LOW: {
    bg: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
    icon: Info,
    label: 'LOW',
  },
  SAFE: {
    bg: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    icon: ShieldCheck,
    label: 'SAFE',
  },
};

export const RiskBadge: React.FC<RiskBadgeProps> = ({ score, level, showScore = true }) => {
  let evaluatedLevel = level?.toUpperCase();
  if (!evaluatedLevel && score !== undefined) {
    if (score >= 80) evaluatedLevel = 'CRITICAL';
    else if (score >= 60) evaluatedLevel = 'HIGH';
    else if (score >= 40) evaluatedLevel = 'MEDIUM';
    else if (score >= 20) evaluatedLevel = 'LOW';
    else evaluatedLevel = 'SAFE';
  }

  const config: BadgeConfig = BADGE_MAP[evaluatedLevel || 'SAFE'] || BADGE_MAP.SAFE;
  const Icon = config.icon;

  return (
    <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border font-mono text-[11px] font-bold tracking-wider ${config.bg}`}>
      <Icon className="h-3.5 w-3.5 shrink-0" />
      <span>{config.label}</span>
      {showScore && score !== undefined && (
        <span className="opacity-80 font-normal">({score.toFixed(1)})</span>
      )}
    </div>
  );
};

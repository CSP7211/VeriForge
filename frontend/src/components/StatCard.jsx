import React from 'react';

const colorMap = {
  blue: {
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30',
    text: 'text-blue-400',
    glow: 'hover:shadow-blue-500/20',
    iconBg: 'bg-blue-500/20',
  },
  emerald: {
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    text: 'text-emerald-400',
    glow: 'hover:shadow-emerald-500/20',
    iconBg: 'bg-emerald-500/20',
  },
  amber: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    text: 'text-amber-400',
    glow: 'hover:shadow-amber-500/20',
    iconBg: 'bg-amber-500/20',
  },
  red: {
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    text: 'text-red-400',
    glow: 'hover:shadow-red-500/20',
    iconBg: 'bg-red-500/20',
  },
  purple: {
    bg: 'bg-purple-500/10',
    border: 'border-purple-500/30',
    text: 'text-purple-400',
    glow: 'hover:shadow-purple-500/20',
    iconBg: 'bg-purple-500/20',
  },
  cyan: {
    bg: 'bg-cyan-500/10',
    border: 'border-cyan-500/30',
    text: 'text-cyan-400',
    glow: 'hover:shadow-cyan-500/20',
    iconBg: 'bg-cyan-500/20',
  },
};

export default function StatCard({ title, value, subtitle, icon, color = 'blue' }) {
  const c = colorMap[color] || colorMap.blue;

  return (
    <div
      className={`vf-card ${c.bg} border ${c.border} ${c.glow} hover:shadow-lg transition-all duration-300 cursor-default group`}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <p className="text-xs font-semibold text-vf-textMuted uppercase tracking-wider mb-1">
            {title}
          </p>
          <p className={`text-2xl font-bold ${c.text} tabular-nums`}>
            {value}
          </p>
          {subtitle && (
            <p className="text-xs text-vf-textMuted mt-1">{subtitle}</p>
          )}
        </div>
        <div className={`flex-shrink-0 w-10 h-10 ${c.iconBg} rounded-lg flex items-center justify-center text-lg group-hover:scale-110 transition-transform duration-300`}>
          {icon}
        </div>
      </div>
    </div>
  );
}

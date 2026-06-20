import React from 'react';

const severityStyles = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
};

const severityLabels = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export default function SeverityBadge({ severity }) {
  const normalized = severity?.toLowerCase() || 'info';
  const style = severityStyles[normalized] || severityStyles.info;
  const label = severityLabels[normalized] || normalized;

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${style}`}>
      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${
        normalized === 'critical' ? 'bg-red-500' :
        normalized === 'high' ? 'bg-orange-500' :
        normalized === 'medium' ? 'bg-amber-500' :
        normalized === 'low' ? 'bg-blue-500' :
        'bg-gray-500'
      }`} />
      {label}
    </span>
  );
}

import React, { useState } from 'react';
import SeverityBadge from './SeverityBadge';

export default function FindingRow({ finding, onStatusChange }) {
  const [expanded, setExpanded] = useState(false);

  const statusStyles = {
    open: 'text-red-400 bg-red-500/10 border-red-500/20',
    resolved: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    'false_positive': 'text-gray-400 bg-gray-500/10 border-gray-500/20',
    accepted: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  };

  return (
    <React.Fragment>
      <tr
        onClick={() => setExpanded(!expanded)}
        className="cursor-pointer group"
      >
        <td>
          <SeverityBadge severity={finding.severity} />
        </td>
        <td>
          <span className="font-medium text-vf-textPrimary group-hover:text-vf-primaryGlow transition-colors">
            {finding.title}
          </span>
        </td>
        <td>
          {finding.cwe ? (
            <span className="text-xs font-mono text-vf-textMuted">{finding.cwe}</span>
          ) : (
            <span className="text-xs text-vf-textMuted">—</span>
          )}
        </td>
        <td>
          {finding.line ? (
            <span className="text-xs font-mono text-vf-textMuted">L{finding.line}</span>
          ) : (
            <span className="text-xs text-vf-textMuted">—</span>
          )}
        </td>
        <td>
          <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${
            statusStyles[finding.status] || statusStyles.open
          }`}>
            {finding.status?.replace('_', ' ') || 'open'}
          </span>
        </td>
        <td>
          <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
            {finding.status === 'open' && (
              <>
                <button
                  onClick={() => onStatusChange(finding.id, 'resolved')}
                  className="p-1 text-emerald-400 hover:bg-emerald-500/10 rounded transition-colors"
                  title="Mark resolved"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </button>
                <button
                  onClick={() => onStatusChange(finding.id, 'false_positive')}
                  className="p-1 text-gray-400 hover:bg-gray-500/10 rounded transition-colors"
                  title="Mark false positive"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </>
            )}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={6} className="px-4 py-4">
            <div className="animate-slide-up">
              {finding.matched && (
                <div className="mb-3">
                  <p className="text-xs font-semibold text-vf-textMuted uppercase tracking-wider mb-1.5">
                    Matched Code
                  </p>
                  <pre className="bg-vf-bg border border-vf-border rounded-lg p-3 text-xs font-mono text-red-400 overflow-x-auto">
                    {finding.matched}
                  </pre>
                </div>
              )}
              {finding.fix && (
                <div>
                  <p className="text-xs font-semibold text-vf-textMuted uppercase tracking-wider mb-1.5">
                    Suggested Fix
                  </p>
                  <pre className="bg-vf-bg border border-emerald-500/30 rounded-lg p-3 text-xs font-mono text-emerald-400 overflow-x-auto">
                    {finding.fix}
                  </pre>
                </div>
              )}
              {finding.description && (
                <p className="text-sm text-vf-textSecondary mt-3">{finding.description}</p>
              )}
            </div>
          </td>
        </tr>
      )}
    </React.Fragment>
  );
}

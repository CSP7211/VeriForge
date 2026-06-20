import React from 'react';

const gradeStyles = {
  'A+': 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
  'A': 'bg-green-500/20 text-green-400 border-green-500/40',
  'B': 'bg-lime-500/20 text-lime-400 border-lime-500/40',
  'C': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
  'D': 'bg-orange-500/20 text-orange-400 border-orange-500/40',
  'F': 'bg-red-500/20 text-red-400 border-red-500/40',
};

export default function GradeBadge({ grade, size = 'sm' }) {
  const style = gradeStyles[grade] || gradeStyles['F'];
  const sizeClasses = size === 'lg'
    ? 'px-4 py-2 text-lg font-bold min-w-[48px] text-center'
    : 'px-2.5 py-0.5 text-xs font-bold min-w-[32px] text-center';

  return (
    <span className={`inline-flex items-center justify-center rounded-lg border ${sizeClasses} ${style}`}>
      {grade}
    </span>
  );
}

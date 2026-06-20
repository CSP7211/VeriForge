/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    './index.html',
    './src/**/*.{js,jsx}',
  ],
  theme: {
    extend: {
      colors: {
        vf: {
          bg: '#0a0e17',
          surface: '#111827',
          surfaceHover: '#1f2937',
          border: '#1e3a5f',
          primary: '#3b82f6',
          primaryGlow: '#60a5fa',
          accentGreen: '#10b981',
          accentRed: '#ef4444',
          accentYellow: '#f59e0b',
          textPrimary: '#f1f5f9',
          textSecondary: '#94a3b8',
          textMuted: '#64748b',
          severity: {
            critical: '#dc2626',
            high: '#ef4444',
            medium: '#f59e0b',
            low: '#3b82f6',
            info: '#6b7280',
          },
          grade: {
            'A+': '#10b981',
            'A': '#22c55e',
            'B': '#84cc16',
            'C': '#eab308',
            'D': '#f97316',
            'F': '#dc2626',
          },
        },
      },
      fontFamily: {
        mono: ['"Fira Code"', '"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      animation: {
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'pulse-glow': 'pulseGlow 2s ease-in-out infinite',
        'spin-slow': 'spin 2s linear infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(12px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        pulseGlow: {
          '0%, 100%': { boxShadow: '0 0 5px rgba(59, 130, 246, 0.3)' },
          '50%': { boxShadow: '0 0 20px rgba(59, 130, 246, 0.6)' },
        },
      },
    },
  },
  plugins: [],
}

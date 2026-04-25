import type { Config } from 'tailwindcss'
import typography from '@tailwindcss/typography'

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        tron: {
          cyan: '#00e5ff',
          blue: '#0ea5e9',
          purple: '#7c3aed',
          dark: '#020c1b',
          panel: '#0a1628',
          border: '#0d2137',
          glow: 'rgba(0,229,255,0.2)',
        },
        status: {
          online: '#00ff88',
          offline: '#ff3333',
          scanning: '#ffd700',
          unknown: '#6b7280',
        },
      },
      boxShadow: {
        'tron-sm': '0 0 8px rgba(0,229,255,0.4)',
        'tron-md': '0 0 16px rgba(0,229,255,0.5)',
        'tron-lg': '0 0 32px rgba(0,229,255,0.6)',
        'tron-xl': '0 0 48px rgba(0,229,255,0.7)',
        'status-online': '0 0 12px rgba(0,255,136,0.6)',
        'status-offline': '0 0 12px rgba(255,51,51,0.6)',
        'status-scanning': '0 0 12px rgba(255,215,0,0.6)',
        'vuln-critical': '0 0 12px rgba(239,68,68,0.8)',
        'vuln-high': '0 0 8px rgba(249,115,22,0.6)',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-glow': 'pulseGlow 2s ease-in-out infinite',
        'pulse-fast': 'pulse 1s ease-in-out infinite',
        'scan-line': 'scanLine 3s linear infinite',
        'data-flow': 'dataFlow 1.5s linear infinite',
        'float': 'float 3s ease-in-out infinite',
      },
      keyframes: {
        pulseGlow: {
          '0%, 100%': { boxShadow: '0 0 8px rgba(0,229,255,0.4)' },
          '50%': { boxShadow: '0 0 24px rgba(0,229,255,0.8), 0 0 48px rgba(0,229,255,0.4)' },
        },
        scanLine: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        dataFlow: {
          '0%': { strokeDashoffset: '24' },
          '100%': { strokeDashoffset: '0' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-4px)' },
        },
      },
      backgroundImage: {
        'tron-grid': `
          linear-gradient(rgba(0,229,255,0.05) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0,229,255,0.05) 1px, transparent 1px)
        `,
      },
      backgroundSize: {
        'tron-grid': '40px 40px',
      },
    },
  },
  plugins: [typography],
} satisfies Config

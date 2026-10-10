import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{vue,ts,tsx}'],
  safelist: ['sev-critical', 'sev-high', 'sev-medium', 'sev-unknown', 'sev-low', 'sev-info'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: '#0d1117',
          raised: '#161b22',
          overlay: '#1c2128',
          border: '#30363d',
          'border-subtle': '#21262d',
        },
        accent: {
          DEFAULT: '#58a6ff',
          hover: '#79c0ff',
          muted: '#388bfd66',
        },
        sev: {
          critical: '#f85149',
          high: '#e6550d',
          medium: '#d29922',
          // No source rates it (ADR-038 §3): neutral, distinct from low.
          unknown: '#a3a3a3',
          low: '#8b949e',
          info: '#58a6ff',
        },
        // Malware has one colour everywhere: violet, so a malicious package
        // never reads as "just another critical" (red) or KEV (red flame).
        malware: {
          DEFAULT: '#a371f7',
          muted: '#a371f726',
        },
        ok: {
          DEFAULT: '#3fb950',
          muted: '#238636',
        },
        warn: {
          DEFAULT: '#d29922',
          muted: '#9e6a03',
        },
        danger: {
          DEFAULT: '#f85149',
          muted: '#da3633',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
} satisfies Config
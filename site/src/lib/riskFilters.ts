// The filter bar's risk qualifiers (ADR-038 §6): cvss:, epss: and
// epss-percentile:. Server-side like the CWE qualifiers: the value is a
// comparison the server compiles, so the bar sends them as `q`.

import type { CWEFilterDef, CWEValueSuggestion } from '@/lib/cweFilters'

const COMPARISON = /^((>=|<=|>|<|=)?\d+(\.\d+)?%?|none|any)$/i

function describeComparison(value: string, unit: 'cvss' | 'epss' | 'percentile') {
  if (/^none$/i.test(value)) {
    return { title: unit === 'cvss' ? 'No CVSS score' : 'No EPSS score', detail: unit === 'cvss' ? 'Findings no source scores, and code findings' : 'CVEs FIRST does not score, and non-CVE findings' }
  }
  if (/^any$/i.test(value)) return { title: unit === 'cvss' ? 'Any CVSS score' : 'Any EPSS score' }
  const match = /^(>=|<=|>|<|=)?(\d+(?:\.\d+)?)(%)?$/.exec(value)
  if (!match) return undefined
  const operator = { '>=': 'at least', '<=': 'at most', '>': 'above', '<': 'below', '=': 'exactly' }[match[1] ?? '>='] ?? 'at least'
  if (unit === 'cvss') return { title: `CVSS ${operator} ${match[2]}` }
  const number = match[3] ? Number(match[2]) : Number(match[2]) * 100
  return unit === 'epss'
    ? { title: `EPSS ${operator} ${number}%`, detail: 'Probability of exploitation in the next 30 days' }
    : { title: `EPSS percentile ${operator} ${number}%`, detail: 'Rank among all CVEs FIRST scores' }
}

function suggestions(items: CWEValueSuggestion[]) {
  return async (fragment: string) => items.filter(item => !fragment || item.value.startsWith(fragment.toLowerCase()))
}

export function riskFilterDefs(): CWEFilterDef[] {
  return [
    {
      key: 'cvss',
      label: 'CVSS',
      options: [],
      hidden: true,
      serverQuery: true,
      valuePattern: COMPARISON,
      description: 'The CVSS score a finding uses: cvss:>=7, cvss:<4, cvss:none',
      suggestValues: suggestions([
        { value: '>=9', label: 'critical', detail: 'CVSS 9.0 and above' },
        { value: '>=7', label: 'high and above', detail: 'CVSS 7.0 and above' },
        { value: '>=4', label: 'medium and above', detail: 'CVSS 4.0 and above' },
        { value: 'none', label: 'unscored', detail: 'No source scores it' },
      ]),
      describeValue: value => describeComparison(value, 'cvss'),
    },
    {
      key: 'epss',
      label: 'EPSS',
      options: [],
      hidden: true,
      serverQuery: true,
      valuePattern: COMPARISON,
      description: 'Probability of exploitation in the next 30 days (FIRST): epss:>=10%, epss:>=0.5',
      suggestValues: suggestions([
        { value: '>=10%', label: 'top exploitation risk', detail: 'At least a 1-in-10 chance of exploitation within 30 days' },
        { value: '>=1%', label: 'elevated', detail: 'At least a 1% chance within 30 days' },
        { value: 'none', label: 'unscored', detail: 'No EPSS score' },
      ]),
      describeValue: value => describeComparison(value, 'epss'),
    },
    {
      key: 'epss-percentile',
      label: 'EPSS percentile',
      options: [],
      hidden: true,
      serverQuery: true,
      valuePattern: COMPARISON,
      description: 'Rank of the EPSS score among all CVEs: epss-percentile:>=95%',
      suggestValues: suggestions([
        { value: '>=95%', label: 'top 5%', detail: 'More likely to be exploited than 95% of CVEs' },
        { value: '>=99%', label: 'top 1%' },
      ]),
      describeValue: value => describeComparison(value, 'percentile'),
    },
  ]
}

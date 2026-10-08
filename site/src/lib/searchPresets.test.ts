import { describe, expect, it } from 'vitest'

import { OPEN_RISK_KEV_QUERY, OPEN_RISK_QUERY } from './openRiskPreset'
import {
  BUILTIN_FINDINGS_PRESETS,
  barQueryText,
  barStateFromQuery,
  canonicalBarQuery,
  findActivePreset,
  findPresetByName,
  type PresetEntry,
} from './searchPresets'

const repoFilters = [
  { key: 'status', label: 'Status', options: ['detected', 'resolved', 'suppressed'], multi: true, hidden: true, defaultValue: 'detected' },
  { key: 'type', label: 'Type', options: ['dependency', 'sast', 'container', 'malware'], multi: true },
  { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'], multi: true },
  { key: 'acceptance', label: 'Triage', options: ['open', 'accepted', 'risk_accepted', 'false_positive', 'disputed'] },
  { key: 'tool', label: 'Sources', options: ['trivy', 'semgrep'], multi: true },
  { key: 'file', label: 'File', options: [], multi: true, freeform: true },
  { key: 'exploited', label: 'Exploited', options: ['true', 'false'] },
]
const orgFilters = repoFilters.filter(filter => filter.key !== 'file')

function saved(name: string, query: string): PresetEntry {
  return { id: name, name, query, builtin: false }
}

describe('built-in presets', () => {
  it('validate as advanced queries on both the repo and org lists', () => {
    for (const filters of [repoFilters, orgFilters]) {
      for (const preset of BUILTIN_FINDINGS_PRESETS) {
        expect(barStateFromQuery(preset.query, filters)).toEqual({ filters: {}, search: '', advancedQuery: preset.query })
      }
    }
    expect(BUILTIN_FINDINGS_PRESETS.map(preset => preset.query)).toEqual([OPEN_RISK_QUERY, OPEN_RISK_KEV_QUERY])
  })
})

describe('barStateFromQuery', () => {
  it('maps a plain query onto discrete filters, the hidden default status, and free text', () => {
    expect(barStateFromQuery('severity:critical,high type:dependency openssl', repoFilters)).toEqual({
      filters: { status: 'detected', severity: 'critical,high', type: 'dependency' },
      search: 'openssl',
      advancedQuery: '',
    })
  })

  it('refuses a query using a filter this list does not have', () => {
    expect(barStateFromQuery('file:go.mod', repoFilters)).toBeDefined()
    expect(barStateFromQuery('file:go.mod', orgFilters)).toBeUndefined()
  })

  it('refuses an invalid value', () => {
    expect(barStateFromQuery('severity:catastrophic', repoFilters)).toBeUndefined()
  })
})

describe('barQueryText', () => {
  it('prefers the advanced query and otherwise rebuilds the bar text', () => {
    expect(barQueryText({ filters: { type: 'sast' }, search: 'x', advancedQuery: ` ${OPEN_RISK_QUERY} ` }, repoFilters)).toBe(OPEN_RISK_QUERY)
    expect(barQueryText({ filters: { status: 'detected', type: 'sast' }, search: ' x ', advancedQuery: '' }, repoFilters)).toBe('type:sast x')
  })

  it('round-trips through barStateFromQuery', () => {
    const state = { filters: { status: 'detected', type: 'dependency', severity: 'critical', exploited: 'true' }, search: 'log4j', advancedQuery: '' }
    expect(barStateFromQuery(barQueryText(state, repoFilters), repoFilters)).toEqual(state)
  })
})

describe('findActivePreset', () => {
  const presets = [...BUILTIN_FINDINGS_PRESETS, saved('Critical deps', 'type:dependency severity:critical')]

  it('matches a plain preset regardless of qualifier order or the hidden default status', () => {
    expect(findActivePreset(presets, 'severity:critical  type:dependency', repoFilters)?.name).toBe('Critical deps')
    expect(findActivePreset(presets, 'status:detected severity:critical type:dependency', repoFilters)?.name).toBe('Critical deps')
  })

  it('matches an advanced preset modulo whitespace', () => {
    expect(findActivePreset(presets, OPEN_RISK_QUERY.replace(/ /g, '  '), repoFilters)?.name).toBe('Open risk')
  })

  it('matches nothing for an empty, different, or invalid query', () => {
    expect(findActivePreset(presets, '', repoFilters)).toBeUndefined()
    expect(findActivePreset(presets, 'severity:critical', repoFilters)).toBeUndefined()
    expect(findActivePreset(presets, '(severity:critical', repoFilters)).toBeUndefined()
  })

  it('is consistent with the query a preset applies', () => {
    for (const preset of presets) {
      const state = barStateFromQuery(preset.query, repoFilters)
      expect(state).toBeDefined()
      expect(findActivePreset(presets, barQueryText(state!, repoFilters), repoFilters)?.id).toBe(preset.id)
    }
  })
})

describe('canonicalBarQuery', () => {
  it('is undefined for queries the bar rejects', () => {
    expect(canonicalBarQuery('severity:nope', repoFilters)).toBeUndefined()
  })
})

describe('findPresetByName', () => {
  it('compares names case-insensitively and ignoring surrounding space', () => {
    expect(findPresetByName([saved('Triage', 'severity:low')], '  triage ')?.name).toBe('Triage')
    expect(findPresetByName([saved('Triage', 'severity:low')], 'Other')).toBeUndefined()
  })
})

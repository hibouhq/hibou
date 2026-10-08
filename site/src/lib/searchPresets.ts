import { buildBarQuery, parseBarQuery, type FilterBarFilter } from './filterBarQuery'
import { OPEN_RISK_KEV_QUERY, OPEN_RISK_QUERY } from './openRiskPreset'

export interface PresetEntry {
  id: string
  name: string
  query: string
  description?: string
  builtin: boolean
}

export const BUILTIN_FINDINGS_PRESETS: PresetEntry[] = [
  {
    id: 'builtin:open-risk',
    name: 'Open risk',
    query: OPEN_RISK_QUERY,
    description: 'Detected findings plus disputed suppressions that remain open or risk accepted',
    builtin: true,
  },
  {
    id: 'builtin:exploited-open-risk',
    name: 'Exploited open risk',
    query: OPEN_RISK_KEV_QUERY,
    description: 'Open risk on known-exploited dependencies (CISA KEV / ENISA EUVD)',
    builtin: true,
  },
]

export interface BarState {
  filters: Record<string, string>
  search: string
  advancedQuery: string
}

// The text the bar shows for a view state: an advanced query verbatim,
// otherwise the qualifiers and free text the discrete model holds.
export function barQueryText(state: BarState, filterDefs: FilterBarFilter[]) {
  if (state.advancedQuery.trim()) return state.advancedQuery.trim()
  return buildBarQuery(filterDefs, state.filters, state.search, true)
}

// The view state a preset query applies. Undefined when the query does not
// validate against this bar's filters (e.g. `file:` on the org list).
export function barStateFromQuery(query: string, filterDefs: FilterBarFilter[]): BarState | undefined {
  const parsed = parseBarQuery(query, filterDefs, true)
  if (parsed.issues.length > 0) return undefined
  if (parsed.advancedQuery) return { filters: {}, search: '', advancedQuery: parsed.advancedQuery }
  return { filters: parsed.filters, search: parsed.searchText, advancedQuery: '' }
}

// Two spellings of the same plain query (qualifier order, spacing, the hidden
// default status) compare equal; advanced queries compare by their text.
export function canonicalBarQuery(query: string, filterDefs: FilterBarFilter[]) {
  const state = barStateFromQuery(query, filterDefs)
  if (!state) return undefined
  if (state.advancedQuery) return state.advancedQuery.replace(/\s+/g, ' ').trim()
  return buildBarQuery(filterDefs, state.filters, state.search, true)
}

export function findActivePreset(presets: PresetEntry[], currentQuery: string, filterDefs: FilterBarFilter[]) {
  const current = canonicalBarQuery(currentQuery, filterDefs)
  if (!current) return undefined
  return presets.find(preset => canonicalBarQuery(preset.query, filterDefs) === current)
}

export function findPresetByName<T extends { name: string }>(presets: T[], name: string) {
  const wanted = name.trim().toLowerCase()
  return presets.find(preset => preset.name.trim().toLowerCase() === wanted)
}

import type { LocationQueryRaw } from 'vue-router'

import { buildBarQuery, type FilterBarFilter } from './filterBarQuery'

export const OPEN_RISK_QUERY = '(status:detected OR (status:suppressed AND acceptance:disputed)) AND (acceptance:open OR acceptance:risk_accepted)'
export const OPEN_RISK_KEV_QUERY = `${OPEN_RISK_QUERY} AND type:dependency AND exploited:true`

function andQuery(...clauses: string[]) {
  const present = clauses.map(clause => clause.trim()).filter(Boolean)
  return present.map(clause => `(${clause})`).join(' AND ')
}

export function migrateRiskOnlyQuery(query: LocationQueryRaw, filters: FilterBarFilter[]): LocationQueryRaw {
  const nextQuery = { ...query }
  if (nextQuery.risk_only !== 'true') return nextQuery

  delete nextQuery.risk_only

  const filterValues: Record<string, string> = {}
  for (const filter of filters) {
    const value = query[filter.key]
    if (typeof value === 'string' && value) filterValues[filter.key] = value
    delete nextQuery[filter.key]
  }

  const search = typeof query.search === 'string' ? query.search : ''
  delete nextQuery.search

  const existingQuery = typeof query.q === 'string' ? query.q : ''
  const explicitFilters = filters.map(filter => ({ ...filter, hidden: false }))
  const legacyQuery = buildBarQuery(explicitFilters, filterValues, search, true)
  nextQuery.q = andQuery(OPEN_RISK_QUERY, existingQuery, legacyQuery)

  return nextQuery
}

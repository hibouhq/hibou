// Client-side view of the embedded MITRE CWE catalog (ADR-037): titles for
// hover cards and chips, search for completion, and the named sets and
// categories the cwe-set: / cwe-category: qualifiers accept. The server is the
// source; this module only caches what it returned, per catalog version.

import { reactive, ref } from 'vue'

import { api, type CWECatalogEntry, type CWESetsResponse } from '@/api/client'

/** CWE id from any spelling the server accepts: 79, "79", "CWE-79", "cwe-079". */
export function parseCWE(value: string | number | undefined | null): number | undefined {
  if (typeof value === 'number') return Number.isInteger(value) && value > 0 ? value : undefined
  const match = /^\s*(?:cwe-)?0*([1-9]\d{0,6})\s*$/i.exec(value ?? '')
  return match ? Number(match[1]) : undefined
}

export function formatCWE(id: number): string {
  return `CWE-${id}`
}

/** MITRE's page for a CWE id. */
export function mitreCWEUrl(id: number): string {
  return `https://cwe.mitre.org/data/definitions/${id}.html`
}

// id → entry, or null when the catalog does not know the id (still a real
// producer claim; shown without a title). Reactive so chips and hover cards
// re-render when a batch lands.
const entries = reactive(new Map<number, CWECatalogEntry | null>())
const pending = new Set<number>()
let flushScheduled = false

/** The cached entry for id; undefined while unknown to the cache. */
export function cachedCWE(id: number): CWECatalogEntry | null | undefined {
  return entries.get(id)
}

/** Title for id from the cache, or '' when not (yet) known. */
export function cweTitle(id: number): string {
  return entries.get(id)?.name ?? ''
}

/** Seed the cache with entries a response already carried (titles inline). */
export function rememberCWEs(items: Array<{ id: number; name?: string }>) {
  for (const item of items) {
    if (item.name && !entries.get(item.id)) {
      entries.set(item.id, { id: item.id, name: item.name })
    }
  }
}

/**
 * Ensure titles for ids are loaded. Calls in the same tick share one request,
 * so a page of rows or a bar full of tokens costs one round trip.
 */
export function ensureCWEs(ids: number[]) {
  for (const id of ids) {
    if (!entries.has(id)) pending.add(id)
  }
  if (pending.size === 0 || flushScheduled) return
  flushScheduled = true
  queueMicrotask(async () => {
    flushScheduled = false
    const batch = [...pending].slice(0, 100)
    batch.forEach(id => pending.delete(id))
    if (batch.length === 0) return
    try {
      const response = await api.lookupCWEs(batch)
      const known = new Set<number>()
      for (const entry of response.data.entries) {
        entries.set(entry.id, entry.name ? entry : null)
        known.add(entry.id)
      }
      for (const id of batch) {
        if (!known.has(id)) entries.set(id, null)
      }
    } catch {
      // Titles are decoration: a failed lookup leaves bare ids, and the next
      // ensure() retries.
    }
    if (pending.size > 0) ensureCWEs([])
  })
}

/**
 * Load titles for ids and resolve once they are cached — for completion
 * rows, which are built once and must already carry the title.
 */
export async function loadCWEs(ids: number[]): Promise<void> {
  // An entry seeded from a list row has only a title; completion also needs
  // the hierarchy (descendants/ancestors), so those are fetched again.
  const missing = [...new Set(ids)].filter(id => {
    const entry = entries.get(id)
    return entry === undefined || (entry !== null && entry.descendants === undefined)
  }).slice(0, 100)
  if (missing.length === 0) return
  try {
    const response = await api.lookupCWEs(missing)
    const known = new Set<number>()
    for (const entry of response.data.entries) {
      entries.set(entry.id, entry.name ? entry : null)
      known.add(entry.id)
    }
    for (const id of missing) {
      if (!known.has(id)) entries.set(id, null)
    }
  } catch {
    // Rows fall back to bare ids.
  }
}

/** Catalog search by id or title (completion). */
export async function searchCWECatalog(query: string, limit = 12): Promise<CWECatalogEntry[]> {
  if (!query.trim()) return []
  try {
    const response = await api.searchCWEs(query, limit)
    for (const entry of response.data.entries) entries.set(entry.id, entry)
    return response.data.entries
  } catch {
    return []
  }
}

const sets = ref<CWESetsResponse | null>(null)
let setsRequest: Promise<CWESetsResponse | null> | null = null

/** Named sets and categories, fetched once per page load. */
export function loadCWESets(): Promise<CWESetsResponse | null> {
  if (sets.value) return Promise.resolve(sets.value)
  setsRequest ??= api.listCWESets()
    .then(response => {
      sets.value = response.data
      return response.data
    })
    .catch(() => {
      setsRequest = null
      return null
    })
  return setsRequest
}

/** The reactive sets payload (null until loadCWESets resolves). */
export function cweSets() {
  return sets
}

/** One-line description of a CWE for tooltips: "CWE-89 · title · Injection". */
export function describeCWEInline(id: number): string {
  const entry = entries.get(id)
  const parts = [formatCWE(id)]
  if (entry?.name) parts.push(entry.name)
  if (entry?.category?.name) parts.push(entry.category.name)
  return parts.join(' · ')
}

/** Sets worth a badge: the OWASP Top 10 umbrella adds nothing next to the
 * specific OWASP category it implies. */
export function displaySets<T extends { slug: string }>(sets: T[] | undefined): T[] {
  const list = sets ?? []
  const hasCategory = list.some(set => set.slug.startsWith('owasp-a'))
  return hasCategory ? list.filter(set => set.slug !== 'owasp-top10') : list
}

let pillars: Promise<CWECatalogEntry[]> | null = null

/** MITRE's pillars — the broadest View 1000 roots — fetched once. */
export function loadCWEPillars(): Promise<CWECatalogEntry[]> {
  pillars ??= api.listCWEsByAbstraction(['pillar'])
    .then(response => {
      for (const entry of response.data.entries) entries.set(entry.id, entry)
      return response.data.entries
    })
    .catch(() => {
      pillars = null
      return []
    })
  return pillars
}

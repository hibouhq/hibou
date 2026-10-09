// The filter bar's CWE qualifiers (ADR-037 §5): cwe:, cwe-tree:, cwe-set:
// and cwe-category:. Every suggestion and hover card carries the CWE title, so
// nobody has to know what CWE-1321 is. They are server-side qualifiers — the
// discrete filter model has no CWE field — so the bar sends them as `q`.

import {
  cachedCWE,
  cweSets,
  cweTitle,
  ensureCWEs,
  formatCWE,
  loadCWEPillars,
  loadCWEs,
  loadCWESets,
  parseCWE,
  searchCWECatalog,
} from '@/lib/cweCatalog'

export interface CWEValueSuggestion {
  value: string
  label?: string
  detail?: string
  count?: number
  group?: string
}

export interface CWEFilterDef {
  key: string
  label: string
  options: string[]
  multi?: boolean
  hidden?: boolean
  serverQuery?: boolean
  valuePattern?: RegExp
  description?: string
  suggestValues?: (fragment: string) => Promise<CWEValueSuggestion[]>
  describeValue?: (value: string) => { title: string; detail?: string } | undefined
}

const ID_OR_TEST = /^((cwe-)?\d+|none|any)$/i
const ID_ONLY = /^(cwe-)?\d+$/i

function entryDetail(id: number): string | undefined {
  const entry = cachedCWE(id)
  if (!entry) return undefined
  const parts: string[] = []
  if (entry.category?.name) parts.push(entry.category.name)
  for (const set of entry.sets ?? []) {
    parts.push(set.rank ? `${set.name} #${set.rank}` : set.name)
  }
  if (entry.deprecated) parts.push('deprecated')
  return parts.join(' · ') || undefined
}

function describeId(value: string, tree: boolean) {
  const id = parseCWE(value)
  if (id === undefined) return undefined
  ensureCWEs([id])
  const entry = cachedCWE(id)
  const title = entry?.name ? `${formatCWE(id)} · ${entry.name}` : formatCWE(id)
  if (entry === null) return { title, detail: 'Not in the CWE catalog — matched as reported by the scanner' }
  let detail = entryDetail(id)
  if (tree && entry?.descendants !== undefined) {
    detail = [`with ${entry.descendants} descendant${entry.descendants === 1 ? '' : 's'}`, detail].filter(Boolean).join(' · ')
  }
  return { title, detail }
}

/**
 * Build the four qualifiers. `facet` returns the current view's CWE counts
 * (id → findings), offered first as "In this view".
 */
export function cweFilterDefs(facet: () => Record<string, number> | undefined): CWEFilterDef[] {
  void loadCWESets()
  const sets = cweSets().value

  const inView = async (fragment: string, tree: boolean): Promise<CWEValueSuggestion[]> => {
    const counts = facet() ?? {}
    const ids = Object.keys(counts).map(Number).filter(Number.isFinite)
    await loadCWEs(ids)
    const needle = fragment.toLowerCase().replace(/^cwe-/, '')
    return ids
      .filter(id => !needle || String(id).startsWith(needle) || cweTitle(id).toLowerCase().includes(needle))
      .sort((a, b) => (counts[b] ?? 0) - (counts[a] ?? 0))
      .map(id => {
        const entry = cachedCWE(id)
        const title = entry?.name ?? ''
        return {
          value: String(id),
          label: formatCWE(id),
          detail: (tree && entry?.descendants ? `${title} · +${entry.descendants}` : title) || undefined,
          count: counts[String(id)],
          group: 'In this view',
        }
      })
  }

  const catalog = async (fragment: string, exclude: Set<string>, tree: boolean): Promise<CWEValueSuggestion[]> => {
    const results = await searchCWECatalog(fragment, 12)
    return results
      .filter(entry => !exclude.has(String(entry.id)))
      .map(entry => ({
        value: String(entry.id),
        label: formatCWE(entry.id),
        detail: tree && entry.descendants ? `${entry.name} · +${entry.descendants}` : entry.name,
        group: 'All CWEs',
      }))
  }

  const idSuggestions = (tree: boolean) => async (fragment: string): Promise<CWEValueSuggestion[]> => {
    const local = await inView(fragment, tree)
    const special: CWEValueSuggestion[] = tree || fragment ? [] : [
      { value: 'none', detail: 'Findings with no CWE — scanners that classify nothing', group: 'Coverage' },
      { value: 'any', detail: 'Findings with at least one CWE', group: 'Coverage' },
    ]
    if (!fragment) return [...local.slice(0, 15), ...special]
    const remote = await catalog(fragment, new Set(local.map(item => item.value)), tree)
    return [...local.slice(0, 10), ...remote]
  }

  // cwe-tree: wants the broad parents of what is in view: scanners report
  // CWE-89, a tree query names CWE-74 (Injection) to catch all its kinds.
  // Each ancestor is ranked by the findings it would cover (summed facet
  // counts — a finding under two of its children counts twice, a hint, not a
  // total); pillars sit apart because they contain nearly everything.
  const treeSuggestions = async (fragment: string): Promise<CWEValueSuggestion[]> => {
    const counts = facet() ?? {}
    const ids = Object.keys(counts).map(Number).filter(Number.isFinite)
    await loadCWEs(ids)
    const covered = new Map<number, number>()
    for (const id of ids) {
      for (const ancestor of cachedCWE(id)?.ancestors ?? []) {
        covered.set(ancestor, (covered.get(ancestor) ?? 0) + (counts[String(id)] ?? 0))
      }
    }
    await loadCWEs([...covered.keys()])
    const [roots] = await Promise.all([loadCWEPillars()])
    const needle = fragment.toLowerCase().replace(/^cwe-/, '')
    const matches = (id: number) => !needle || String(id).startsWith(needle) || cweTitle(id).toLowerCase().includes(needle)
    const describe = (id: number) => {
      const entry = cachedCWE(id)
      const subtypes = entry?.descendants ? ` · ${entry.descendants} sub-types` : ''
      return `${entry?.name ?? ''}${subtypes}` || undefined
    }
    const inView = [...covered.entries()]
      .filter(([id]) => cachedCWE(id)?.abstraction !== 'pillar' && matches(id))
      .sort((a, b) => (b[1] - a[1]) || ((cachedCWE(a[0])?.descendants ?? 0) - (cachedCWE(b[0])?.descendants ?? 0)))
      .slice(0, 12)
      .map(([id, count]) => ({ value: String(id), label: formatCWE(id), detail: describe(id), count, group: 'Parents of CWEs in this view' }))
    const broad = roots
      .filter(entry => matches(entry.id))
      .map(entry => ({ value: String(entry.id), label: formatCWE(entry.id), detail: describe(entry.id), count: covered.get(entry.id), group: 'Broad roots' }))
    if (!fragment) return [...inView, ...broad]
    const remote = await catalog(fragment, new Set([...inView, ...broad].map(item => item.value)), true)
    return [...inView, ...broad, ...remote]
  }

  const setOptions = (sets?.sets ?? []).map(set => set.slug)
  const categoryOptions = (sets?.categories ?? []).map(set => set.slug)

  return [
    {
      key: 'cwe',
      label: 'CWE',
      options: [],
      multi: true,
      hidden: true,
      serverQuery: true,
      valuePattern: ID_OR_TEST,
      description: 'Findings carrying a CWE — from the scanner rule, the advisory, or a manual declaration',
      suggestValues: idSuggestions(false),
      describeValue: (value) => {
        if (/^none$/i.test(value)) return { title: 'No CWE', detail: 'Findings whose scanner or advisory gives no CWE' }
        if (/^any$/i.test(value)) return { title: 'Any CWE', detail: 'Findings carrying at least one CWE' }
        return describeId(value, false)
      },
    },
    {
      key: 'cwe-tree',
      label: 'CWE + sub-types',
      options: [],
      multi: true,
      hidden: true,
      serverQuery: true,
      valuePattern: ID_ONLY,
      description: 'A CWE and all its sub-types in MITRE\'s hierarchy: cwe-tree:74 (Injection) also matches SQL injection, XSS, command injection…',
      suggestValues: treeSuggestions,
      describeValue: (value) => describeId(value, true),
    },
    {
      key: 'cwe-set',
      label: 'CWE list',
      options: setOptions,
      multi: true,
      hidden: true,
      serverQuery: true,
      description: 'Named CWE lists: CWE Top 25, OWASP Top 10 and its categories',
      suggestValues: async (fragment) => (cweSets().value?.sets ?? [])
        .filter(set => !fragment || set.slug.includes(fragment.toLowerCase()) || set.name.toLowerCase().includes(fragment.toLowerCase()))
        .map(set => ({ value: set.slug, detail: `${set.name} · ${set.member_count} CWEs` })),
      describeValue: (value) => {
        const set = cweSets().value?.sets.find(item => item.slug === value.toLowerCase())
        return set ? { title: set.name, detail: `${set.member_count} CWEs` } : undefined
      },
    },
    {
      key: 'cwe-category',
      label: 'CWE category',
      options: categoryOptions,
      multi: true,
      hidden: true,
      serverQuery: true,
      description: 'MITRE View 1400 categories: every weakness is in exactly one (Injection, Encryption, …)',
      suggestValues: async (fragment) => (cweSets().value?.categories ?? [])
        .filter(set => !fragment || set.slug.includes(fragment.toLowerCase()) || set.name.toLowerCase().includes(fragment.toLowerCase()))
        .map(set => ({ value: set.slug, detail: `${set.name} · ${set.member_count} CWEs` })),
      describeValue: (value) => {
        const category = cweSets().value?.categories.find(item => item.slug === value.toLowerCase())
        return category ? { title: `Category: ${category.name}`, detail: `${category.member_count} CWEs` } : undefined
      },
    },
  ]
}

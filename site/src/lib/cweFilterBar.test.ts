import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'

import CweChips from '@/components/finding/CweChips.vue'
import { parseCWE } from '@/lib/cweCatalog'
import { appendBarToken, highlightBarQuery, parseBarQuery, withHiddenDefaults, type FilterBarFilter } from '@/lib/filterBarQuery'

// The findings tab's filters plus ADR-037's server-side CWE qualifiers.
const FILTERS: FilterBarFilter[] = [
  { key: 'status', label: 'Status', options: ['detected', 'resolved', 'suppressed'], multi: true, hidden: true, defaultValue: 'detected' },
  { key: 'type', label: 'Type', options: ['sast', 'dependency', 'secret'], multi: true },
  { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'], multi: true },
  { key: 'cwe', label: 'CWE', options: [], multi: true, hidden: true, serverQuery: true, valuePattern: /^((cwe-)?\d+|none|any)$/i },
  { key: 'cwe-set', label: 'CWE list', options: ['top25', 'owasp-a03'], multi: true, hidden: true, serverQuery: true },
]

const parse = (query: string) => parseBarQuery(query, FILTERS, true)

describe('server-side CWE qualifiers in the plain dialect', () => {
  it('runs the whole bar server-side but keeps the discrete model live', () => {
    const parsed = parse('severity:high cwe:89')
    expect(parsed.booleanSyntax).toBe(false)
    expect(parsed.advancedQuery).toBe('severity:high cwe:89')
    // The dropdowns still reflect severity:high…
    expect(parsed.filters.severity).toBe('high')
    // …and the CWE token is not a discrete filter the server would ignore.
    expect(parsed.filters.cwe).toBeUndefined()
    expect(parsed.serverTokens).toEqual(['cwe:89'])
  })

  it('treats a bare CWE-79 as the CWE, not as title search', () => {
    const parsed = parse('log4j CWE-79')
    expect(parsed.searchText).toBe('log4j')
    expect(parsed.serverTokens).toEqual(['CWE-79'])
    expect(parsed.advancedQuery).toBe('log4j CWE-79')
  })

  it('rejects malformed CWE values instead of sending them', () => {
    const parsed = parse('cwe:sqli')
    expect(parsed.issues.map(issue => issue.id)).toContain('invalid-value:cwe:sqli')
    expect(parsed.advancedQuery).toBe('')
  })

  it('a plain query without CWE qualifiers stays discrete', () => {
    expect(parse('severity:high').advancedQuery).toBe('')
  })
})

describe('withHiddenDefaults', () => {
  it('applies the invisible status:detected default to server-side queries', () => {
    expect(withHiddenDefaults('cwe:89', FILTERS)).toBe('status:detected (cwe:89)')
    // Boolean structure stays intact inside the group.
    expect(withHiddenDefaults('cwe:89 OR type:secret', FILTERS)).toBe('status:detected (cwe:89 OR type:secret)')
  })

  it('leaves a query that sets the key alone', () => {
    expect(withHiddenDefaults('status:resolved cwe:89', FILTERS)).toBe('status:resolved cwe:89')
    expect(withHiddenDefaults('', FILTERS)).toBe('')
  })
})

describe('appendBarToken (CWE chip click)', () => {
  it('adds the qualifier to the current plain bar', () => {
    expect(appendBarToken(FILTERS, { filters: { status: 'detected', severity: 'high' }, searchText: '', advancedQuery: '' }, 'cwe:79'))
      .toBe('severity:high cwe:79')
  })

  it('wraps a boolean query so the new qualifier narrows all of it', () => {
    expect(appendBarToken(FILTERS, { filters: {}, searchText: '', advancedQuery: 'type:sast OR type:secret' }, 'cwe:79'))
      .toBe('(type:sast OR type:secret) cwe:79')
  })

  it('does not add a token twice', () => {
    expect(appendBarToken(FILTERS, { filters: {}, searchText: '', advancedQuery: 'cwe:79' }, 'cwe:79')).toBe('cwe:79')
  })
})

describe('parseCWE', () => {
  it.each([['79', 79], ['CWE-79', 79], ['cwe-079', 79], [89, 89]] as const)('%s → %s', (input, want) => {
    expect(parseCWE(input)).toBe(want)
  })
  it.each(['NVD-CWE-Other', 'abc', '', '0'])('%s is not a CWE', input => {
    expect(parseCWE(input)).toBeUndefined()
  })
})

describe('CweChips', () => {
  it('shows ids, keeps the title in the tooltip, and collapses the rest', async () => {
    const html = await renderToString(createSSRApp({
      render: () => h(CweChips, {
        max: 1,
        cwes: [
          { id: 89, name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", category: { slug: 'injection', name: 'Injection' }, sets: [{ slug: 'top25', name: 'CWE Top 25 (2025)', rank: 2 }] },
          { id: 564, name: 'SQL Injection: Hibernate' },
        ],
      }),
    }))
    expect(html).toContain('CWE-89')
    expect(html).toContain('SQL Injection')
    expect(html).toContain('Category: Injection')
    expect(html).toContain('CWE Top 25 (2025) #2')
    expect(html).toContain('+1')
    expect(html).not.toContain('>CWE-564<')
  })
})

describe('GitHub-style exclusion (-key:value)', () => {
  it('runs server-side and keeps the discrete model untouched', () => {
    const parsed = parse('cwe:400 -type:dependency,secret')
    expect(parsed.issues).toEqual([])
    expect(parsed.filters.type).toBeUndefined()
    expect(parsed.serverTokens).toEqual(['cwe:400', '-type:dependency,secret'])
    expect(parsed.advancedQuery).toBe('cwe:400 -type:dependency,secret')
  })

  it('validates excluded values like included ones', () => {
    expect(parse('-type:nonsense').issues.map(issue => issue.id)).toContain('invalid-value:type:nonsense')
    expect(parse('-bogus:x').issues.map(issue => issue.id)).toContain('unknown-filter:-bogus')
  })

  it('a dash on plain text is still search text', () => {
    expect(parse('-foo').searchText).toBe('-foo')
  })

  it('does not count an exclusion as setting the hidden default', () => {
    expect(withHiddenDefaults('-status:suppressed', FILTERS)).toBe('status:detected (-status:suppressed)')
  })

  it('highlights the minus apart from the qualifier', () => {
    const segments = highlightBarQuery('-type:sast', FILTERS)
    expect(segments[0]).toEqual({ text: '-', className: 'text-[#ff7b72]' })
    expect(segments.map(segment => segment.text).join('')).toBe('-type:sast')
  })
})

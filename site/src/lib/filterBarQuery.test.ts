import { describe, expect, it } from 'vitest'

import { buildBarQuery, parseBarQuery, tokenizeBarQuery, type FilterBarFilter } from './filterBarQuery'

// The repo findings tab's filter set, shape-for-shape.
const FILTERS: FilterBarFilter[] = [
  { key: 'status', label: 'Status', options: ['detected', 'resolved', 'suppressed'], multi: true, hidden: true, defaultValue: 'detected' },
  { key: 'type', label: 'Type', options: ['sast', 'dependency', 'secret'], multi: true },
  { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'], multi: true },
  { key: 'acceptance', label: 'Triage', options: ['open', 'accepted', 'risk_accepted', 'false_positive', 'disputed'] },
  { key: 'file', label: 'File', options: ['main.go'], multi: true, freeform: true },
]

function tokens(query: string): string[] {
  return tokenizeBarQuery(query).filter(chunk => !chunk.isWhitespace).map(chunk => chunk.text)
}

function parse(query: string) {
  return parseBarQuery(query, FILTERS, true)
}

describe('tokenizeBarQuery', () => {
  it('does not swallow connectives into a qualifier value (the reported bug)', () => {
    // Double space before `and` was the original failure shape.
    expect(tokens('status:detected,suppressed  and severity:high and type:sast')).toEqual([
      'status:detected,suppressed', 'and', 'severity:high', 'and', 'type:sast',
    ])
  })

  it('splits parentheses even when glued to tokens', () => {
    expect(tokens('(severity:high or severity:critical) and type:sast')).toEqual([
      '(', 'severity:high', 'or', 'severity:critical', ')', 'and', 'type:sast',
    ])
  })

  it('is case-insensitive about connectives', () => {
    expect(tokens('severity:high AND type:sast OR type:secret')).toEqual([
      'severity:high', 'AND', 'type:sast', 'OR', 'type:secret',
    ])
  })

  it('a word merely starting with a connective is a plain word, not an operator', () => {
    const parsed = parse('severity:high android')
    expect(parsed.searchText).toBe('android')
    expect(parsed.issues).toEqual([])
  })

  it('values are whitespace-delimited — words after a qualifier are free text', () => {
    // The old behavior merged everything up to the next qualifier into the
    // value, which is how "suppressed and" became an invalid status.
    expect(tokens('file:some path')).toEqual(['file:some', 'path'])
  })
})

describe('parseBarQuery — plain queries', () => {
  it('parses the reported bug string without issues', () => {
    const parsed = parse('status:detected,suppressed  and severity:high and type:sast')
    expect(parsed.issues).toEqual([])
    expect(parsed.advancedQuery).toBe('')
    expect(parsed.filters.status).toBe('detected,suppressed')
    expect(parsed.filters.severity).toBe('high')
    expect(parsed.filters.type).toBe('sast')
  })

  it('injects hidden defaults when the query does not name them', () => {
    expect(parse('severity:high').filters.status).toBe('detected')
  })

  it('flags invalid values and unknown keys', () => {
    const invalid = parse('status:bogus')
    expect(invalid.issues.some(issue => issue.id.startsWith('invalid-value:status'))).toBe(true)
    const unknown = parse('nosuchkey:x')
    expect(unknown.issues.some(issue => issue.id.startsWith('unknown-filter'))).toBe(true)
  })

  it('keeps free text out of the filters and connectives out of the free text', () => {
    const parsed = parse('severity:high and memory')
    expect(parsed.searchText).toBe('memory')
    expect(parsed.filters.severity).toBe('high')
  })
})

describe('parseBarQuery — advanced queries (OR / parentheses)', () => {
  it('marks OR queries advanced and returns them verbatim', () => {
    const parsed = parse('severity:high or severity:critical')
    expect(parsed.issues).toEqual([])
    expect(parsed.advancedQuery).toBe('severity:high or severity:critical')
  })

  it('handles parenthesised queries', () => {
    const parsed = parse('(severity:high or severity:critical) and type:sast')
    expect(parsed.issues).toEqual([])
    expect(parsed.advancedQuery).toBe('(severity:high or severity:critical) and type:sast')
  })

  it('still validates qualifier values inside an advanced query', () => {
    const parsed = parse('severity:bogus or type:sast')
    expect(parsed.issues.some(issue => issue.id.startsWith('invalid-value:severity'))).toBe(true)
    // A query with issues is never handed to the server.
    expect(parsed.advancedQuery).toBe('')
  })

  it('flags unbalanced parentheses in both directions', () => {
    expect(parse('(severity:high or type:sast').issues.some(issue => issue.id === 'parens:unbalanced')).toBe(true)
    expect(parse('severity:high or type:sast)').issues.some(issue => issue.id === 'parens:unbalanced')).toBe(true)
  })

  it('flags dangling connectives', () => {
    for (const query of ['and severity:high', 'severity:high or', 'severity:high and and type:sast', '(or severity:high)']) {
      expect(parse(query).issues.some(issue => issue.id.startsWith('connective:')), query).toBe(true)
    }
  })
})

describe('buildBarQuery', () => {
  it('keeps a hidden filter silent at its default and audible otherwise', () => {
    expect(buildBarQuery(FILTERS, { status: 'detected' }, '', true)).toBe('')
    expect(buildBarQuery(FILTERS, { status: 'detected,suppressed' }, '', true)).toBe('status:detected,suppressed')
  })

  it('round-trips with parseBarQuery', () => {
    const built = buildBarQuery(FILTERS, { status: 'detected,suppressed', severity: 'high' }, 'leak', true)
    const parsed = parse(built)
    expect(parsed.filters.status).toBe('detected,suppressed')
    expect(parsed.filters.severity).toBe('high')
    expect(parsed.searchText).toBe('leak')
    expect(parsed.issues).toEqual([])
  })
})

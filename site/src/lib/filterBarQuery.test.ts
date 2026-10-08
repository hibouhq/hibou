import { describe, expect, it } from 'vitest'

import { buildBarQuery, getCursorContext, highlightBarQuery, parseBarQuery, tokenizeBarQuery, type FilterBarFilter } from './filterBarQuery'

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

describe('getCursorContext', () => {
  it('stops a token at parentheses on either side', () => {
    const text = '(status:detected OR acceptance:)'
    expect(getCursorContext(text, text.length - 1)).toEqual({ token: 'acceptance:', start: 20, end: 31 })
    expect(getCursorContext('(sta', 4)).toEqual({ token: 'sta', start: 1, end: 4 })
    expect(getCursorContext('(status:det)', 11)).toEqual({ token: 'status:det', start: 1, end: 11 })
  })

  it('reads an empty token right after a paren or a space', () => {
    expect(getCursorContext('(a:1)', 5)).toEqual({ token: '', start: 5, end: 5 })
    expect(getCursorContext('a:1 ', 4)).toEqual({ token: '', start: 4, end: 4 })
  })

  it('spans the whole word when the cursor is inside it', () => {
    expect(getCursorContext('severity:cri high', 11)).toEqual({ token: 'severity:cri', start: 0, end: 12 })
  })
})

describe('validation messages', () => {
  const defs: FilterBarFilter[] = [
    { key: 'acceptance', label: 'Triage', options: ['open', 'accepted', 'risk_accepted', 'false_positive', 'disputed'] },
    { key: 'type', label: 'Type', options: ['dependency', 'sast'], multi: true },
  ]
  const text = (query: string) => parseBarQuery(query, defs, true).issues.map(issue => issue.parts.map(part => part.text).join(''))

  it('explains that a single-value filter takes no comma list', () => {
    expect(text('acceptance:risk_accepted,')).toEqual(['acceptance: takes one value — use OR to match several'])
  })

  it('suggests valid values', () => {
    expect(text('acceptance:')).toEqual(['acceptance: needs a value — try open, accepted, risk_accepted, false_positive, …'])
    expect(text('type:binary')).toEqual(['binary is not a valid type — try dependency, sast'])
    expect(text('owner:me')).toEqual(['owner is not a filter — try acceptance:, type:'])
  })
})

describe('booleanSyntax', () => {
  const defs: FilterBarFilter[] = [{ key: 'severity', label: 'Severity', options: ['high', 'low'], multi: true }]

  it('stays set while a boolean query has issues, though nothing is sent', () => {
    for (const query of ['(severity:high', 'severity:high OR', 'severity:nope OR severity:low']) {
      const parsed = parseBarQuery(query, defs, true)
      expect(parsed.booleanSyntax, query).toBe(true)
      expect(parsed.advancedQuery, query).toBe('')
    }
  })

  it('is unset for a plain query', () => {
    expect(parseBarQuery('severity:nope', defs, true).booleanSyntax).toBe(false)
  })
})

describe('highlightBarQuery', () => {
  const defs: FilterBarFilter[] = [
    { key: 'type', label: 'Type', options: ['dependency', 'sast'], multi: true },
    { key: 'acceptance', label: 'Triage', options: ['open', 'risk_accepted'] },
  ]

  it('reproduces the text exactly', () => {
    const query = '(type:dependency,sast OR acceptance:open)  AND openssl owner:x'
    expect(highlightBarQuery(query, defs).map(segment => segment.text).join('')).toBe(query)
  })

  it('colours structure, valid values and problems', () => {
    const byText = Object.fromEntries(highlightBarQuery('(type:sast,bogus OR nope:x)', defs).map(segment => [segment.text, segment.className]))
    expect(byText['(']).toBe('text-[#d29922]')
    expect(byText.OR).toBe('text-[#d2a8ff]')
    expect(byText.sast).toBe('text-[#79c0ff]')
    expect(byText.bogus).toBe('text-[#d29922]')
    expect(byText.nope).toBe('text-[#d29922]')
  })
})

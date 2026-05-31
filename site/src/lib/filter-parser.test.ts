import { describe, expect, it } from 'vitest'

import { parse, serialize, toQueryString, tokenize, type FilterNode } from './filter-parser'

function expectQualifier(node: FilterNode | null, key: string, value: string) {
  expect(node).not.toBeNull()
  expect(node).toMatchObject({ type: 'qualifier', key, value })
}

describe('tokenize', () => {
  it('keeps qualifiers and operators distinct', () => {
    expect(tokenize('(type:sast OR severity:high)')).toEqual([
      { type: 'LPAREN', value: '(', start: 0, end: 1 },
      { type: 'QUALIFIER', value: 'type:sast', start: 1, end: 10 },
      { type: 'OR', value: 'OR', start: 11, end: 13 },
      { type: 'QUALIFIER', value: 'severity:high', start: 14, end: 27 },
      { type: 'RPAREN', value: ')', start: 27, end: 28 },
      { type: 'EOF', value: '', start: 28, end: 28 },
    ])
  })
})

describe('parse', () => {
  it('handles empty input', () => {
    const result = parse('')
    expect(result.errors).toEqual([])
    expect(result.node).toBeNull()
  })

  it('parses simple qualifier', () => {
    const result = parse('type:sast')
    expect(result.errors).toEqual([])
    expectQualifier(result.node, 'type', 'sast')
  })

  it('parses implicit AND between qualifiers', () => {
    const result = parse('type:sast severity:high')
    expect(result.errors).toEqual([])
    expect(result.node).toMatchObject({
      type: 'and',
      left: { type: 'qualifier', key: 'type', value: 'sast' },
      right: { type: 'qualifier', key: 'severity', value: 'high' },
    })
  })

  it('parses explicit AND', () => {
    const result = parse('type:sast AND severity:high')
    expect(result.errors).toEqual([])
    expect(result.node).toMatchObject({ type: 'and' })
  })

  it('parses OR', () => {
    const result = parse('type:sast OR type:secret')
    expect(result.errors).toEqual([])
    expect(result.node).toMatchObject({ type: 'or' })
  })

  it('respects parentheses precedence', () => {
    const result = parse('(type:sast OR type:secret) AND severity:high')
    expect(result.errors).toEqual([])
    expect(result.node).toMatchObject({
      type: 'and',
      left: {
        type: 'group',
        child: {
          type: 'or',
          left: { type: 'qualifier', key: 'type', value: 'sast' },
          right: { type: 'qualifier', key: 'type', value: 'secret' },
        },
      },
      right: { type: 'qualifier', key: 'severity', value: 'high' },
    })
  })

  it('parses nested parentheses', () => {
    const result = parse('((type:sast OR type:secret) AND severity:critical) OR type:malware')
    expect(result.errors).toEqual([])
    expect(result.node).toMatchObject({ type: 'or' })
  })

  it('rejects excessive nesting depth', () => {
    const input = `${'('.repeat(17)}type:sast${')'.repeat(17)}`
    const result = parse(input)
    expect(result.errors).toHaveLength(1)
    expect(result.errors[0]?.message).toContain('maximum depth of 16')
  })

  it('keeps comma shorthand as qualifier value', () => {
    const result = parse('type:sast,secret')
    expect(result.errors).toEqual([])
    expectQualifier(result.node, 'type', 'sast,secret')
  })

  it('binds AND tighter than OR', () => {
    const result = parse('type:sast severity:high OR type:secret')
    expect(result.errors).toEqual([])
    expect(result.node).toMatchObject({
      type: 'or',
      left: {
        type: 'and',
        left: { type: 'qualifier', key: 'type', value: 'sast' },
        right: { type: 'qualifier', key: 'severity', value: 'high' },
      },
      right: { type: 'qualifier', key: 'type', value: 'secret' },
    })
  })

  it('normalizes case for qualifiers and operators', () => {
    const result = parse('Type:SAST and Severity:HIGH')
    expect(result.errors).toEqual([])
    expect(serialize(result.node as FilterNode)).toBe('type:sast AND severity:high')
  })

  it('includes free text as a text node', () => {
    const result = parse('some text type:sast')
    expect(result.errors).toEqual([])
    expect(result.node).toMatchObject({
      type: 'and',
      left: { type: 'text', value: 'some text' },
      right: { type: 'qualifier', key: 'type', value: 'sast' },
    })
  })

  it('parses free text as text node', () => {
    const result = parse('zlib')
    expect(result.errors).toEqual([])
    expect(result.node).toEqual({ type: 'text', value: 'zlib' })
  })

  it('joins consecutive text tokens', () => {
    const result = parse('hello world')
    expect(result.errors).toEqual([])
    expect(result.node).toEqual({ type: 'text', value: 'hello world' })
  })

  it('combines free text with qualifiers', () => {
    const result = parse('CVE-2023 type:dependency')
    expect(result.errors).toEqual([])
    expect(result.node).toMatchObject({
      type: 'and',
      left: { type: 'text', value: 'CVE-2023' },
      right: { type: 'qualifier', key: 'type', value: 'dependency' },
    })
  })

  it('handles OR between free text and qualifier', () => {
    const result = parse('zlib OR type:sast')
    expect(result.errors).toEqual([])
    expect(result.node).toMatchObject({
      type: 'or',
      left: { type: 'text', value: 'zlib' },
      right: { type: 'qualifier', key: 'type', value: 'sast' },
    })
  })

  it('parses qualifier with colon in value', () => {
    const result = parse('file:src/main.go')
    expect(result.errors).toEqual([])
    expectQualifier(result.node, 'file', 'src/main.go')
  })

  it('handles multiple OR chains', () => {
    const result = parse('type:sast OR type:secret OR type:malware')
    expect(result.errors).toEqual([])
    expect(result.node).toMatchObject({
      type: 'or',
      left: {
        type: 'or',
        left: { type: 'qualifier', key: 'type', value: 'sast' },
        right: { type: 'qualifier', key: 'type', value: 'secret' },
      },
      right: { type: 'qualifier', key: 'type', value: 'malware' },
    })
  })

  it('handles multiple AND chains', () => {
    const result = parse('type:sast severity:high status:detected')
    expect(result.errors).toEqual([])
    expect(result.node).toMatchObject({
      type: 'and',
      left: {
        type: 'and',
        left: { type: 'qualifier', key: 'type', value: 'sast' },
        right: { type: 'qualifier', key: 'severity', value: 'high' },
      },
      right: { type: 'qualifier', key: 'status', value: 'detected' },
    })
  })

  it('handles mixed precedence with parens', () => {
    const result = parse('type:sast OR (severity:critical AND file:main.go)')
    expect(result.errors).toEqual([])
    expect(result.node).toMatchObject({
      type: 'or',
      left: { type: 'qualifier', key: 'type', value: 'sast' },
      right: {
        type: 'group',
        child: {
          type: 'and',
          left: { type: 'qualifier', key: 'severity', value: 'critical' },
          right: { type: 'qualifier', key: 'file', value: 'main.go' },
        },
      },
    })
  })

  it('reports trailing OR error', () => {
    const result = parse('type:sast OR')
    expect(result.errors).not.toEqual([])
    expect(result.errors[0]?.message).toContain('OR must be followed')
  })

  it('reports consecutive operators', () => {
    const result = parse('type:sast AND OR severity:high')
    expect(result.errors.length).toBeGreaterThan(0)
  })

  it('parses case-insensitive operators', () => {
    const lower = parse('type:sast and severity:high')
    const mixed = parse('type:sast And severity:high')
    expect(lower.errors).toEqual([])
    expect(mixed.errors).toEqual([])
    expect(lower.node).toMatchObject({ type: 'and' })
    expect(mixed.node).toMatchObject({ type: 'and' })
  })

  it('reports unmatched parentheses', () => {
    const result = parse('(type:sast OR type:secret')
    expect(result.errors).toHaveLength(1)
    expect(result.errors[0]?.message).toContain('Missing closing parenthesis')
  })

  it('reports empty parentheses', () => {
    const result = parse('() AND type:sast')
    expect(result.errors).not.toHaveLength(0)
    expect(result.errors[0]?.message).toContain('Parentheses cannot be empty')
  })

  it('reports trailing operators', () => {
    const result = parse('type:sast AND')
    expect(result.errors).not.toHaveLength(0)
    expect(result.errors[0]?.message).toContain('AND must be followed')
  })
})

describe('serialize', () => {
  it('serialize handles text nodes', () => {
    expect(serialize({ type: 'text', value: 'zlib' })).toBe('zlib')
  })

  it('round-trips through parse and serialize', () => {
    const source = '(Type:SAST or type:secret) AND severity:HIGH'
    const parsed = parse(source)
    expect(parsed.errors).toEqual([])
    expect(serialize(parsed.node as FilterNode)).toBe('(type:sast OR type:secret) AND severity:high')
  })
})

describe('toQueryString', () => {
  it('URL-encodes the serialized query', () => {
    const parsed = parse('(type:sast OR type:secret) AND severity:high')
    expect(parsed.errors).toEqual([])
    expect(toQueryString(parsed.node as FilterNode)).toBe('(type%3Asast%20OR%20type%3Asecret)%20AND%20severity%3Ahigh')
  })

  it('omits text nodes from the API query string', () => {
    const parsed = parse('some text type:sast OR more words severity:high')
    expect(parsed.errors).toEqual([])
    expect(toQueryString(parsed.node as FilterNode)).toBe('type%3Asast%20OR%20severity%3Ahigh')
  })

  it('toQueryString omits standalone text', () => {
    const parsed = parse('zlib')
    expect(parsed.errors).toEqual([])
    expect(toQueryString(parsed.node as FilterNode)).toBe('')
  })
})

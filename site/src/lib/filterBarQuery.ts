// The FilterBar's query core: tokenizing, validating, parsing and building
// the bar text. Pure functions, extracted from the component so the grammar
// is unit-testable (filterBarQuery.test.ts).
//
// The bar speaks two dialects:
//  - plain: space-separated `key:value` qualifiers (implicit AND) plus free
//    text — mapped onto the discrete filter model;
//  - advanced: the moment OR or parentheses appear, the query is boolean
//    structure the discrete model cannot express — it is validated here and
//    then executed verbatim server-side (the ADR-023 filterquery `q` param).

export interface FilterBarFilter {
  key: string
  label: string
  options: string[]
  multi?: boolean
  freeform?: boolean
  hidden?: boolean
  defaultValue?: string
}

export interface DisplaySegment {
  text: string
  className: string
}

export interface ValidationIssue {
  id: string
  parts: DisplaySegment[]
}

export interface ParsedQuery {
  filters: Record<string, string>
  searchText: string
  issues: ValidationIssue[]
  // Non-empty when the query uses OR or parentheses; the consumer sends it
  // verbatim as the server-side filterquery instead of discrete params.
  advancedQuery: string
  // True as soon as the text uses OR or parentheses, valid or not: the
  // discrete controls cannot represent it even while it has issues.
  booleanSyntax: boolean
}

export interface BarQueryChunk {
  text: string
  isWhitespace: boolean
}

export function isWhitespaceChar(char: string) {
  return /\s/.test(char)
}

export function isParenChar(char: string) {
  return char === '(' || char === ')'
}

const CONNECTIVES = new Set(['and', 'or'])

export function isConnectiveWord(word: string) {
  return CONNECTIVES.has(word.toLowerCase())
}

// findBarTokenEnd: every token — qualifier or plain word — ends at the first
// whitespace or parenthesis. The bar used to let a qualifier's value run
// across spaces until the next qualifier, which silently swallowed free text
// and boolean connectives into the value ("Invalid value 'suppressed and'").
// Whitespace-delimited is what every search bar trains people to expect;
// multi-word values are not supported.
export function findBarTokenEnd(query: string, start: number) {
  let end = start
  while (end < query.length && !isWhitespaceChar(query[end]) && !isParenChar(query[end])) {
    end += 1
  }
  return end
}

export function tokenizeBarQuery(query: string): BarQueryChunk[] {
  const chunks: BarQueryChunk[] = []
  let index = 0

  while (index < query.length) {
    if (isWhitespaceChar(query[index])) {
      const whitespaceStart = index
      while (index < query.length && isWhitespaceChar(query[index])) {
        index += 1
      }

      chunks.push({
        text: query.slice(whitespaceStart, index),
        isWhitespace: true,
      })
      continue
    }

    // Parentheses are always their own token, even glued to a word:
    // `(status:x` is a paren followed by a qualifier.
    if (isParenChar(query[index])) {
      chunks.push({ text: query[index], isWhitespace: false })
      index += 1
      continue
    }

    const tokenEnd = findBarTokenEnd(query, index)
    chunks.push({
      text: query.slice(index, tokenEnd),
      isWhitespace: false,
    })
    index = tokenEnd
  }

  return chunks
}

export function normalizeFilterFragment(value: string) {
  return value.trim().toLowerCase()
}

export function getCanonicalFilterOption(filter: FilterBarFilter, value: string) {
  const normalized = normalizeFilterFragment(value)
  if (normalized.length === 0) {
    return undefined
  }
  for (const option of filter.options) {
    if (normalizeFilterFragment(option) === normalized) {
      return option
    }
  }
  return undefined
}

export function isValidFilterValue(filter: FilterBarFilter, rawValue: string) {
  const trimmed = rawValue.trim()
  if (trimmed.length === 0) {
    return false
  }

  if (filter.freeform || filter.options.length === 0) {
    return true
  }

  return getCanonicalFilterOption(filter, rawValue) !== undefined
}

export function validateFilterValues(filter: FilterBarFilter, rawValue: string) {
  const values: string[] = []
  const issues: ValidationIssue[] = []

  if (!filter.multi) {
    const trimmed = rawValue.trim()
    if (trimmed.length === 0) {
      issues.push(createEmptyValueIssue(filter))
      return { values, issues }
    }

    if (filter.freeform) {
      values.push(trimmed)
      return { values, issues }
    }

    if (trimmed.includes(',')) {
      issues.push(createSingleValueIssue(filter))
      return { values, issues }
    }

    if (filter.options.length > 0) {
      const canonical = getCanonicalFilterOption(filter, rawValue)
      if (!canonical) {
        issues.push(createInvalidValueIssue(filter, trimmed))
        return { values, issues }
      }
      values.push(canonical)
      return { values, issues }
    }

    values.push(trimmed)
    return { values, issues }
  }

  const fragments = rawValue.split(',')
  for (const fragment of fragments) {
    const trimmed = fragment.trim()
    if (trimmed.length === 0) {
      issues.push(createEmptyValueIssue(filter))
      continue
    }

    if (filter.freeform) {
      values.push(trimmed)
      continue
    }

    if (filter.options.length > 0) {
      const canonical = getCanonicalFilterOption(filter, fragment)
      if (!canonical) {
        issues.push(createInvalidValueIssue(filter, trimmed))
        continue
      }
      values.push(canonical)
      continue
    }

    values.push(trimmed)
  }

  if (issues.length > 0) {
    return { values: [], issues }
  }

  return { values, issues }
}

function dedupe(values: string[]) {
  return Array.from(new Set(values))
}

function addValidationIssue(target: Map<string, ValidationIssue>, issue: ValidationIssue) {
  if (!target.has(issue.id)) {
    target.set(issue.id, issue)
  }
}

const HIGHLIGHT = 'font-medium text-amber-100'

// suggestionPart: a short "try …" tail so a message says how to fix itself.
function suggestionPart(values: string[]): DisplaySegment[] {
  if (values.length === 0) return []
  const shown = values.slice(0, 4).join(', ')
  return [{ text: ` — try ${shown}${values.length > 4 ? ', …' : ''}`, className: 'text-amber-200/70' }]
}

export function createUnknownFilterIssue(rawKey: string, knownKeys: string[] = []): ValidationIssue {
  return {
    id: `unknown-filter:${rawKey.toLowerCase()}`,
    parts: [
      { text: rawKey, className: HIGHLIGHT },
      { text: ' is not a filter', className: '' },
      ...suggestionPart(knownKeys.map(key => `${key}:`)),
    ],
  }
}

export function createEmptyValueIssue(filter: FilterBarFilter): ValidationIssue {
  return {
    id: `empty-value:${filter.key}`,
    parts: [
      { text: `${filter.key}:`, className: HIGHLIGHT },
      { text: ' needs a value', className: '' },
      ...suggestionPart(filter.freeform ? [] : filter.options),
    ],
  }
}

export function createInvalidValueIssue(filter: FilterBarFilter, value: string): ValidationIssue {
  return {
    id: `invalid-value:${filter.key}:${value.toLowerCase()}`,
    parts: [
      { text: value, className: HIGHLIGHT },
      { text: ' is not a valid ', className: '' },
      { text: filter.key, className: HIGHLIGHT },
      ...suggestionPart(filter.options),
    ],
  }
}

export function createSingleValueIssue(filter: FilterBarFilter): ValidationIssue {
  return {
    id: `single-value:${filter.key}`,
    parts: [
      { text: `${filter.key}:`, className: HIGHLIGHT },
      { text: ' takes one value — use OR to match several', className: '' },
    ],
  }
}

export function createUnbalancedParensIssue(): ValidationIssue {
  return {
    id: 'parens:unbalanced',
    parts: [
      { text: 'Unbalanced parentheses', className: HIGHLIGHT },
      { text: ' — every ( needs a matching )', className: '' },
    ],
  }
}

export function createDanglingConnectiveIssue(word: string): ValidationIssue {
  return {
    id: `connective:${word.toLowerCase()}`,
    parts: [
      { text: word.toUpperCase(), className: HIGHLIGHT },
      { text: ' must sit between two conditions', className: '' },
    ],
  }
}

export function parseBarQuery(query: string, filterDefs: FilterBarFilter[], searchable: boolean): ParsedQuery {
  const filterMap = new Map(filterDefs.map(filter => [filter.key.toLowerCase(), filter]))
  const filters: Record<string, string> = {}
  const searchTerms: string[] = []
  const issues = new Map<string, ValidationIssue>()
  const tokens = tokenizeBarQuery(query)
    .filter(chunk => !chunk.isWhitespace)
    .map(chunk => chunk.text)

  // OR and parentheses make the query "advanced": boolean structure the
  // discrete filter model cannot express, executed server-side as `q`.
  // A bare `and` is not — space-separated qualifiers already mean AND.
  let advanced = false
  let parenDepth = 0
  let unbalanced = false
  let previousToken = ''

  for (const token of tokens) {
    if (token === '(') {
      parenDepth += 1
      advanced = true
      previousToken = token
      continue
    }
    if (token === ')') {
      parenDepth -= 1
      if (parenDepth < 0) {
        unbalanced = true
      }
      advanced = true
      previousToken = token
      continue
    }
    if (isConnectiveWord(token)) {
      if (token.toLowerCase() === 'or') {
        advanced = true
      }
      if (previousToken === '' || previousToken === '(' || isConnectiveWord(previousToken)) {
        addValidationIssue(issues, createDanglingConnectiveIssue(token))
      }
      previousToken = token
      continue
    }
    previousToken = token

    const match = token.match(/^([A-Za-z0-9_-]+):(.*)$/)
    if (!match) {
      if (searchable && token.length > 0) {
        searchTerms.push(token)
      }
      continue
    }

    const rawKey = match[1]
    const rawValue = match[2]
    const filter = filterMap.get(rawKey.toLowerCase())

    if (!filter) {
      addValidationIssue(issues, createUnknownFilterIssue(rawKey, filterDefs.map(filter => filter.key)))
      continue
    }

    const validated = validateFilterValues(filter, rawValue)

    for (const issue of validated.issues) {
      addValidationIssue(issues, issue)
    }

    if (validated.issues.length === 0 && validated.values.length > 0) {
      filters[filter.key] = filter.multi ? dedupe(validated.values).join(',') : validated.values[0]
    }
  }

  if (parenDepth !== 0 || unbalanced) {
    addValidationIssue(issues, createUnbalancedParensIssue())
  }
  if (isConnectiveWord(previousToken) || previousToken === '(') {
    addValidationIssue(issues, createDanglingConnectiveIssue(previousToken))
  }

  for (const [key, filter] of filterMap) {
    if (filter.defaultValue && !(filter.key in filters)) {
      filters[key] = filter.defaultValue
    }
  }

  return {
    filters,
    searchText: searchable ? searchTerms.join(' ') : '',
    issues: [...issues.values()],
    advancedQuery: advanced && issues.size === 0 ? query.trim() : '',
    booleanSyntax: advanced,
  }
}

export function buildBarQuery(filterDefs: FilterBarFilter[], filters: Record<string, string>, freeText: string, searchable: boolean) {
  const tokens: string[] = []

  for (const filter of filterDefs) {
    const value = filters[filter.key]
    // A hidden filter surfaces in the bar only when it deviates from its
    // default: "status:detected" alone stays invisible, adding suppressed
    // makes the bar say so — otherwise dropdown selections were silent.
    if (filter.hidden && (!value || value === filter.defaultValue)) {
      continue
    }
    if (value) {
      tokens.push(`${filter.key}:${value}`)
    }
  }

  const trimmedSearch = searchable ? freeText.trim() : ''
  if (trimmedSearch.length > 0) {
    tokens.push(trimmedSearch)
  }

  return tokens.join(' ')
}

export interface CursorContext {
  token: string
  start: number
  end: number
}

// getCursorContext: the token under the cursor, bounded like every other
// token by whitespace or a parenthesis — `acceptance:)` is the qualifier
// `acceptance:` followed by a paren, not a qualifier whose value is `)`.
export function getCursorContext(text: string, cursor: number): CursorContext {
  const safeCursor = Math.max(0, Math.min(cursor, text.length))
  const leftToken = text.slice(0, safeCursor).match(/[^\s()]+$/)?.[0] ?? ''
  const rightToken = text.slice(safeCursor).match(/^[^\s()]+/)?.[0] ?? ''
  return {
    token: `${leftToken}${rightToken}`,
    start: safeCursor - leftToken.length,
    end: safeCursor + rightToken.length,
  }
}

const QUALIFIER_CLASS = 'text-gray-400'
const VALUE_CLASS = 'text-[#79c0ff]'
const WARNING_CLASS = 'text-[#d29922]'

function qualifierSegments(filter: FilterBarFilter | undefined, rawKey: string, rawValue: string): DisplaySegment[] {
  if (!filter) {
    return [
      { text: rawKey, className: WARNING_CLASS },
      { text: ':', className: WARNING_CLASS },
      ...(rawValue.length > 0 ? [{ text: rawValue, className: WARNING_CLASS }] : []),
    ]
  }

  const segments: DisplaySegment[] = [
    { text: filter.key, className: QUALIFIER_CLASS },
    { text: ':', className: QUALIFIER_CLASS },
  ]

  if (!filter.multi) {
    if (rawValue.length > 0) {
      segments.push({ text: rawValue, className: isValidFilterValue(filter, rawValue) ? VALUE_CLASS : WARNING_CLASS })
    }
    return segments
  }

  const fragments = rawValue.split(',')
  for (let index = 0; index < fragments.length; index += 1) {
    const fragment = fragments[index]
    if (index > 0) {
      const hasEmptyNeighbor = fragments[index - 1].trim().length === 0 || fragment.trim().length === 0
      segments.push({ text: ',', className: hasEmptyNeighbor ? WARNING_CLASS : QUALIFIER_CLASS })
    }
    if (fragment.length > 0) {
      segments.push({ text: fragment, className: isValidFilterValue(filter, fragment) ? VALUE_CLASS : WARNING_CLASS })
    }
  }
  return segments
}

// highlightBarQuery: the bar's syntax colouring, shared so a query reads the
// same wherever it is shown. Connectives purple, parens amber, valid values
// blue, anything the bar would reject amber.
export function highlightBarQuery(query: string, filterDefs: FilterBarFilter[]): DisplaySegment[] {
  const filterMap = new Map(filterDefs.map(filter => [filter.key.toLowerCase(), filter]))
  return tokenizeBarQuery(query).flatMap((chunk): DisplaySegment[] => {
    if (chunk.isWhitespace) return [{ text: chunk.text, className: '' }]
    if (isParenChar(chunk.text)) return [{ text: chunk.text, className: 'text-[#d29922]' }]
    if (isConnectiveWord(chunk.text)) return [{ text: chunk.text, className: 'text-[#d2a8ff]' }]
    const match = chunk.text.match(/^([A-Za-z0-9_-]+):(.*)$/)
    if (!match) return [{ text: chunk.text, className: 'text-gray-100' }]
    return qualifierSegments(filterMap.get(match[1].toLowerCase()), match[1], match[2])
  })
}

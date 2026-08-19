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
      issues.push(createEmptyValueIssue(filter.key))
      return { values, issues }
    }

    if (filter.freeform) {
      values.push(trimmed)
      return { values, issues }
    }

    if (filter.options.length > 0) {
      const canonical = getCanonicalFilterOption(filter, rawValue)
      if (!canonical) {
        issues.push(createInvalidValueIssue(filter.key, trimmed))
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
      issues.push(createEmptyValueIssue(filter.key))
      continue
    }

    if (filter.freeform) {
      values.push(trimmed)
      continue
    }

    if (filter.options.length > 0) {
      const canonical = getCanonicalFilterOption(filter, fragment)
      if (!canonical) {
        issues.push(createInvalidValueIssue(filter.key, trimmed))
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

export function createUnknownFilterIssue(rawKey: string): ValidationIssue {
  return {
    id: `unknown-filter:${rawKey.toLowerCase()}`,
    parts: [
      { text: 'Unknown filter ', className: 'text-[#f0c674]' },
      { text: rawKey, className: 'font-medium text-[#ffcc66]' },
    ],
  }
}

export function createEmptyValueIssue(key: string): ValidationIssue {
  return {
    id: `empty-value:${key}`,
    parts: [
      { text: 'Empty value for ', className: 'text-[#f0c674]' },
      { text: key, className: 'font-medium text-[#ffd38a]' },
    ],
  }
}

export function createInvalidValueIssue(key: string, value: string): ValidationIssue {
  return {
    id: `invalid-value:${key}:${value.toLowerCase()}`,
    parts: [
      { text: 'Invalid value ', className: 'text-[#f0c674]' },
      { text: value, className: 'font-medium text-[#ffd38a]' },
      { text: ' for ', className: 'text-[#f0c674]' },
      { text: key, className: 'font-medium text-[#ffcc66]' },
    ],
  }
}

export function createUnbalancedParensIssue(): ValidationIssue {
  return {
    id: 'parens:unbalanced',
    parts: [
      { text: 'Unbalanced parentheses', className: 'font-semibold' },
      { text: ' — every ( needs a matching )', className: '' },
    ],
  }
}

export function createDanglingConnectiveIssue(word: string): ValidationIssue {
  return {
    id: `connective:${word.toLowerCase()}`,
    parts: [
      { text: word, className: 'font-semibold' },
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
      addValidationIssue(issues, createUnknownFilterIssue(rawKey))
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

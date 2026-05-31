export type TokenType = 'QUALIFIER' | 'AND' | 'OR' | 'LPAREN' | 'RPAREN' | 'TEXT' | 'EOF'

export interface Token {
  type: TokenType
  value: string
  start: number
  end: number
}

export type FilterNode =
  | { type: 'qualifier'; key: string; value: string; negated?: boolean }
  | { type: 'and'; left: FilterNode; right: FilterNode }
  | { type: 'or'; left: FilterNode; right: FilterNode }
  | { type: 'group'; child: FilterNode }
  | { type: 'text'; value: string }

export interface ParseResult {
  node: FilterNode | null
  errors: ParseError[]
}

export interface ParseError {
  message: string
  start: number
  end: number
}

const PRIMARY_TOKENS = new Set<TokenType>(['QUALIFIER', 'TEXT', 'LPAREN'])
const maxDepth = 16

export function tokenize(input: string): Token[] {
  const tokens: Token[] = []
  let index = 0

  while (index < input.length) {
    const char = input[index]

    if (/\s/.test(char)) {
      index += 1
      continue
    }

    if (char === '(') {
      tokens.push({ type: 'LPAREN', value: char, start: index, end: index + 1 })
      index += 1
      continue
    }

    if (char === ')') {
      tokens.push({ type: 'RPAREN', value: char, start: index, end: index + 1 })
      index += 1
      continue
    }

    const start = index
    while (index < input.length && !/\s/.test(input[index]) && input[index] !== '(' && input[index] !== ')') {
      index += 1
    }

    const value = input.slice(start, index)
    const upper = value.toUpperCase()

    if (value.includes(':')) {
      tokens.push({ type: 'QUALIFIER', value, start, end: index })
      continue
    }

    if (upper === 'AND') {
      tokens.push({ type: 'AND', value, start, end: index })
      continue
    }

    if (upper === 'OR') {
      tokens.push({ type: 'OR', value, start, end: index })
      continue
    }

    tokens.push({ type: 'TEXT', value, start, end: index })
  }

  tokens.push({ type: 'EOF', value: '', start: input.length, end: input.length })
  return tokens
}

class Parser {
  private readonly tokens: Token[]

  private readonly errors: ParseError[] = []

  private position = 0

  constructor(input: string) {
    this.tokens = tokenize(input)
  }

  parse(): ParseResult {
    if (this.peek().type === 'EOF') {
      return { node: null, errors: [] }
    }

    const node = this.parseOr(0)

    while (this.peek().type !== 'EOF') {
      const token = this.peek()
      if (token.type === 'RPAREN') {
        this.errors.push({ message: 'Unmatched closing parenthesis', start: token.start, end: token.end })
      } else {
        this.errors.push({ message: `Unexpected token ${token.value || token.type}`, start: token.start, end: token.end })
      }
      this.consume()
    }

    return { node, errors: this.errors }
  }

  private parseOr(depth: number): FilterNode | null {
    let left = this.parseAnd(depth)

    for (; ;) {
      if (!this.match('OR')) {
        return left
      }

      const operator = this.previous()
      const right = this.parseAnd(depth)
      if (left === null || right === null) {
        this.errors.push({ message: 'OR must be followed by a filter expression', start: operator.start, end: operator.end })
        return left ?? right
      }

      left = { type: 'or', left, right }
    }
  }

  private parseAnd(depth: number): FilterNode | null {
    let left = this.parsePrimary(depth)

    for (; ;) {
      const next = this.peek()
      const explicitAnd = this.match('AND')
      const implicitAnd = !explicitAnd && PRIMARY_TOKENS.has(next.type)

      if (!explicitAnd && !implicitAnd) {
        return left
      }

      const operator = explicitAnd ? this.previous() : next
      const right = this.parsePrimary(depth)
      if (left === null || right === null) {
        this.errors.push({ message: 'AND must be followed by a filter expression', start: operator.start, end: operator.end })
        return left ?? right
      }

      left = { type: 'and', left, right }
    }
  }

  private parsePrimary(depth: number): FilterNode | null {
    const token = this.peek()

    if (this.match('QUALIFIER')) {
      const qualifier = this.previous().value
      const separator = qualifier.indexOf(':')
      const key = qualifier.slice(0, separator).trim().toLowerCase()
      const value = qualifier.slice(separator + 1).trim().toLowerCase()

      if (!key || !value) {
        this.errors.push({ message: 'Qualifier must use key:value syntax', start: token.start, end: token.end })
        return null
      }

      return { type: 'qualifier', key, value }
    }

    if (this.match('TEXT')) {
      const parts = [this.previous().value]

      while (this.peek().type === 'TEXT') {
        const nextText = this.consume()
        parts.push(nextText.value)
      }

      return { type: 'text', value: parts.join(' ') }
    }

    if (this.match('LPAREN')) {
      const open = this.previous()
      if (depth >= maxDepth) {
        this.errors.push({ message: `Filter nesting exceeds maximum depth of ${maxDepth}`, start: open.start, end: open.end })
        this.skipGroup()
        return null
      }
      if (this.match('RPAREN')) {
        const close = this.previous()
        this.errors.push({ message: 'Parentheses cannot be empty', start: open.start, end: close.end })
        return null
      }

      const child = this.parseOr(depth + 1)
      if (!this.match('RPAREN')) {
        this.errors.push({ message: 'Missing closing parenthesis', start: open.start, end: open.end })
        return child === null ? null : { type: 'group', child }
      }

      if (child === null) {
        return null
      }

      return { type: 'group', child }
    }

    if (this.match('RPAREN')) {
      this.errors.push({ message: 'Unmatched closing parenthesis', start: token.start, end: token.end })
      return null
    }

    return null
  }

  private peek(): Token {
    return this.tokens[this.position]
  }

  private previous(): Token {
    return this.tokens[this.position - 1]
  }

  private consume(): Token {
    const token = this.tokens[this.position]
    this.position += 1
    return token
  }

  private match(type: TokenType): boolean {
    if (this.peek().type !== type) {
      return false
    }
    this.position += 1
    return true
  }

  private skipGroup(): void {
    let depth = 1

    while (depth > 0 && this.peek().type !== 'EOF') {
      const token = this.consume()
      if (token.type === 'LPAREN') {
        depth += 1
      } else if (token.type === 'RPAREN') {
        depth -= 1
      }
    }
  }
}

export function parse(input: string): ParseResult {
  return new Parser(input).parse()
}

export function serialize(node: FilterNode): string {
  return serializeNode(node, 0)
}

export function toQueryString(node: FilterNode): string {
  return encodeURIComponent(serializeQueryNode(node, 0))
}

function serializeNode(node: FilterNode, parentPrecedence: number): string {
  switch (node.type) {
    case 'qualifier':
      return `${node.key}:${node.value}`
    case 'text':
      return node.value
    case 'group':
      return `(${serializeNode(node.child, 0)})`
    case 'and': {
      const value = `${serializeNode(node.left, 2)} AND ${serializeNode(node.right, 2)}`
      return parentPrecedence > 2 ? `(${value})` : value
    }
    case 'or': {
      const value = `${serializeNode(node.left, 1)} OR ${serializeNode(node.right, 1)}`
      return parentPrecedence > 1 ? `(${value})` : value
    }
  }
}

function serializeQueryNode(node: FilterNode, parentPrecedence: number): string {
  switch (node.type) {
    case 'qualifier':
      return `${node.key}:${node.value}`
    case 'text':
      return ''
    case 'group': {
      const child = serializeQueryNode(node.child, 0)
      return child ? `(${child})` : ''
    }
    case 'and': {
      const left = serializeQueryNode(node.left, 2)
      const right = serializeQueryNode(node.right, 2)
      return joinQueryParts(left, right, 'AND', parentPrecedence, 2)
    }
    case 'or': {
      const left = serializeQueryNode(node.left, 1)
      const right = serializeQueryNode(node.right, 1)
      return joinQueryParts(left, right, 'OR', parentPrecedence, 1)
    }
  }
}

function joinQueryParts(left: string, right: string, operator: 'AND' | 'OR', parentPrecedence: number, precedence: number): string {
  if (!left) {
    return right
  }

  if (!right) {
    return left
  }

  const value = `${left} ${operator} ${right}`
  return parentPrecedence > precedence ? `(${value})` : value
}

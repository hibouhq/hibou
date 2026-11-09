// Autolink references (ADR-053): the organisation's tracker prefixes turned
// into links wherever people write, plus bare URLs. Pure: the component
// renders the segments.

export interface Autolink {
  prefix: string
  url_template: string
  alphanumeric: boolean
}

export type TextSegment =
  | { kind: 'text'; text: string }
  | { kind: 'link'; text: string; href: string }

const URL_PATTERN = /https?:\/\/[^\s<>"')\]]+/g
const SAFE_HREF = /^https?:\/\//i

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * The reference matcher for a set of autolinks: longest prefix first so
 * "SEC-" never shadows "SECOPS-", case-insensitive, bounded so "ASEC-7" or
 * "SEC-7a" (numeric) do not match. Null when there is nothing to match.
 */
function referencePattern(autolinks: Autolink[]): RegExp | null {
  const usable = autolinks.filter(link => link.prefix && link.url_template.includes('<num>'))
  if (usable.length === 0) return null
  const sorted = [...usable].sort((a, b) => b.prefix.length - a.prefix.length)
  const alternatives = sorted.map((link) => {
    const body = link.alphanumeric ? '[A-Za-z0-9][A-Za-z0-9-]*?' : '[0-9]+'
    return `${escapeRegExp(link.prefix)}(${body})(?![A-Za-z0-9-])`
  })
  return new RegExp(`(?<![A-Za-z0-9/])(?:${alternatives.join('|')})`, 'gi')
}

function hrefFor(match: string, autolinks: Autolink[]): string | null {
  const lower = match.toLowerCase()
  const link = [...autolinks]
    .sort((a, b) => b.prefix.length - a.prefix.length)
    .find(entry => lower.startsWith(entry.prefix.toLowerCase()))
  if (!link) return null
  const number = match.slice(link.prefix.length)
  const href = link.url_template.replaceAll('<num>', encodeURIComponent(number))
  return SAFE_HREF.test(href) ? href : null
}

/** Splits text into plain and linked segments: URLs and tracker references. */
export function autolinkSegments(text: string, autolinks: Autolink[] = []): TextSegment[] {
  if (!text) return []
  const pattern = referencePattern(autolinks)
  const marks: { start: number; end: number; href: string }[] = []
  for (const match of text.matchAll(URL_PATTERN)) {
    marks.push({ start: match.index, end: match.index + match[0].length, href: match[0] })
  }
  if (pattern) {
    for (const match of text.matchAll(pattern)) {
      const start = match.index
      const end = start + match[0].length
      // A reference inside a URL is part of the URL.
      if (marks.some(mark => start >= mark.start && start < mark.end)) continue
      const href = hrefFor(match[0], autolinks)
      if (href) marks.push({ start, end, href })
    }
  }
  marks.sort((a, b) => a.start - b.start)
  const segments: TextSegment[] = []
  let cursor = 0
  for (const mark of marks) {
    if (mark.start < cursor) continue
    if (mark.start > cursor) segments.push({ kind: 'text', text: text.slice(cursor, mark.start) })
    segments.push({ kind: 'link', text: text.slice(mark.start, mark.end), href: mark.href })
    cursor = mark.end
  }
  if (cursor < text.length) segments.push({ kind: 'text', text: text.slice(cursor) })
  return segments
}

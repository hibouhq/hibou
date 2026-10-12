// Vue does not sanitize bound href values, so a `javascript:` or `data:` URL
// coming from an advisory, a scanner report or a forge would execute on click.
// Every data-bound href goes through these helpers: only absolute http(s) URLs
// survive.

/** True when url is an absolute http:// or https:// URL. */
export function isSafeUrl(url: string | null | undefined): boolean {
  const value = (url ?? '').trim()
  if (!/^https?:\/\//i.test(value)) return false
  try {
    const parsed = new URL(value)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:'
  } catch {
    return false
  }
}

/** The url when it is safe to bind to href, otherwise undefined (no link). */
export function safeHref(url: string | null | undefined): string | undefined {
  return isSafeUrl(url) ? (url ?? '').trim() : undefined
}

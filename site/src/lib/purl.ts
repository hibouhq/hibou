/**
 * Minimal Package URL (purl) parser.
 * Spec: pkg:type/namespace/name@version?qualifiers#subpath
 * We only need type (ecosystem), namespace, name, version.
 */
export interface ParsedPurl {
  type: string
  namespace: string
  name: string
  version: string
}

export function parsePurl(purl: string | undefined | null): ParsedPurl | null {
  if (!purl || !purl.startsWith('pkg:')) {
    return null
  }

  let rest = purl.slice('pkg:'.length)

  // Strip qualifiers (?...) and subpath (#...)
  const hashIndex = rest.indexOf('#')
  if (hashIndex !== -1) {
    rest = rest.slice(0, hashIndex)
  }
  const queryIndex = rest.indexOf('?')
  if (queryIndex !== -1) {
    rest = rest.slice(0, queryIndex)
  }

  const atIndex = rest.lastIndexOf('@')
  let version = ''
  if (atIndex !== -1) {
    version = decodeURIComponent(rest.slice(atIndex + 1))
    rest = rest.slice(0, atIndex)
  }

  const segments = rest.split('/').filter(Boolean)
  if (segments.length === 0) {
    return null
  }

  const type = segments[0].toLowerCase()
  const name = segments.length > 1 ? decodeURIComponent(segments[segments.length - 1]) : ''
  const namespace = segments.length > 2
    ? segments.slice(1, -1).map((segment) => decodeURIComponent(segment)).join('/')
    : ''

  return { type, namespace, name, version }
}

/**
 * Canonical ecosystem key for badge styling. Falls back to a normalized
 * lowercase token, then "unknown".
 */
export function ecosystemKey(ecosystem: string | undefined | null): string {
  const value = (ecosystem || '').trim().toLowerCase()
  if (!value || value === 'unknown') {
    return 'unknown'
  }

  const aliases: Record<string, string> = {
    'go': 'golang',
    'golang': 'golang',
    'npm': 'npm',
    'maven': 'maven',
    'pypi': 'pypi',
    'pip': 'pypi',
    'python': 'pypi',
    'nuget': 'nuget',
    'cargo': 'cargo',
    'crates': 'cargo',
    'gem': 'gem',
    'rubygems': 'gem',
    'deb': 'deb',
    'debian': 'deb',
    'rpm': 'rpm',
    'redhat': 'rpm',
    'ubuntu': 'deb',
    'oci': 'oci',
    'docker': 'oci',
    'container': 'oci',
  }

  return aliases[value] ?? value
}

/** Source/advisory-feed key for badge styling (trivy, nvd, ghsa, …). */
export function sourceKey(source: string | undefined | null): string {
  const value = (source || '').trim().toLowerCase().replace(/[\s_]+/g, '')
  return value || 'unknown'
}

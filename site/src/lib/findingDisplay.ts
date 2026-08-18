// One vocabulary for how a finding *looks*: severity colour, the kind badge,
// and the outbound links an identifier implies. The finding views each grew
// their own copy of these; new surfaces import from here instead.

export type FindingKind = 'dependency' | 'container' | 'sast' | 'dast' | 'secret' | 'malware' | 'fuzzing' | 'manual' | 'generic' | (string & {})

/** Normalizes the severity spellings scanners emit ("Moderate", "VERY_HIGH"). */
export function severityKey(severity: unknown): string {
  const value = String(severity ?? '').toLowerCase().replace(/[._ ]/g, '')
  if (value === 'critical' || value === 'veryhigh') return 'critical'
  if (value === 'high') return 'high'
  if (value === 'medium' || value === 'moderate') return 'medium'
  if (value === 'low') return 'low'
  return 'info'
}

const SEVERITY_CLASSES: Record<string, string> = {
  critical: 'bg-danger/15 text-danger',
  high: 'bg-orange-500/15 text-orange-300',
  medium: 'bg-amber-500/15 text-amber-300',
  low: 'bg-sky-500/15 text-sky-300',
  info: 'bg-surface-overlay text-gray-400',
}

export function severityBadgeClass(severity: unknown): string {
  return `rounded-full px-2 py-0.5 text-[11px] font-medium ${SEVERITY_CLASSES[severityKey(severity)]}`
}

const TYPE_CLASSES: Record<string, string> = {
  malware: 'bg-red-500/15 text-red-400',
  secret: 'bg-amber-500/15 text-amber-400',
  dependency: 'bg-blue-500/15 text-blue-400',
  sast: 'bg-purple-500/15 text-purple-400',
  dast: 'bg-cyan-500/15 text-cyan-400',
  fuzzing: 'bg-teal-500/15 text-teal-400',
  container: 'bg-slate-500/15 text-slate-400',
}

export function findingTypeBadgeClass(type: string): string {
  return `rounded-full px-2 py-0.5 text-[11px] font-medium ${TYPE_CLASSES[type] ?? 'bg-gray-500/15 text-gray-400'}`
}

/**
 * Groups the nine finding types into the four shapes that need genuinely
 * different detail views. A generic renderer for all of them would show a
 * component field to a SAST finding and a file path to a CVE.
 */
export function findingShape(type: string): 'component' | 'code' | 'secret' | 'generic' {
  switch (type) {
    case 'dependency':
    case 'container':
    case 'malware':
      return 'component'
    case 'sast':
    case 'dast':
    case 'fuzzing':
      return 'code'
    case 'secret':
      return 'secret'
    default:
      return 'generic'
  }
}

/** VEX describes the exploitability of a component in a product, nothing else. */
export function isComponentBacked(type: string | undefined): boolean {
  return type === 'dependency' || type === 'container'
}

/** Where to read the advisory an identifier names. */
export function advisoryUrl(id: string | undefined): string {
  const value = (id ?? '').trim()
  if (!value) return ''
  if (value.startsWith('GHSA-')) return `https://github.com/advisories/${value}`
  if (value.startsWith('CVE-')) return `https://nvd.nist.gov/vuln/detail/${value}`
  if (value.startsWith('GO-')) return `https://pkg.go.dev/vuln/${value}`
  if (/^[A-Z]+-\d/.test(value)) return `https://osv.dev/vulnerability/${value}`
  return ''
}

/** MITRE page for a CWE-1234 style identifier; empty when it is not one. */
export function cweUrl(cwe: string | undefined): string {
  const match = /CWE-(\d+)/i.exec(cwe ?? '')
  return match ? `https://cwe.mitre.org/data/definitions/${match[1]}.html` : ''
}

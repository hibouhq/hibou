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
  critical: 'bg-sev-critical/15 text-sev-critical',
  high: 'bg-sev-high/15 text-sev-high',
  medium: 'bg-sev-medium/15 text-sev-medium',
  low: 'bg-sev-low/15 text-sev-low',
  info: 'bg-sev-info/15 text-sev-info',
}

export function severityBadgeClass(severity: unknown): string {
  return `inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-medium ${SEVERITY_CLASSES[severityKey(severity)]}`
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

/**
 * Where to read the advisory an identifier names: the vendor's own page when
 * one is constructible from the id alone, osv.dev for the many namespaces OSV
 * hosts (ALSA, SUSE-SU, RLSA, PHSA, MGASA, CGA, MAL, PYSEC, CURL, …).
 * Namespace list mirrors ADVISORY_PATTERNS in SearchPalette.vue.
 */
export function advisoryUrl(id: string | undefined): string {
  const value = (id ?? '').trim()
  if (!value) return ''
  const upper = value.toUpperCase()
  if (/^EUVD-\d{4}-\d+$/.test(upper)) return `https://euvd.enisa.europa.eu/vulnerability/${upper}`
  if (upper.startsWith('EUVD-')) return ''
  if (upper.startsWith('CVE-')) return `https://nvd.nist.gov/vuln/detail/${value}`
  if (upper.startsWith('GHSA-')) return `https://github.com/advisories/${value}`
  if (upper.startsWith('GO-')) return `https://pkg.go.dev/vuln/${value}`
  if (upper.startsWith('RUSTSEC-')) return `https://rustsec.org/advisories/${value}.html`
  if (upper.startsWith('SNYK-')) return `https://security.snyk.io/vuln/${value}`
  if (/^RH(SA|BA|EA)-/.test(upper)) return `https://access.redhat.com/errata/${value}`
  if (upper.startsWith('USN-')) return `https://ubuntu.com/security/notices/${value}`
  if (/^(DSA|DLA)-/.test(upper)) return `https://security-tracker.debian.org/tracker/${value}`
  if (upper.startsWith('ELSA-')) return `https://linux.oracle.com/errata/${value}.html`
  // Amazon Linux 2 pages live under /AL2/ with the plain ALAS- prefix.
  if (upper.startsWith('ALAS2-')) return `https://alas.aws.amazon.com/AL2/${value.replace(/^ALAS2-/i, 'ALAS-')}.html`
  if (upper.startsWith('ALAS-')) return `https://alas.aws.amazon.com/${value}.html`
  if (upper.startsWith('GLSA-')) return `https://security.gentoo.org/glsa/${value.replace(/^GLSA-/i, '')}`
  if (upper.startsWith('FEDORA-')) return `https://bodhi.fedoraproject.org/updates/${value}`
  // Chainguard ids are GHSA-shaped (letter groups), so the digit-based
  // fallback below cannot be relied on for them.
  if (upper.startsWith('CGA-')) return `https://osv.dev/vulnerability/${value}`
  // Multi-segment prefixes (SUSE-SU-…, openSUSE-SU-…, UBUNTU-CVE-…) included.
  if (/^[A-Z]+(-[A-Z]+)*-\d/i.test(value)) return `https://osv.dev/vulnerability/${value}`
  return ''
}

/** MITRE page for a CWE-1234 style identifier; empty when it is not one. */
export function cweUrl(cwe: string | undefined): string {
  const match = /CWE-(\d+)/i.exec(cwe ?? '')
  return match ? `https://cwe.mitre.org/data/definitions/${match[1]}.html` : ''
}

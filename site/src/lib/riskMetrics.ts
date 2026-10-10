// Risk metrics display (ADR-038): CVSS bands, who rated what, EPSS.

import type { FindingRating } from '@/api/client'

export type CVSSBand = 'critical' | 'high' | 'medium' | 'low' | 'none'

/** FIRST's qualitative bands; hibou shows v2 scores in the same bands. */
export function cvssBand(score: number): CVSSBand {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'none'
}

const BAND_TEXT: Record<CVSSBand, string> = {
  critical: 'text-red-300',
  high: 'text-orange-300',
  medium: 'text-amber-300',
  low: 'text-sky-300',
  none: 'text-gray-400',
}

/** Text colour for a score or a severity word. */
export function bandTextClass(value: number | string | undefined): string {
  if (value === undefined || value === '') return 'text-gray-500'
  if (typeof value === 'number') return BAND_TEXT[cvssBand(value)]
  if (value === 'info') return BAND_TEXT.none
  if (value === 'unknown') return 'text-gray-400'
  return BAND_TEXT[value as CVSSBand] ?? 'text-gray-400'
}

const RATERS: Record<string, string> = {
  nvd: 'NVD',
  ghsa: 'GitHub',
  redhat: 'Red Hat',
  debian: 'Debian',
  ubuntu: 'Ubuntu',
  oracle: 'Oracle Linux',
  alma: 'AlmaLinux',
  rocky: 'Rocky Linux',
  amazon: 'Amazon Linux',
  azure: 'Azure Linux',
  'cbl-mariner': 'CBL-Mariner',
  photon: 'Photon OS',
  suse: 'SUSE',
  fedora: 'Fedora',
  'cisa-adp': 'CISA-ADP',
  pypa: 'PyPA',
  go: 'Go',
  rustsec: 'RustSec',
  julia: 'Julia',
  bitnami: 'Bitnami',
  bottlerocket: 'Bottlerocket',
  cve: 'CVE record',
}

/** The rater's display name; a CNA short name passes through as given. */
export function raterName(rater: string | undefined): string {
  if (!rater) return ''
  return RATERS[rater] ?? rater
}

/** "CVSS:3.1/AV:N/..." → "3.1"; a v2 vector has no prefix. */
export function cvssVersionLabel(version: string | undefined): string {
  return (version ?? '').replace(/^v/, '')
}

function metrics(vector: string): Map<string, string> {
  const out = new Map<string, string>()
  for (const part of vector.replace(/^\(|\)$/g, '').split('/')) {
    const [key, value] = part.split(':')
    if (key && value && key !== 'CVSS') out.set(key, value)
  }
  return out
}

/**
 * The metrics where `other` differs from `used`, written as other's values
 * ("AC:L"): why two raters land on different scores. Only comparable within
 * one CVSS version.
 */
export function vectorDifferences(used: FindingRating | undefined, other: FindingRating): string[] {
  if (!used?.vector || !other.vector || used.version !== other.version || used === other) return []
  const base = metrics(used.vector)
  const differences: string[] = []
  for (const [key, value] of metrics(other.vector)) {
    if (base.has(key) && base.get(key) !== value) differences.push(`${key}:${value}`)
  }
  return differences
}

/** 0.89398 → "89.4%"; tiny probabilities keep two significant digits. */
export function formatEPSS(score: number): string {
  const percent = score * 100
  return percent >= 1 ? `${percent.toFixed(1)}%` : `${percent.toPrecision(2)}%`
}

/** 0.998 → "99.8th". */
export function formatPercentile(percentile: number): string {
  const value = Math.floor(percentile * 1000) / 10
  const text = Number.isInteger(value) ? value.toFixed(0) : value.toFixed(1)
  const last = Math.floor(value) % 10
  const teen = Math.floor(value) % 100 >= 11 && Math.floor(value) % 100 <= 13
  const suffix = !Number.isInteger(value) || teen ? 'th' : last === 1 ? 'st' : last === 2 ? 'nd' : last === 3 ? 'rd' : 'th'
  return `${text}${suffix}`
}

/** One line per rater for the list's hover: "Red Hat: low 4.7 (label)". */
export function ratingsSummary(ratings: FindingRating[] | undefined): string {
  const byRater = new Map<string, FindingRating>()
  for (const rating of ratings ?? []) {
    const current = byRater.get(rating.rater)
    if (rating.used || !current || (!current.score && rating.score)) byRater.set(rating.rater, rating)
  }
  return [...byRater.values()]
    .map(rating => {
      const score = rating.score !== undefined ? ` ${rating.score.toFixed(1)}` : ''
      return `${rating.used ? '▸ ' : ''}${raterName(rating.rater)}: ${rating.severity}${score}`
    })
    .join('\n')
}

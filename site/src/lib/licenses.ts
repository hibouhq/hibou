// License comparison for the components diff. Extracted from CompareView so the
// rule below is testable: it is subtle enough that a regression here silently
// turns the "new licenses" panel into noise, and a noisy panel gets ignored.

/**
 * Splits an SPDX expression into the units whose obligations independently
 * apply.
 *
 * AND is conjunctive — `MPL-2.0 AND MIT` imposes both, so each operand is its
 * own unit and can be newly introduced on its own. OR is elective — with
 * `MIT OR GPL-3.0-only` a consumer picks one, so the expression stays whole
 * rather than reporting GPL as an introduced obligation nobody is under.
 *
 * This mirrors the backend's evaluation semantics (see internal/license).
 * Splitting is depth-aware, so `(MIT OR GPL-3.0-only) AND Apache-2.0` yields
 * the parenthesised choice and Apache-2.0, not four fragments.
 */
export function splitConjunctiveUnits(expression: string): string[] {
  const trimmed = stripOuterParens(expression.trim())
  if (!trimmed) return []

  const units: string[] = []
  let depth = 0
  let current = ''
  const tokens = trimmed.split(/\s+/)

  for (const token of tokens) {
    // A token may carry parens on either side, so count both before deciding
    // whether an AND at this position is top level.
    const opens = (token.match(/\(/g) ?? []).length
    const closes = (token.match(/\)/g) ?? []).length

    if (depth === 0 && token.toUpperCase() === 'AND') {
      if (current) units.push(current.trim())
      current = ''
      continue
    }
    current = current ? `${current} ${token}` : token
    depth += opens - closes
  }
  if (current) units.push(current.trim())

  // Re-split after unwrapping: "(MIT AND Apache-2.0) AND GPL-3.0-only" yields a
  // unit whose parens hid another top-level AND, and leaving it glued reports the
  // compound string as one newly-introduced license the base may already carry.
  return units.flatMap((unit) => {
    const unwrapped = stripOuterParens(unit)
    if (!unwrapped) return []
    if (unwrapped === unit) return [unwrapped]
    return splitConjunctiveUnits(unwrapped)
  })
}

function stripOuterParens(value: string): string {
  let result = value.trim()
  while (result.startsWith('(') && result.endsWith(')') && result.length > 2) {
    const inner = result.slice(1, -1).trim()
    // Only strip when the parens actually wrap the whole expression; for
    // "(A) AND (B)" the outer characters are not a matching pair.
    let depth = 0
    let wraps = true
    for (let i = 0; i < inner.length; i += 1) {
      if (inner[i] === '(') depth += 1
      else if (inner[i] === ')') depth -= 1
      if (depth < 0) {
        wraps = false
        break
      }
    }
    if (!wraps || depth !== 0) break
    result = inner
  }
  return result
}

export interface LicenseBearingComponent {
  licenses?: string[]
}

/**
 * The licenses this change introduces that the base snapshot did not have
 * anywhere — the reviewable event ("this PR brings in the first GPL-3.0
 * dependency").
 *
 * `baseLicenses` must be the WHOLE base snapshot's licenses, not just those of
 * removed components: reconstructing the base side from the diff alone reported
 * a license as new whenever an untouched dependency already carried it.
 *
 * Comparison is case-folded and unit-wise. Returns [label, count] pairs sorted
 * by count, where the label keeps the first spelling encountered.
 */
export function newLicensesIntroduced(
  baseLicenses: string[],
  headComponents: LicenseBearingComponent[],
): Array<[string, number]> {
  const base = new Set<string>()
  for (const expression of baseLicenses) {
    for (const unit of splitConjunctiveUnits(expression)) {
      base.add(unit.toLowerCase())
    }
  }

  const introduced = new Map<string, { label: string; count: number }>()
  for (const component of headComponents) {
    // One component must not count twice for the same license even if its SBOM
    // entry repeats it across expressions.
    const seen = new Set<string>()
    for (const expression of component.licenses ?? []) {
      for (const unit of splitConjunctiveUnits(expression)) {
        const key = unit.toLowerCase()
        if (base.has(key) || seen.has(key)) continue
        seen.add(key)
        const entry = introduced.get(key)
        if (entry) entry.count += 1
        else introduced.set(key, { label: unit, count: 1 })
      }
    }
  }

  return Array.from(introduced.values())
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
    .map((entry) => [entry.label, entry.count] as [string, number])
}

// The category taxonomy for display. Single source for both the org Licenses tab
// and the policy settings form — it was duplicated in three places, and a
// category added server-side would have silently rendered no checkbox.
//
// This is presentation only: it does not decide any component's category, which
// the API always supplies. The `LicenseCategory` union in api/client.ts still
// makes a server-side addition a type error here.
export const LICENSE_CATEGORY_ORDER = [
  'unknown',
  'source-available',
  'network-copyleft',
  'copyleft',
  'weak-copyleft',
  'permissive',
  'public-domain',
] as const

export type LicenseCategoryId = (typeof LICENSE_CATEGORY_ORDER)[number]

export const LICENSE_CATEGORY_LABELS: Record<LicenseCategoryId, string> = {
  'unknown': 'Unknown',
  'source-available': 'Source-available',
  'network-copyleft': 'Network copyleft',
  'copyleft': 'Copyleft',
  'weak-copyleft': 'Weak copyleft',
  'permissive': 'Permissive',
  'public-domain': 'Public domain',
}

// Plain-English obligations, so choosing a legal stance does not require knowing
// SPDX.
export const LICENSE_CATEGORY_MEANINGS: Record<LicenseCategoryId, string> = {
  'unknown': 'A license Hibou cannot classify — its obligations have not been established.',
  'source-available': 'Source you can read but not freely use: commercial or hosted use is restricted (BUSL-1.1, SSPL-1.0).',
  'network-copyleft': 'Offering the software over a network obliges you to publish your own source (AGPL-3.0).',
  'copyleft': 'Shipping a product that includes it obliges you to release that product under the same license (GPL-3.0).',
  'weak-copyleft': "Obligations stay with the library's own files; your surrounding code is unaffected (LGPL-3.0, MPL-2.0).",
  'permissive': 'Use it anywhere, keep the copyright notice (MIT, Apache-2.0, BSD).',
  'public-domain': 'No conditions to meet at all (CC0-1.0, Unlicense).',
}

export function licenseCategoryLabel(category: string): string {
  return LICENSE_CATEGORY_LABELS[category as LicenseCategoryId] ?? category
}

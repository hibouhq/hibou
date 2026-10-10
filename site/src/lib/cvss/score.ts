// CVSS parsing and scoring for every version (2.0, 3.0, 3.1, 4.0), the
// frontend twin of internal/cvss. Both must reproduce the same golden file
// (internal/cvss/testdata/v4-golden.json, scored by FIRST's own calculator),
// so a vector scores identically in the calculator and in stored data.
//
// v4.0 scoring is ported from FIRST's reference calculator
// (https://github.com/FIRSTdotorg/cvss-v4-calculator, cvss_score.js),
// keeping its order of floating-point operations.
// Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause (v4.0 algorithm and tables)

import { type CvssVersion, metricIndex } from './definitions'
import { V4_LOOKUP, V4_MAX_COMPOSED, V4_MAX_SEVERITY } from './v4Data'

export interface ParsedVector {
  version: CvssVersion
  /** Metrics in vector order, by abbreviation. */
  metrics: Map<string, string>
}

export type ParseResult = { ok: true; vector: ParsedVector } | { ok: false; error: string }

const PREFIX: Record<string, CvssVersion> = { '2.0': '2.0', '3.0': '3.0', '3.1': '3.1', '4.0': '4.0' }

/**
 * Reads any CVSS vector: "CVSS:4.0/AV:N/...", "CVSS:3.1/...", a bare or
 * parenthesised v2 vector. Required metrics must be present; every metric's
 * value must be one the version defines.
 */
export function parseVector(raw: string): ParseResult {
  let text = raw.trim().replace(/^\(/, '').replace(/\)$/, '')
  if (!text) return { ok: false, error: 'Empty vector' }
  let version: CvssVersion = '2.0'
  const parts = text.split('/')
  const head = /^CVSS:(\d\.\d)$/.exec(parts[0])
  if (head) {
    const known = PREFIX[head[1]]
    if (!known) return { ok: false, error: `Unsupported CVSS version ${head[1]}` }
    version = known
    parts.shift()
    text = parts.join('/')
  }
  const index = metricIndex(version)
  const metrics = new Map<string, string>()
  for (const part of parts) {
    const [key, value, extra] = part.split(':')
    if (!key || !value || extra !== undefined) return { ok: false, error: `Malformed metric "${part}"` }
    const metric = index.get(key)
    if (!metric) return { ok: false, error: `${key} is not a CVSS ${version} metric` }
    if (!metric.values.some(candidate => candidate.code === value)) return { ok: false, error: `${key}:${value} is not a valid value` }
    if (metrics.has(key)) return { ok: false, error: `${key} appears twice` }
    metrics.set(key, value)
  }
  for (const metric of index.values()) {
    if (metric.required && !metrics.has(metric.key)) return { ok: false, error: `Missing required metric ${metric.key} (${metric.name})` }
  }
  return { ok: true, vector: { version, metrics } }
}

/** Renders a vector in canonical order, dropping undefined optional metrics. */
export function formatVector(version: CvssVersion, metrics: Map<string, string>): string {
  const parts: string[] = []
  for (const metric of metricIndex(version).values()) {
    const value = metrics.get(metric.key)
    if (value === undefined || value === 'X' || value === 'ND') continue
    parts.push(`${metric.key}:${value}`)
  }
  return version === '2.0' ? parts.join('/') : [`CVSS:${version}`, ...parts].join('/')
}

/** The vector's score: base score for v2/v3, CVSS-B/BT/BE/BTE for v4.0. */
export function scoreVector(vector: ParsedVector): number {
  switch (vector.version) {
    case '2.0': return v2Score(vector.metrics)
    case '3.0': return v3Score(vector.metrics, roundUp30)
    case '3.1': return v3Score(vector.metrics, roundUp31)
    case '4.0': return v4Score(vector.metrics)
  }
}

export type CvssSeverity = 'none' | 'low' | 'medium' | 'high' | 'critical'

/** FIRST's qualitative rating (v3 and v4; hibou shows v2 the same way). */
export function severityOf(score: number): CvssSeverity {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'none'
}

// ---------------------------------------------------------------- v2

const V2_AV: Record<string, number> = { L: 0.395, A: 0.646, N: 1.0 }
const V2_AC: Record<string, number> = { H: 0.35, M: 0.61, L: 0.71 }
const V2_AU: Record<string, number> = { M: 0.45, S: 0.56, N: 0.704 }
const V2_CIA: Record<string, number> = { N: 0, P: 0.275, C: 0.66 }

function v2Score(m: Map<string, string>): number {
  const impact = 10.41 * (1 - (1 - V2_CIA[m.get('C')!]) * (1 - V2_CIA[m.get('I')!]) * (1 - V2_CIA[m.get('A')!]))
  const exploitability = 20 * V2_AV[m.get('AV')!] * V2_AC[m.get('AC')!] * V2_AU[m.get('Au')!]
  if (impact === 0) return 0
  return Math.round((0.6 * impact + 0.4 * exploitability - 1.5) * 1.176 * 10) / 10
}

// ---------------------------------------------------------------- v3.x

const V3_AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const V3_AC: Record<string, number> = { L: 0.77, H: 0.44 }
const V3_PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 }
const V3_PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 }
const V3_UI: Record<string, number> = { N: 0.85, R: 0.62 }
const V3_CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 }

/** CVSS v3.1 Roundup (specification Appendix A). */
function roundUp31(value: number): number {
  const scaled = Math.round(value * 100000)
  if (scaled % 10000 === 0) return scaled / 100000
  return (Math.floor(scaled / 10000) + 1) / 10
}

function roundUp30(value: number): number {
  return Math.ceil(value * 10) / 10
}

function v3Score(m: Map<string, string>, roundUp: (value: number) => number): number {
  const changed = m.get('S') === 'C'
  const iss = 1 - (1 - V3_CIA[m.get('C')!]) * (1 - V3_CIA[m.get('I')!]) * (1 - V3_CIA[m.get('A')!])
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss
  const pr = (changed ? V3_PR_C : V3_PR_U)[m.get('PR')!]
  const exploitability = 8.22 * V3_AV[m.get('AV')!] * V3_AC[m.get('AC')!] * pr * V3_UI[m.get('UI')!]
  if (impact <= 0) return 0
  return changed ? roundUp(Math.min(1.08 * (impact + exploitability), 10)) : roundUp(Math.min(impact + exploitability, 10))
}

// ---------------------------------------------------------------- v4.0

const LEVELS: Record<string, Record<string, number>> = {
  AV: { N: 0.0, A: 0.1, L: 0.2, P: 0.3 },
  PR: { N: 0.0, L: 0.1, H: 0.2 },
  UI: { N: 0.0, P: 0.1, A: 0.2 },
  AC: { L: 0.0, H: 0.1 },
  AT: { N: 0.0, P: 0.1 },
  VC: { H: 0.0, L: 0.1, N: 0.2 },
  VI: { H: 0.0, L: 0.1, N: 0.2 },
  VA: { H: 0.0, L: 0.1, N: 0.2 },
  SC: { H: 0.1, L: 0.2, N: 0.3 },
  SI: { S: 0.0, H: 0.1, L: 0.2, N: 0.3 },
  SA: { S: 0.0, H: 0.1, L: 0.2, N: 0.3 },
  CR: { H: 0.0, M: 0.1, L: 0.2 },
  IR: { H: 0.0, M: 0.1, L: 0.2 },
  AR: { H: 0.0, M: 0.1, L: 0.2 },
}
const DISTANCE_ORDER = ['AV', 'PR', 'UI', 'AC', 'AT', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA', 'CR', 'IR', 'AR'] as const

/** Effective value: E/CR/IR/AR default to worst case, M* overrides base. */
function effective(m: Map<string, string>, metric: string): string {
  const selected = m.get(metric) ?? 'X'
  if (metric === 'E' && selected === 'X') return 'A'
  if ((metric === 'CR' || metric === 'IR' || metric === 'AR') && selected === 'X') return 'H'
  const modified = m.get(`M${metric}`)
  if (modified !== undefined && modified !== 'X') return modified
  return selected
}

function macroVector(m: Map<string, string>): string {
  const v = (metric: string) => effective(m, metric)
  let eq1: number
  if (v('AV') === 'N' && v('PR') === 'N' && v('UI') === 'N') eq1 = 0
  else if ((v('AV') === 'N' || v('PR') === 'N' || v('UI') === 'N') && v('AV') !== 'P') eq1 = 1
  else eq1 = 2
  const eq2 = v('AC') === 'L' && v('AT') === 'N' ? 0 : 1
  let eq3: number
  if (v('VC') === 'H' && v('VI') === 'H') eq3 = 0
  else if (v('VC') === 'H' || v('VI') === 'H' || v('VA') === 'H') eq3 = 1
  else eq3 = 2
  let eq4: number
  if (v('MSI') === 'S' || v('MSA') === 'S') eq4 = 0
  else if (v('SC') === 'H' || v('SI') === 'H' || v('SA') === 'H') eq4 = 1
  else eq4 = 2
  const eq5 = ({ A: 0, P: 1, U: 2 } as Record<string, number>)[v('E')]
  const eq6 = (v('CR') === 'H' && v('VC') === 'H') || (v('IR') === 'H' && v('VI') === 'H') || (v('AR') === 'H' && v('VA') === 'H') ? 0 : 1
  return `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`
}

const lookup = (macro: string): number => V4_LOOKUP[macro] ?? Number.NaN

function maxVectorMetrics(raw: string): Map<string, string> {
  const out = new Map<string, string>()
  for (const part of raw.split('/')) {
    const [key, value] = part.split(':')
    if (key && value) out.set(key, value)
  }
  return out
}

type EQ1Key = keyof typeof V4_MAX_COMPOSED.eq1
type EQ3Key = keyof typeof V4_MAX_COMPOSED.eq3

function v4Score(m: Map<string, string>): number {
  if (['VC', 'VI', 'VA', 'SC', 'SI', 'SA'].every(metric => effective(m, metric) === 'N')) return 0.0

  const macro = macroVector(m)
  let value = lookup(macro)
  const [eq1, eq2, eq3, eq4, eq5, eq6] = macro.split('').map(Number)
  const at = (...levels: number[]) => levels.join('')

  const scoreEQ1Lower = lookup(at(eq1 + 1, eq2, eq3, eq4, eq5, eq6))
  const scoreEQ2Lower = lookup(at(eq1, eq2 + 1, eq3, eq4, eq5, eq6))
  let scoreEQ3EQ6Lower: number
  if ((eq3 === 1 && eq6 === 1) || (eq3 === 0 && eq6 === 1)) {
    scoreEQ3EQ6Lower = lookup(at(eq1, eq2, eq3 + 1, eq4, eq5, eq6))
  } else if (eq3 === 1 && eq6 === 0) {
    scoreEQ3EQ6Lower = lookup(at(eq1, eq2, eq3, eq4, eq5, eq6 + 1))
  } else if (eq3 === 0 && eq6 === 0) {
    const left = lookup(at(eq1, eq2, eq3, eq4, eq5, eq6 + 1))
    const right = lookup(at(eq1, eq2, eq3 + 1, eq4, eq5, eq6))
    scoreEQ3EQ6Lower = left > right ? left : right
  } else {
    scoreEQ3EQ6Lower = lookup(at(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1))
  }
  const scoreEQ4Lower = lookup(at(eq1, eq2, eq3, eq4 + 1, eq5, eq6))
  const scoreEQ5Lower = lookup(at(eq1, eq2, eq3, eq4, eq5 + 1, eq6))

  const composed = V4_MAX_COMPOSED
  const eq3Maxes = (composed.eq3[String(eq3) as EQ3Key] as Record<string, readonly string[]>)[String(eq6)]
  const maxVectors: string[] = []
  for (const a of composed.eq1[String(eq1) as EQ1Key]) {
    for (const b of composed.eq2[String(eq2) as keyof typeof composed.eq2]) {
      for (const c of eq3Maxes) {
        for (const d of composed.eq4[String(eq4) as keyof typeof composed.eq4]) {
          for (const e of composed.eq5[String(eq5) as keyof typeof composed.eq5]) maxVectors.push(a + b + c + d + e)
        }
      }
    }
  }

  // The first highest vector the scored one does not exceed; as in the
  // reference, the last one's distances stand if none fits.
  const distance: Record<string, number> = {}
  for (const raw of maxVectors) {
    const max = maxVectorMetrics(raw)
    for (const metric of DISTANCE_ORDER) {
      distance[metric] = LEVELS[metric][effective(m, metric)] - LEVELS[metric][max.get(metric)!]
    }
    if (DISTANCE_ORDER.some(metric => distance[metric] < 0)) continue
    break
  }

  const currentEQ1 = distance.AV + distance.PR + distance.UI
  const currentEQ2 = distance.AC + distance.AT
  const currentEQ3EQ6 = distance.VC + distance.VI + distance.VA + distance.CR + distance.IR + distance.AR
  const currentEQ4 = distance.SC + distance.SI + distance.SA

  const step = 0.1
  const availableEQ1 = value - scoreEQ1Lower
  const availableEQ2 = value - scoreEQ2Lower
  const availableEQ3EQ6 = value - scoreEQ3EQ6Lower
  const availableEQ4 = value - scoreEQ4Lower
  const availableEQ5 = value - scoreEQ5Lower

  const severity = V4_MAX_SEVERITY
  const maxSeverityEQ1 = severity.eq1[String(eq1) as keyof typeof severity.eq1] * step
  const maxSeverityEQ2 = severity.eq2[String(eq2) as keyof typeof severity.eq2] * step
  const maxSeverityEQ3EQ6 = (severity.eq3eq6[String(eq3) as keyof typeof severity.eq3eq6] as Record<string, number>)[String(eq6)] * step
  const maxSeverityEQ4 = severity.eq4[String(eq4) as keyof typeof severity.eq4] * step

  let existing = 0
  let normalizedEQ1 = 0
  let normalizedEQ2 = 0
  let normalizedEQ3EQ6 = 0
  let normalizedEQ4 = 0
  let normalizedEQ5 = 0
  if (!Number.isNaN(availableEQ1)) { existing++; normalizedEQ1 = availableEQ1 * (currentEQ1 / maxSeverityEQ1) }
  if (!Number.isNaN(availableEQ2)) { existing++; normalizedEQ2 = availableEQ2 * (currentEQ2 / maxSeverityEQ2) }
  if (!Number.isNaN(availableEQ3EQ6)) { existing++; normalizedEQ3EQ6 = availableEQ3EQ6 * (currentEQ3EQ6 / maxSeverityEQ3EQ6) }
  if (!Number.isNaN(availableEQ4)) { existing++; normalizedEQ4 = availableEQ4 * (currentEQ4 / maxSeverityEQ4) }
  if (!Number.isNaN(availableEQ5)) { existing++; normalizedEQ5 = availableEQ5 * 0 }

  const meanDistance = existing === 0 ? 0 : (normalizedEQ1 + normalizedEQ2 + normalizedEQ3EQ6 + normalizedEQ4 + normalizedEQ5) / existing
  value -= meanDistance
  if (value < 0) value = 0.0
  if (value > 10) value = 10.0
  return Math.round(value * 10) / 10
}

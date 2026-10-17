// ADR-025 anomaly rule, computed client-side from the stats payload so the
// thresholds can move without a migration.

import type { InstanceJobBaseline, InstanceJobStatsBucket } from '@/api/client'

const KIND_LABELS: Record<string, string> = {
  secret_scan: 'Secret scans',
  dep_extraction: 'Dependency extraction',
  artifact_processing: 'Artifact processing',
  advisory_scan: 'Advisory scans',
}

// New job kinds render with their raw name until given a label here.
export function jobKindLabel(kind: string) {
  return KIND_LABELS[kind] ?? kind
}

export interface KindLatency {
  samples: number
  p50Duration: number
  p95Duration: number
  p50Wait: number
  p95Wait: number
}

export interface KindVerdict {
  kind: string
  /** True when the window has enough samples AND a baseline exists. */
  comparable: boolean
  degraded: boolean
  reasons: string[]
  current: KindLatency
  baseline?: InstanceJobBaseline
}

const MIN_SAMPLES = 5
const P50_FACTOR = 1.5
const P95_FACTOR = 2

// The window-wide percentile is not recoverable from per-bucket percentiles,
// so we estimate it as the sample-weighted median of the bucket values. Good
// enough for a badge; the per-bucket chart shows the real shape.
function weightedMedian(pairs: { value: number, weight: number }[]) {
  const rows = pairs.filter(p => p.weight > 0).sort((a, b) => a.value - b.value)
  const total = rows.reduce((sum, p) => sum + p.weight, 0)
  if (total === 0) {
    return 0
  }
  let seen = 0
  for (const row of rows) {
    seen += row.weight
    if (seen >= total / 2) {
      return row.value
    }
  }
  return rows[rows.length - 1].value
}

export function currentLatency(buckets: InstanceJobStatsBucket[]): KindLatency {
  const weights = buckets.map(b => ({ bucket: b, weight: b.completed + b.failed }))
  return {
    samples: weights.reduce((sum, w) => sum + w.weight, 0),
    p50Duration: weightedMedian(weights.map(w => ({ value: w.bucket.p50_duration_seconds, weight: w.weight }))),
    p95Duration: weightedMedian(weights.map(w => ({ value: w.bucket.p95_duration_seconds, weight: w.weight }))),
    p50Wait: weightedMedian(weights.map(w => ({ value: w.bucket.p50_wait_seconds, weight: w.weight }))),
    p95Wait: weightedMedian(weights.map(w => ({ value: w.bucket.p95_wait_seconds, weight: w.weight }))),
  }
}

// Degraded when the current window's p50 exceeds 1.5× the trailing-7-day
// baseline p50, or its p95 exceeds 2× the baseline p95 — for run duration or
// queue wait — with at least 5 samples on each side.
export function computeKindVerdict(
  kind: string,
  buckets: InstanceJobStatsBucket[],
  baseline: InstanceJobBaseline | undefined,
): KindVerdict {
  const current = currentLatency(buckets)
  const comparable = current.samples >= MIN_SAMPLES && (baseline?.samples ?? 0) >= MIN_SAMPLES
  const reasons: string[] = []

  if (comparable && baseline) {
    const checks: { name: string, current: number, base: number, factor: number }[] = [
      { name: 'run time p50', current: current.p50Duration, base: baseline.p50_duration_seconds, factor: P50_FACTOR },
      { name: 'run time p95', current: current.p95Duration, base: baseline.p95_duration_seconds, factor: P95_FACTOR },
      { name: 'queue wait p50', current: current.p50Wait, base: baseline.p50_wait_seconds, factor: P50_FACTOR },
      { name: 'queue wait p95', current: current.p95Wait, base: baseline.p95_wait_seconds, factor: P95_FACTOR },
    ]
    for (const check of checks) {
      if (check.base > 0 && check.current > check.base * check.factor) {
        reasons.push(check.name)
      }
    }
  }

  return { kind, comparable, degraded: reasons.length > 0, reasons, current, baseline }
}

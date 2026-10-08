import type { TrendPoint } from '@/api/client'

export type InsightMetric = 'vulnerabilities' | 'findings'

export interface InsightPoint extends TrendPoint {
  timestamp: number
  vulnerabilities_total: number
  findings_total: number
}

function count(value: number | null | undefined): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error('Observation counts are unavailable or invalid. No trend can be inferred.')
  }
  return value
}

export function normalizeTrendPoints(points: TrendPoint[]): InsightPoint[] {
  return points
    .map((point) => ({
      ...point,
      timestamp: Date.parse(point.date),
      components_total: count(point.components_total),
      vulnerabilities_total: count(point.vulns_critical) + count(point.vulns_high) + count(point.vulns_medium) + count(point.vulns_low) + count(point.vulns_info),
      findings_total: count(point.findings_critical) + count(point.findings_high) + count(point.findings_medium) + count(point.findings_low) + count(point.findings_info),
    }))
    .filter((point) => Number.isFinite(point.timestamp))
    .sort((left, right) => left.timestamp - right.timestamp)
}

export function trendBounds(points: InsightPoint[]): { start: Date; end: Date } | null {
  if (points.length === 0) return null
  return {
    start: new Date(points[0].timestamp),
    end: new Date(points[points.length - 1].timestamp),
  }
}

export function countForMetric(point: InsightPoint, metric: InsightMetric): number {
  return metric === 'vulnerabilities' ? point.vulnerabilities_total : point.findings_total
}
// Display logic for the known-exploited catalogs (ADR-032). The UI speaks one
// concept — "actively exploited" — and names catalogs only as provenance, so
// the mapping from source keys to human names lives here, next to the
// freshness verdict the health cards render.

import type { KEVSourceHealth } from '@/api/client'

const SOURCE_LABELS: Record<string, string> = {
  cisa: 'CISA KEV',
  euvd: 'ENISA EUVD',
}

/** Human name for a catalog source key; unknown sources show uppercased. */
export function kevSourceLabel(source: string): string {
  return SOURCE_LABELS[source] ?? source.toUpperCase()
}

export type KevSyncTone = 'ok' | 'stale' | 'failing'

/**
 * Freshness verdict for one catalog's card. Failing beats stale: an error is
 * actionable now, staleness is a question. The stale threshold is four missed
 * passes at the CONFIGURED interval (the backend reports it), so an operator
 * who syncs every 48h is not shown amber half of every healthy cycle; when the
 * interval is unknown the default 6h cadence is assumed (threshold 24h).
 */
export function kevSyncTone(source: KEVSourceHealth, intervalSeconds?: number, now: number = Date.now()): KevSyncTone {
  if (source.error) return 'failing'
  if (!source.at) return 'stale'
  const interval = intervalSeconds && intervalSeconds > 0 ? intervalSeconds : 6 * 3600
  return now - new Date(source.at).getTime() > 4 * interval * 1000 ? 'stale' : 'ok'
}

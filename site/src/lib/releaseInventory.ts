import type { ReleaseInventory, ReleaseInventorySummary } from '@/api/client'

export function canExtractReleaseInventory(inventory?: ReleaseInventory, enabled = false): boolean {
  return enabled && inventory?.can_extract === true && !inventory.has_inventory
    && (inventory.state === 'missing' || inventory.state === 'failed')
}

export function canBackfillReleases(summary?: ReleaseInventorySummary | null): boolean {
  return summary?.enabled === true && summary.eligible > 0
}

export function releaseInventoryPending(summary?: ReleaseInventorySummary | null): boolean {
  return !!summary && summary.queued + summary.processing + summary.matching > 0
}

export function releaseInventoryLabel(inventory?: ReleaseInventory): string {
  if (!inventory) return 'Inventory status unavailable'
  const labels: Record<ReleaseInventory['state'], string> = {
    missing: 'Dependency inventory missing',
    queued: 'Dependency extraction queued',
    processing: 'Extracting dependencies',
    matching: 'Matching release dependencies against advisories',
    complete: 'Dependency inventory available',
    partial: 'Partial dependency inventory',
    unsupported: 'No inventory produced — see extraction details',
    failed: 'Dependency extraction failed',
    unavailable: 'No valid release tag available',
  }
  return labels[inventory.state]
}

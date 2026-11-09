import { describe, expect, it } from 'vitest'
import type { ReleaseInventory, ReleaseInventorySummary } from '@/api/client'
import { canBackfillReleases, canExtractReleaseInventory, releaseInventoryLabel, releaseInventoryPending } from './releaseInventory'
import { needsDependencyExtraction } from './sca'

const summary: ReleaseInventorySummary = { enabled: true, eligible: 1, queued: 0, processing: 0, matching: 0, failed: 0, inventoried: 0, unsupported: 0 }

describe('release inventory action visibility', () => {
  it('offers extraction only for missing inventory or a terminal failure', () => {
    for (const state of ['missing', 'failed'] as const) {
      expect(canExtractReleaseInventory({ state, can_extract: true, has_inventory: false }, true)).toBe(true)
    }
  })

  it.each(['queued', 'processing', 'matching', 'complete', 'partial', 'unsupported', 'unavailable'] as const)('hides the action for %s', state => {
    expect(canExtractReleaseInventory({ state, can_extract: false, has_inventory: false }, true)).toBe(false)
  })

  it('hides covered inventories even if a stale eligibility flag says otherwise', () => {
    expect(canExtractReleaseInventory({ state: 'missing', can_extract: true, has_inventory: true }, true)).toBe(false)
  })

  it('does not show actions while status is unavailable or extraction is disabled', () => {
    expect(canExtractReleaseInventory(undefined, true)).toBe(false)
    expect(canExtractReleaseInventory({ state: 'missing', can_extract: true, has_inventory: false }, false)).toBe(false)
    expect(canBackfillReleases(undefined)).toBe(false)
    expect(canBackfillReleases({ ...summary, enabled: false })).toBe(false)
  })

  it('hides bulk backfill when no eligible release remains, including while everything is queued', () => {
    expect(canBackfillReleases(summary)).toBe(true)
    expect(canBackfillReleases({ ...summary, eligible: 0, queued: 100 })).toBe(false)
    expect(releaseInventoryPending({ ...summary, eligible: 0, queued: 100 })).toBe(true)
    expect(releaseInventoryPending({ ...summary, eligible: 0, processing: 1 })).toBe(true)
    expect(releaseInventoryPending({ ...summary, eligible: 0, matching: 1 })).toBe(true)
    expect(releaseInventoryPending(summary)).toBe(false)
  })

  it('keeps unsupported and failure outcomes distinct without claiming assessment', () => {
    for (const state of ['unsupported', 'failed', 'missing', 'processing'] as const) {
      const inventory: ReleaseInventory = { state, can_extract: false, has_inventory: false }
      expect(releaseInventoryLabel(inventory)).not.toContain('No open findings')
    }
    expect(releaseInventoryLabel()).toBe('Inventory status unavailable')
  })
})

describe('repository dependency extraction visibility', () => {
  it('requires explicit evidence that inventory is missing', () => {
    expect(needsDependencyExtraction(undefined)).toBe(false)
    expect(needsDependencyExtraction({ state: 'not_assessed', enabled: true, on_push: true })).toBe(false)
    expect(needsDependencyExtraction({ state: 'not_assessed', enabled: true, on_push: true, has_inventory: false })).toBe(true)
  })

  it.each(['complete', 'partial', 'unsupported', 'queued', 'extracting', 'matching', 'disabled'] as const)('hides the dependency button for %s', state => {
    expect(needsDependencyExtraction({ state, enabled: true, on_push: true, has_inventory: false })).toBe(false)
  })

  it('does not offer extraction for advisory failures when inventory already exists', () => {
    expect(needsDependencyExtraction({ state: 'failed', enabled: true, on_push: true, has_inventory: true })).toBe(false)
    expect(needsDependencyExtraction({ state: 'failed', enabled: true, on_push: true, has_inventory: false })).toBe(true)
  })
})

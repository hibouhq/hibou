import { describe, expect, it } from 'vitest'
import { ApiError, type ScaCoverage } from '@/api/client'
import { MAX_SCA_SELECTION, canEnableSca, hasInventory, inventoryKnownCount, inventorySource, inventorySourceTitle, needsDependencyExtraction, scaAction, scaAssessed, scaErrorMessage, scaKnownCount, scaLabel, scaPending, scaResultCoverage, scaSelectionValid, scaState } from './sca'

function coverage(state: ScaCoverage['state']): ScaCoverage {
  return { state, enabled: true, on_push: true }
}

describe('SCA coverage', () => {
  it('does not turn absent legacy evidence into a healthy zero', () => {
    expect(scaState()).toBe('unknown')
    expect(scaLabel()).toBe('Status unavailable')
    expect(scaAssessed()).toBe(false)
    expect(scaLabel(undefined, false)).toBe('Status unavailable')
  })

  it('keeps partial known nonzero counts and never gives unassessed inventory a clean zero', () => {
    expect(scaKnownCount(7, coverage('partial'))).toBe(7)
    expect(scaKnownCount(7, coverage('failed'))).toBe(7)
    expect(scaKnownCount(0, coverage('partial'))).toBe(0)
    expect(scaKnownCount(0, coverage('complete'))).toBe(0)
    for (const state of ['not_monitored', 'not_assessed', 'queued', 'extracting', 'matching', 'unsupported', 'failed', 'disabled'] as const) {
      expect(scaKnownCount(0, coverage(state))).toBe('Not assessed')
    }
    expect(scaKnownCount(0)).toBe('Not reported')
  })

  it.each(['queued', 'extracting', 'matching'] as const)('polls only pending %s', state => {
    expect(scaPending(coverage(state))).toBe(true)
    expect(scaAssessed(coverage(state))).toBe(false)
    expect(canEnableSca('active', coverage(state))).toBe(false)
  })

  it.each(['not_monitored', 'not_assessed', 'complete', 'partial', 'unsupported', 'failed', 'disabled'] as const)('does not poll terminal %s', state => {
    expect(scaPending(coverage(state))).toBe(false)
  })

  it('counts partial known results without claiming complete coverage', () => {
    expect(scaAssessed(coverage('complete'))).toBe(true)
    expect(scaAssessed(coverage('partial'))).toBe(true)
    expect(scaLabel(coverage('partial'))).toBe('Partial analysis')
  })

  it('distinguishes unsupported inventory, advisory failure and disabled extraction', () => {
    expect(scaLabel(coverage('unsupported'))).toBe('No supported dependency files')
    expect(scaLabel({ ...coverage('failed'), detail: 'Advisory matching failed' })).toBe('Analysis failed')
    expect(scaAssessed(coverage('failed'))).toBe(false)
    expect(scaLabel(coverage('disabled'))).toContain('server operator')
  })
})

describe('SCA actions', () => {
  it('uses enrollment rather than lifecycle to choose enable/extract/retry', () => {
    expect(scaAction(false)).toBeNull()
    expect(scaAction(false, coverage('not_monitored'))).toBe('Enable SCA')
    expect(scaAction(true)).toBeNull()
    expect(scaAction(true, { ...coverage('failed'), has_inventory: false })).toBe('Retry')
    expect(canEnableSca('discovered')).toBe(false)
    expect(canEnableSca('discovered', coverage('not_monitored'))).toBe(true)
    expect(canEnableSca('archived')).toBe(false)
    expect(canEnableSca('deleted')).toBe(false)
    expect(canEnableSca('active', { ...coverage('disabled'), enabled: false })).toBe(false)
    expect(canEnableSca('active', coverage('disabled'))).toBe(false)
  })

  it('only offers extraction for explicit missing inventory or a new head', () => {
    expect(scaAction(true, { ...coverage('not_assessed'), has_inventory: false })).toBe('Extract dependencies')
    expect(scaAction(true, { ...coverage('outdated'), has_inventory: false, previous_results: true }, 7, 296)).toBe('Update inventory')
    expect(scaAction(true, { ...coverage('failed'), has_inventory: false, previous_results: true }, 7, 296)).toBe('Retry')
    expect(needsDependencyExtraction(undefined)).toBe(false)
    expect(scaAction(true, { ...coverage('not_assessed'), has_inventory: false }, 7, 296)).toBeNull()
    expect(scaAction(true, coverage('not_assessed'))).toBeNull()
    for (const state of ['reported', 'inventory_ready', 'partial', 'complete', 'queued', 'extracting', 'matching', 'unsupported', 'disabled'] as const) {
      expect(scaAction(true, { ...coverage(state), has_inventory: false })).toBeNull()
    }
    expect(scaAction(true, { ...coverage('failed'), has_inventory: true })).toBeNull()
    expect(scaAction(true, { ...coverage('outdated'), has_inventory: true })).toBeNull()
  })

  it('labels imported findings and inventory without inventing advisory success', () => {
    expect(scaLabel(coverage('reported'))).toBe('Findings reported')
    expect(scaLabel(coverage('inventory_ready'))).toBe('Ready to scan')
    expect(scaAssessed(coverage('reported'))).toBe(false)
    expect(scaKnownCount(0, coverage('inventory_ready'))).toBe('Not assessed')
    expect(inventoryKnownCount(0, coverage('inventory_ready'))).toBe(0)
    expect(inventoryKnownCount(0)).toBe('Not reported')
    expect(inventoryKnownCount(7)).toBe(7)
    expect(scaLabel(coverage('not_assessed'), true, 7, 296)).toBe('Inventory available')
    expect(scaLabel(undefined, true, 0, 296)).toBe('Findings reported')
  })

  it('never guesses SBOM provenance for legacy or previous inventory', () => {
    expect(inventorySource(undefined, 7)).toBe('Source unknown')
    expect(inventorySource({ ...coverage('outdated'), previous_results: true, inventory_source: 'none' })).toBe('Source unknown')
    expect(hasInventory({ ...coverage('outdated'), previous_results: true })).toBe(true)
    expect(inventorySource({ ...coverage('reported'), inventory_source: 'unknown' })).toBe('Source unknown')
    expect(inventorySource({ ...coverage('inventory_ready'), inventory_source: 'sbom' })).toBe('SBOM')
    expect(inventorySource({ ...coverage('partial'), inventory_source: 'cli' })).toBe('Hibou CLI')
    expect(inventorySource({ ...coverage('partial'), inventory_source: 'mixed' })).toBe('Mixed sources')
    expect(inventorySource({ ...coverage('partial'), inventory_source: 'repository' })).toBe('Repository files')
    expect(inventorySourceTitle({ ...coverage('partial'), inventory_source: 'cli' })).toContain('hibou-deps')
    expect(inventorySourceTitle({ ...coverage('inventory_ready'), inventory_source: 'sbom' })).toContain('does not establish')
  })

  it('names concrete mixed sources from the same evidence snapshot', () => {
    const mixed = { ...coverage('partial'), inventory_source: 'mixed' as const, inventory_sources: ['repository', 'sbom'] as const }
    const sca: ScaCoverage = { ...mixed, inventory_sources: [...mixed.inventory_sources] }
    expect(inventorySource(sca)).toBe('Repository files + SBOM')
    expect(inventorySourceTitle(sca)).toContain('same inventory evidence snapshot')
    expect(inventorySourceTitle(sca)).toContain('does not establish')
  })

  it('explains unavailable endpoints without replacing structured server errors', () => {
    expect(scaErrorMessage(new ApiError(404, 'HTTP 404'))).toContain('matching versions')
    expect(scaErrorMessage(new Error('HTTP404'))).toContain('Refresh the page')
    expect(scaErrorMessage(new ApiError(404, 'Repository access revoked', true))).toBe('Repository access revoked')
    expect(scaErrorMessage(new ApiError(404, 'HTTP404', true))).toBe('HTTP404')
  })

  it('explains who can resolve disabled extraction without hiding other errors', () => {
    expect(scaErrorMessage(new Error('Dependency inventory is disabled'))).toContain('server operator')
    expect(scaErrorMessage(new Error('Access denied'))).toBe('Access denied')
  })

  it('bounds bulk requests and rejects empty/duplicate identities', () => {
    expect(scaSelectionValid([])).toBe(false)
    expect(scaSelectionValid([''])).toBe(false)
    expect(scaSelectionValid(['a', 'a'])).toBe(false)
    expect(scaSelectionValid(Array.from({ length: MAX_SCA_SELECTION }, (_, i) => String(i)))).toBe(true)
    expect(scaSelectionValid(Array.from({ length: MAX_SCA_SELECTION + 1 }, (_, i) => String(i)))).toBe(false)
  })

  it('keeps individual failures and usable existing inventory without a job intact', () => {
    const previous = coverage('complete')
    expect(scaResultCoverage({ provider_id: 'a', status: 'failed', error: 'Access denied' }, previous)).toBe(previous)
    expect(scaResultCoverage({ provider_id: 'a', status: 'existing', repo_slug: 'a' }, previous)).toBe(previous)
    expect(scaResultCoverage({ provider_id: 'a', status: 'existing' })).toBeUndefined()
    expect(scaResultCoverage({ provider_id: 'a', status: 'accepted', job_id: 'job' }, previous)).toMatchObject({ state: 'queued', job_id: 'job', on_push: true })
  })
})

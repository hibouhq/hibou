import { describe, expect, it } from 'vitest'
import type { ComponentWithVulns } from '@/api/client'
import { inventoryProvenanceTitle } from './componentProvenance'

const component: ComponentWithVulns = {
  id: 'example', name: 'example', version: '1.0.0', ecosystem: 'npm',
  purl: 'pkg:npm/example@1.0.0', vuln_count: 0,
}

describe('component inventory provenance', () => {
  it('distinguishes known producers from the documents they produced', () => {
    expect(inventoryProvenanceTitle({
      ...component, inventory_sources: ['generated.cdx.json', 'uploaded.cdx.json'],
      inventory_producers: [
        { source: 'generated.cdx.json', name: 'Hibou dependency extraction', engine: 'OSV-SCALIBR + Hibou rules' },
        { source: 'uploaded.cdx.json', name: 'syft' },
      ],
    })).toEqual([
      'Inventory producer: Hibou dependency extraction (OSV-SCALIBR + Hibou rules), syft',
      'Inventory documents: generated.cdx.json, uploaded.cdx.json',
    ])
  })

  it('keeps legacy filenames neutral and missing evidence absent', () => {
    expect(inventoryProvenanceTitle({ ...component, inventory_sources: ['hibou-depinventory.cdx.json'] }))
      .toEqual(['Inventory documents: hibou-depinventory.cdx.json'])
    expect(inventoryProvenanceTitle(component)).toEqual([])
  })
})

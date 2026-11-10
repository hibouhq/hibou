import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'
import type { ScaCoverage } from '@/api/client'
import ScaStatus from './ScaStatus.vue'

function render(sca?: ScaCoverage, compact = false, components = 0) {
  return renderToString(createSSRApp({ render: () => h(ScaStatus, { sca, compact, components }) }))
}

describe('inventory source and status', () => {
  it('keeps repository integration independent of selected snapshot coverage', async () => {
    const html = await renderToString(createSSRApp({
      render: () => h(ScaStatus, { integration: 'ci_integrated', components: 3 }),
    }))
    expect(html).toContain('CI integrated')
    expect(html).toContain('Source unknown')
    expect(html).not.toContain('Advisories checked')
  })
  it('keeps long partial-analysis explanations in expandable, wrapped details', async () => {
    const html = await render({
      state: 'partial', inventory_source: 'repository', enabled: true, on_push: true,
      detail: 'module-one: no lockfile; module-two: indirect dependencies unknown',
    })
    expect(html).toContain('<details')
    expect(html).not.toContain('<details open')
    expect(html).toContain('Analysis details')
    expect(html).toContain('(2)')
    expect(html).toContain('module-one: no lockfile')
    expect(html).toContain('module-two: indirect dependencies unknown')
    expect(html).toContain('[overflow-wrap:anywhere]')
  })
  it('does not turn a supplied SBOM into a completed advisory assessment', async () => {
    const html = await render({ state: 'inventory_ready', inventory_source: 'sbom', enabled: true, on_push: true, has_inventory: true })
    expect(html).toContain('SBOM')
    expect(html).toContain('Ready to scan')
    expect(html).toContain('does not establish technique, completeness or shipped scope')
    expect(html).not.toContain('Advisories checked')
  })

  it('keeps prior inventory commit and current head distinct', async () => {
    const html = await render({
      state: 'outdated', inventory_source: 'cli', has_inventory: false, previous_results: true,
      inventory_commit_sha: 'old-inventory', head_commit_sha: 'new-head', commit_sha: 'new-head',
      enabled: true, on_push: true,
    })
    expect(html).toContain('Hibou CLI')
    expect(html).toContain('hibou-deps')
    expect(html).toContain('Inventory old-inventor')
    expect(html).toContain('Head new-head')
    expect(html).not.toContain('Inventory new-head')
  })

  it('does not label the requested extraction target as an inventory commit', async () => {
    const html = await render({ state: 'queued', has_inventory: false, commit_sha: 'unread-head', enabled: true, on_push: true })
    expect(html).not.toContain('Inventory unread-head')
    expect(html).toContain('Queued')
  })

  it('keeps legacy inventory neutral and compact without guessing a source', async () => {
    const html = await render(undefined, true, 7)
    expect(html).toContain('Source unknown')
    expect(html).toContain('Inventory available')
    expect(html).not.toMatch(/<p(?:\s|>)/)
    expect(html).not.toContain('text-amber')
    expect(html).not.toContain('SCA ·')
  })

  it('shows repository files and supplied SBOM together without a generic mixed-only label', async () => {
    const html = await render({
      state: 'partial', enabled: true, on_push: true, has_inventory: true,
      inventory_source: 'mixed', inventory_sources: ['repository', 'sbom'], inventory_commit_sha: 'same-commit',
    }, true, 7)
    expect(html).toContain('Repository files + SBOM')
    expect(html).toContain('same inventory evidence snapshot')
    expect(html).not.toContain('Mixed sources')
    expect(html).toContain('Partial analysis')
  })
})

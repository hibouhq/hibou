import { describe, expect, it } from 'vitest'
import { createSSRApp, h, provide, ref } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { createMemoryHistory, createRouter } from 'vue-router'
import type { OrgDashboard, RepoDashboardEntry, ScaCoverage, SeverityCounts } from '@/api/client'
import OverviewTab from './OverviewTab.vue'

async function render(sca?: ScaCoverage, options?: { enrolled?: boolean; admin?: boolean; archived?: boolean; known?: number; components?: number; severities?: Partial<SeverityCounts> }) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/orgs/:provider/:slug', component: OverviewTab },
      { path: '/orgs/:provider/:slug/vulnerabilities', name: 'org-vulnerabilities', component: OverviewTab },
      { path: '/orgs/:provider/:slug/repos/:repoSlug/vulnerabilities', name: 'repo-vulnerabilities', component: OverviewTab },
    ],
  })
  await router.push('/orgs/github/example')
  const entry: RepoDashboardEntry = {
    repo_name: 'fixture', repo_slug: 'fixture', provider_id: '123', full_name: 'example/fixture',
    provider: 'github', enrolled: options?.enrolled ?? true, status: options?.archived ? 'archived' : 'discovered',
    vulnerabilities: { critical: 0, high: options?.known ?? 0, medium: 0, low: 0, info: 0, unknown: 0, ...options?.severities },
    components_total: options?.components ?? 0, malware_open: 0, kev_open: null, outdated: false, sca,
  }
  const dashboard: OrgDashboard = {
    repos: [entry],
    totals: { vulnerabilities: entry.vulnerabilities, malware_open: 0, kev_open: null, components_total: entry.components_total },
    coverage: { total_accessible: 1, enrolled: entry.enrolled ? 1 : 0, discovered: 1, active: 0, archived: 0, outdated: 0 },
  }
  const app = createSSRApp({
    setup() {
      provide('orgDashboard', ref(dashboard))
      provide('org', ref({ provider: 'github', slug: 'example', role: options?.admin ? 'admin' : 'member' }))
      return () => h(OverviewTab)
    },
  })
  app.use(router)
  return renderToString(app)
}

describe('SCA overview coverage and actions', () => {
  it('renders unknown legacy capability neutrally rather than absent or clean', async () => {
    const html = await render()
    expect(html).toContain('Not reported')
    expect(html).toContain('0 with inventory · 0 findings only · 0 without inventory')
    expect(html).toContain('1 status unavailable')
    expect(html).not.toContain('Extract dependencies')
    expect(html).not.toContain('Enable SCA')
    expect(html).not.toContain('>None<')
  })

  it('explains discovery-only coverage to non-admins', async () => {
    const html = await render({ state: 'not_monitored', enabled: true, on_push: true, has_inventory: false }, { enrolled: false })
    expect(html).toContain('Ask an organization admin to enable monitoring.')
    expect(html).not.toContain('Enable SCA')
  })

  it('offers enable versus extraction independently from discovered lifecycle', async () => {
    expect(await render({ state: 'not_monitored', enabled: true, on_push: true, has_inventory: false }, { enrolled: false, admin: true })).toContain('Enable SCA')
    expect(await render({ state: 'not_assessed', enabled: true, on_push: true, has_inventory: false }, { enrolled: true, admin: true })).toContain('Extract dependencies')
    expect(await render(undefined, { enrolled: true, admin: true })).not.toContain('Extract dependencies')
  })

  it('disables archived actions', async () => {
    const html = await render({ state: 'not_monitored', enabled: true, on_push: true, has_inventory: false }, { enrolled: false, admin: true, archived: true })
    expect(html).toContain('disabled')
    expect(html).toContain('Archived repositories cannot enable SCA')
  })

  it('retains partial known results and warns about incomplete coverage', async () => {
    const html = await render({ state: 'partial', enabled: true, on_push: false, detail: 'Indirect dependencies unknown' })
    expect(html).toContain('0 known · partial')
    expect(html).toContain('Indirect dependencies unknown')
    expect(html).toContain('Partial analysis')
    expect(html).not.toContain('Automatic push monitoring')
    expect(html).not.toContain('SCA ·')
  })

  it('keeps nonzero partial vulnerability counts in rows and the top summary', async () => {
    const html = await render({ state: 'partial', enabled: true, on_push: true }, { known: 7 })
    expect(html).toContain('7 high')
    expect(html).toContain('text-white">7</span>')
    expect(html).toContain('Partial analysis')
  })

  it('keeps advisory failure and unsupported outcomes distinct', async () => {
    const failed = await render({ state: 'failed', enabled: true, on_push: true, has_inventory: false, detail: 'Advisory matching failed' }, { admin: true })
    expect(failed).toContain('Advisory matching failed')
    expect(failed).toContain('Retry')
    expect(failed).not.toContain('>None<')
    const unsupported = await render({ state: 'unsupported', enabled: true, on_push: true })
    expect(unsupported).toContain('No supported dependency files')
    expect(unsupported).not.toContain('>None<')
  })

  it('keeps screenshot-era component and finding evidence compact and suppresses unnecessary extraction', async () => {
    const html = await render({ state: 'not_assessed', enabled: true, on_push: true, has_inventory: false }, { admin: true, components: 7, known: 296 })
    expect(html).toContain('296 high')
    expect(html).toContain('1 with inventory · 0 findings only · 0 without inventory')
    expect(html).toContain('Source unknown')
    expect(html).toContain('Inventory available')
    expect(html).toContain('Last analysis')
    expect(html).toContain('Counts reflect the latest available analysis')
    expect(html).not.toContain('Extract dependencies')
    expect(html).not.toContain('existing findings shown')
    expect(html).not.toContain('0 assessed')
    expect(html).not.toContain('SCA ·')
    expect(html).not.toContain('SBOM</span>')
  })

  it('reserves a wide, non-wrapping findings lane so Low stays to the right', async () => {
    const html = await render({ state: 'reported', enabled: true, on_push: true }, { components: 7, severities: { critical: 1, high: 12, medium: 234, low: 5, unknown: 6, info: 7 } })
    expect(html).toContain('min-w-[34rem]')
    expect(html).toContain('data-testid="repository-vulnerability-badges"')
    expect(html).toContain('flex-nowrap')
    expect(html).toContain('shrink-0 whitespace-nowrap')
    expect(html).toContain('overflow-x-auto')
    const lane = html.slice(html.indexOf('data-testid="repository-vulnerability-badges"'))
    expect(lane.indexOf('5 low')).toBeGreaterThan(lane.indexOf('1 critical'))
    expect(lane.indexOf('5 low')).toBeGreaterThan(lane.indexOf('234 medium'))
  })

  it('hides unsupported mutation controls on an older server without losing legacy evidence', async () => {
    const html = await render(undefined, { admin: true, components: 7, known: 296 })
    expect(html).toContain('296 high')
    expect(html).toContain('Inventory available')
    expect(html).toContain('Source unknown')
    expect(html).toContain('1 with inventory · 0 findings only · 0 without inventory')
    expect(html).not.toContain('Extract dependencies')
    expect(html).not.toContain('Enable SCA')
    expect(html).not.toContain('Not assessed')
  })

  it.each(['reported', 'inventory_ready', 'partial', 'complete', 'queued', 'extracting', 'matching', 'unsupported', 'disabled'] as const)('does not offer extraction for %s', async state => {
    const html = await render({ state, enabled: true, on_push: true, has_inventory: state === 'inventory_ready' }, { admin: true, known: 12, components: 6 })
    expect(html).not.toContain('Extract dependencies')
    expect(html).not.toContain('>Retry<')
  })

  it('offers only an update for prior inventory at an older commit', async () => {
    const html = await render({
      state: 'outdated', enabled: true, on_push: true, has_inventory: false, previous_results: true,
      inventory_source: 'cli', inventory_commit_sha: 'old-commit', head_commit_sha: 'new-commit', last_assessed: '2026-11-09T12:00:00Z',
    }, { admin: true, known: 12, components: 6 })
    expect(html).toContain('Update inventory')
    expect(html).toContain('Hibou CLI')
    expect(html).toContain('Previous commit')
    expect(html).toContain('Inventory commit: old-commit')
    expect(html).toContain('Current head: new-commit')
    expect(html).toContain('12 high')
    expect(html).not.toContain('Extract dependencies')
  })

  it('shows findings-only evidence without claiming inventory or a clean scan', async () => {
    const html = await render({ state: 'reported', enabled: true, on_push: true, has_inventory: false, inventory_source: 'none' }, { admin: true, known: 22 })
    expect(html).toContain('Findings reported')
    expect(html).toContain('0 with inventory · 1 findings only · 0 without inventory')
    expect(html).toContain('22 high')
    expect(html).not.toContain('Extract dependencies')
    expect(html).not.toContain('>None<')
  })
})

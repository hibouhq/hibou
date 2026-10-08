import { describe, expect, it } from 'vitest'
import { createSSRApp, h, provide, ref, type Component } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { createMemoryHistory, createRouter } from 'vue-router'

import InsightsTab from './InsightsTab.vue'
import OverviewTab from './OverviewTab.vue'

async function render(view: Component, kevOpen: number | null, partial = false) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/orgs/:provider/:slug', component: view },
      { path: '/orgs/:provider/:slug/vulnerabilities', name: 'org-vulnerabilities', component: view },
      { path: '/orgs/:provider/:slug/repos', name: 'repos', component: view },
      { path: '/orgs/:provider/:slug/repos/:repoSlug', component: view },
      { path: '/orgs/:provider/:slug/repos/:repoSlug/vulnerabilities', name: 'repo-vulnerabilities', component: view },
    ],
  })
  await router.push('/orgs/github/hibouhq')
  const app = createSSRApp({
    setup() {
      provide('orgDashboard', ref({
        repos: partial ? [
          { repo_slug: 'known', repo_name: 'known', provider: 'github', provider_id: 'known', enrolled: true, status: 'active', malware_open: 0, kev_open: 3, components_total: 2, vulnerabilities: { critical: 0, high: 0, medium: 1, low: 0, info: 0 } },
          { repo_slug: 'unavailable', repo_name: 'unavailable', provider: 'github', provider_id: 'unavailable', enrolled: true, status: 'active', malware_open: 0, kev_open: null, components_total: 2, vulnerabilities: { critical: 100, high: 0, medium: 0, low: 0, info: 0 } },
        ] : [],
        totals: {
          vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          malware_open: 0, kev_open: kevOpen, components_total: 0,
        },
        coverage: { total_accessible: 0, enrolled: 0, discovered: 0, active: 0, archived: 0, outdated: 0 },
      }))
      return () => h(view)
    },
  })
  app.use(router)
  return renderToString(app)
}

describe.each([['Overview', OverviewTab], ['Insights', InsightsTab]] as const)('%s KEV summary', (_name, view) => {
  it.each([0, 3])('shows successful count %i with matching risk drill-down', async kevOpen => {
    const html = await render(view, kevOpen)
    expect(html).toContain(`${kevOpen} known exploited`)
    expect(html).toContain('exploited=true')
    expect(html).toContain('risk_only=true')
    expect(html).not.toContain('status=detected')
  })

  it('does not turn unavailable catalog evidence into zero', async () => {
    const html = await render(view, null)
    expect(html.toLowerCase()).toContain('known exploited')
    expect(html.toLowerCase()).toContain('unavailable')
    expect(html).not.toContain('0 known exploited')
  })

  it('keeps known risks visible when another repository lacks evidence', async () => {
    const html = await render(view, null, true)
    expect(html).toContain('At least 3 known exploited')
    expect(html).toContain('1 repository')
    expect(html).toContain('risk_only=true')
  })
})
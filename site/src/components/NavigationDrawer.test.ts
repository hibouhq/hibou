import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { createMemoryHistory, createRouter } from 'vue-router'
import { Building2 } from 'lucide-vue-next'

import NavigationDrawer from './NavigationDrawer.vue'

describe('NavigationDrawer', () => {
  it('renders labeled modal navigation with close control and destination links', async () => {
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/orgs', component: NavigationDrawer }] })
    await router.push('/orgs')
    const app = createSSRApp({
      render: () => h(NavigationDrawer, {
        open: true,
        sections: [{ title: 'Global', items: [{ label: 'Organizations', icon: Building2, to: '/orgs' }] }],
      }),
    })
    app.use(router)
    const context: { teleports?: Record<string, string> } = {}
    await renderToString(app, context)
    const html = context.teleports?.body ?? ''
    expect(html).toContain('role="dialog"')
    expect(html).toContain('aria-modal="true"')
    expect(html).toContain('aria-label="Close navigation menu"')
    expect(html).toContain('aria-label="Navigation"')
    expect(html).toContain('Organizations')
    expect(html).toContain('href="/orgs"')
  })
})

import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'
import ScaActionResults from './ScaActionResults.vue'

describe('dependency analysis notices', () => {
  it('renders an actionable, dismissible compact transport notice', async () => {
    const html = await renderToString(createSSRApp({ render: () => h(ScaActionResults, {
      provider: 'github', slug: 'fixture', results: [],
      error: 'Endpoint unavailable. Refresh the page or ask the operator to update the server.',
    }) }))
    expect(html).toContain('Dependency analysis unavailable')
    expect(html).toContain('Refresh the page')
    expect(html).toContain('aria-label="Dismiss dependency analysis notice"')
    expect(html).toContain('aria-live="polite"')
    expect(html).not.toContain('HTTP404')
  })

  it('keeps each failed item visible with an appropriate title', async () => {
    const html = await renderToString(createSSRApp({ render: () => h(ScaActionResults, {
      provider: 'github', slug: 'fixture', error: '',
      results: [{ provider_id: '123', status: 'failed', error: 'Access denied' }],
    }) }))
    expect(html).toContain('Some repositories need attention')
    expect(html).toContain('123')
    expect(html).toContain('Access denied')
    expect(html).toContain('Dismiss dependency analysis notice')
  })

  it('explains raw per-item 404 failures rather than showing a stale HTTP banner', async () => {
    const html = await renderToString(createSSRApp({ render: () => h(ScaActionResults, {
      provider: 'github', slug: 'fixture', error: '',
      results: [{ provider_id: '123', status: 'failed', error: 'HTTP404' }],
    }) }))
    expect(html).toContain('matching versions')
    expect(html).not.toContain('HTTP404')
  })
})

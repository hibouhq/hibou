import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'
import FilterBar from './FilterBar.vue'

describe('FilterBar qualifier controls', () => {
  it('shows matching results against an independent scope total', async () => {
    const html = await renderToString(createSSRApp({
      render: () => h(FilterBar, { filters: [], totalCount: 229, filteredCount: 1 }),
    }))
    expect(html).toContain('Showing 1 / 229')
    expect(html).not.toContain('Showing 1 / 1<')
  })

  it.each(['true', 'false', undefined])('renders a generic boolean button with state %s and no dropdown', async value => {
    const html = await renderToString(createSSRApp({
      render: () => h(FilterBar, {
        modelValue: value ? { archived: value } : {},
        filters: [{ key: 'archived', label: 'Archived', options: ['true', 'false'], control: 'boolean' }],
      }),
    }))
    expect(html).toContain(`aria-pressed="${value === 'true'}"`)
    expect(html).toContain('Archived')
    expect(html).not.toContain('aria-haspopup="true"')
    if (value) expect(html).toContain(`archived:${value}`)
  })

  it('hides token-only dropdowns while preserving search qualifiers and primary status', async () => {
    const html = await renderToString(createSSRApp({
      render: () => h(FilterBar, {
        modelValue: { type: 'dependency', exploited: 'true' },
        filters: [
          { key: 'status', label: 'Status', options: ['detected'], primary: true, hidden: true, defaultValue: 'detected' },
          { key: 'type', label: 'Type', options: ['dependency'] },
          { key: 'exploited', label: 'Exploited', options: ['true', 'false'], hidden: true },
        ],
      }),
    }))
    expect(html).toContain('Status')
    expect(html).toContain('Type')
    expect(html).not.toContain('<span>Exploited</span>')
    expect(html).toContain('type:dependency')
    expect(html).toContain('exploited:true')
  })

  it('keeps controls disabled while a boolean query has an error', async () => {
    const html = await renderToString(createSSRApp({
      render: () => h(FilterBar, {
        modelValue: {},
        advancedQuery: '(severity:high OR severity:low',
        filters: [
          { key: 'severity', label: 'Severity', options: ['high', 'low'], multi: true },
          { key: 'exploited', label: 'Exploited', options: ['true', 'false'], control: 'boolean' },
        ],
      }),
    }))
    expect(html.match(/" disabled[ >]/g)?.length).toBe(2)
  })
})

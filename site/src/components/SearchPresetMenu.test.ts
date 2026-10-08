import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'

import { OPEN_RISK_QUERY } from '@/lib/openRiskPreset'
import { BUILTIN_FINDINGS_PRESETS } from '@/lib/searchPresets'
import SearchPresetMenu from './SearchPresetMenu.vue'

const filters = [
  { key: 'status', label: 'Status', options: ['detected', 'resolved', 'suppressed'], multi: true, hidden: true, defaultValue: 'detected' },
  { key: 'type', label: 'Type', options: ['dependency', 'sast'], multi: true },
  { key: 'acceptance', label: 'Triage', options: ['open', 'accepted', 'risk_accepted', 'false_positive', 'disputed'] },
  { key: 'exploited', label: 'Exploited', options: ['true', 'false'] },
]

function render(query: string) {
  return renderToString(createSSRApp({
    render: () => h(SearchPresetMenu, { surface: 'findings', filters, builtins: BUILTIN_FINDINGS_PRESETS, query }),
  }))
}

describe('SearchPresetMenu', () => {
  it('collapses to a single closed button', async () => {
    const html = await render('')
    expect(html).toContain('Presets')
    expect(html).toContain('aria-expanded="false"')
    expect(html).not.toContain('Save current query')
  })

  it('names the active preset when the bar matches it', async () => {
    const html = await render(OPEN_RISK_QUERY)
    expect(html).toContain('Open risk')
    expect(html).toContain('Preset: Open risk')
  })

  it('falls back to the generic label for an unsaved query', async () => {
    const html = await render('type:sast')
    expect(html).toContain('>Presets<')
  })
})

import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString, type SSRContext } from 'vue/server-renderer'

import PresetDialog from './PresetDialog.vue'

const filters = [{ key: 'type', label: 'Type', options: ['dependency', 'sast'], multi: true }]

async function render(props: Partial<InstanceType<typeof PresetDialog>['$props']> = {}) {
  const context: SSRContext = {}
  await renderToString(createSSRApp({
    render: () => h(PresetDialog, {
      open: true,
      mode: 'save',
      query: '(type:sast OR type:dependency) openssl',
      filters,
      existingPresets: [],
      busy: false,
      error: '',
      ...props,
    }),
  }), context)
  return String(context.teleports?.body ?? '')
}

describe('PresetDialog', () => {
  it('shows the query with the bar colouring', async () => {
    const html = await render()
    expect(html).toContain('<span class="text-[#d2a8ff]">OR</span>')
    expect(html).toContain('<span class="text-[#79c0ff]">sast</span>')
    expect(html).toContain('Save')
  })

  it('surfaces a server error inline', async () => {
    expect(await render({ error: 'preset limit reached' })).toContain('preset limit reached')
  })

  it('renders nothing when closed', async () => {
    expect(await render({ open: false })).not.toContain('Save search preset')
  })

  it('shows the whole query without a scroll box', async () => {
    expect(await render()).not.toContain('overflow-y-auto')
  })

  it('confirms a delete with the preset name and coloured query', async () => {
    const html = await render({ mode: 'delete', presetName: 'My triage' })
    expect(html).toContain('Delete search preset')
    expect(html).toContain('My triage')
    expect(html).toContain('<span class="text-[#79c0ff]">sast</span>')
    expect(html).toContain('>Delete<')
    expect(html).not.toContain('placeholder=')
  })
})

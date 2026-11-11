import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'
import type { Snapshot } from '@/api/client'
import SnapshotSelector from './SnapshotSelector.vue'

const snapshots: Snapshot[] = [
  { id: 'new', ref_id: 'main', commit_sha: 'abcdef123456', status: 'complete', run_number: '42', created_at: '2026-11-11T12:00:00Z' },
  { id: 'old', ref_id: 'main', commit_sha: '123456abcdef', status: 'failed', tag: 'v1.0', created_at: '2026-11-10T12:00:00Z' },
]

function render(props: Partial<InstanceType<typeof SnapshotSelector>['$props']> = {}) {
  return renderToString(createSSRApp({
    render: () => h(SnapshotSelector, { snapshots, modelValue: 'new', label: 'Base snapshot', ...props }),
  }))
}

describe('SnapshotSelector', () => {
  it('shows commit, readable status, date and run together without a separate reset button', async () => {
    const html = await render()
    expect(html).toContain('abcdef1')
    expect(html).toContain('Build passed')
    expect(html).toContain('Nov 11')
    expect(html).toContain('Run #42')
    expect(html).toContain('aria-label="Base snapshot"')
    expect(html).toContain('aria-haspopup="listbox"')
    expect(html).toContain('aria-expanded="false"')
    expect(html.match(/<button/g)).toHaveLength(1)
  })

  it('keeps the datetime inline immediately after build status', async () => {
    const html = await render()
    expect(html).toContain('truncate whitespace-nowrap text-xs leading-5')
    expect(html).toMatch(/Build passed<\/span><span class="text-gray-400"> · Nov 11/)
    expect(html).not.toContain('mt-1 block truncate')
  })

  it('distinguishes default latest selection from an explicitly pinned snapshot', async () => {
    const latest = await render({ modelValue: '', allowLatest: true })
    expect(latest).toContain('>Latest</span>')
    expect(latest).toContain('abcdef1')
    expect(await render({ allowLatest: true })).not.toContain('>Latest</span>')
  })

  it('shows the chosen older run, including failed status and tag', async () => {
    const html = await render({ modelValue: 'old' })
    expect(html).toContain('123456a')
    expect(html).toContain('Build failed')
    expect(html).toContain('v1.0')
    expect(html).not.toContain('Build passed')
  })

  it('does not silently display the latest run for an unavailable pinned snapshot', async () => {
    const html = await render({ modelValue: 'not-in-history' })
    expect(html).toContain('Selected snapshot not-in-')
    expect(html).not.toContain('abcdef1')
  })

  it('shows loading, empty and error states explicitly', async () => {
    expect(await render({ loading: true })).toContain('Loading snapshots...')
    expect(await render({ snapshots: [], modelValue: '' })).toContain('No snapshots available')
    const html = await render({ snapshots: [], error: 'Could not load snapshots' })
    expect(html).toContain('role="alert"')
    expect(html).toContain('Could not load snapshots')
    expect(html).toContain('Retry')
  })
})

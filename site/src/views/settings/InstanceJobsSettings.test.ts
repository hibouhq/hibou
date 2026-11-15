import { readFileSync } from 'node:fs'
import { compile } from '@vue/compiler-dom'
import { compileScript, parse } from '@vue/compiler-sfc'
import { ScriptTarget, transpileModule } from 'typescript'
import { describe, expect, it, vi } from 'vitest'
import * as Vue from 'vue'
import { createRenderer, nextTick, ssrContextKey } from 'vue'

import type { InstanceWorker } from '@/api/client'
import { api } from '@/api/client'
import InstanceJobsSettings from './InstanceJobsSettings.vue'

vi.mock('@/api/client', () => ({
  api: {
    getInstanceJobsOverview: vi.fn(),
    getInstanceJobsTimeline: vi.fn().mockResolvedValue({ data: { runs: [] } }),
    getInstanceJobsStats: vi.fn().mockResolvedValue({ data: { buckets: [], baselines: [] } }),
  },
}))
vi.mock('@/components/settings/JobsTimeline.vue', () => ({ default: { render: () => null } }))
vi.mock('@/components/settings/JobsKindStats.vue', () => ({ default: { render: () => null } }))
vi.mock('@/components/settings/JobsRunList.vue', () => ({ default: { render: () => null } }))

interface TestNode {
  text: string
  children: TestNode[]
  parent: TestNode | null
  props: Record<string, unknown>
}

function node(text = ''): TestNode {
  return { text, children: [], parent: null, props: {} }
}

const renderer = createRenderer<TestNode, TestNode>({
  createElement: () => node(),
  createText: text => node(text),
  createComment: () => node(),
  setText: (target, text) => { target.text = text },
  setElementText: (target, text) => { target.text = text; target.children = [] },
  parentNode: target => target.parent,
  nextSibling: target => target.parent?.children[target.parent.children.indexOf(target) + 1] ?? null,
  patchProp: (target, key, _prev, value) => { target.props[key] = value },
  insert(target, parent, anchor) {
    if (target.parent) target.parent.children.splice(target.parent.children.indexOf(target), 1)
    const index = anchor ? parent.children.indexOf(anchor) : -1
    parent.children.splice(index < 0 ? parent.children.length : index, 0, target)
    target.parent = parent
  },
  remove(target) {
    if (target.parent) target.parent.children.splice(target.parent.children.indexOf(target), 1)
    target.parent = null
  },
})

function text(target: TestNode): string {
  return target.text + target.children.map(text).join('')
}

function find(target: TestNode, predicate: (target: TestNode) => boolean): TestNode | undefined {
  if (predicate(target)) return target
  for (const child of target.children) {
    const match = find(child, predicate)
    if (match) return match
  }
}

function worker(status: InstanceWorker['status'], overrides: Partial<InstanceWorker> = {}): InstanceWorker {
  return {
    id: status, hostname: `${status}-fixture`, pid: 1, version: 'v1', loops: [],
    status, started_at: '2020-01-01T00:00:00Z', last_heartbeat_at: '2020-01-01T01:00:00Z',
    cpu_percent: 87.3, memory_rss_bytes: 1024, heap_alloc_bytes: 2048, goroutines: 42,
    active_jobs: 5, running_jobs: 2, ...overrides,
  }
}

async function mount(workers: InstanceWorker[]) {
  vi.mocked(api.getInstanceJobsOverview).mockResolvedValue({
    data: { kinds: [], workers, heartbeat_interval_seconds: 30 },
  })
  const root = node()
  // Vitest's Node transform supplies SSR code; compile the client template
  // for the in-memory renderer so interactions exercise the actual bindings.
  const source = readFileSync(new URL('./InstanceJobsSettings.vue', import.meta.url), 'utf8')
  const { descriptor } = parse(source)
  const bindings = compileScript(descriptor, { id: 'worker-reporting' }).bindings
  const { code } = compile(descriptor.template!.content, { mode: 'function', prefixIdentifiers: true, bindingMetadata: bindings })
  const { outputText } = transpileModule(code, { compilerOptions: { target: ScriptTarget.ES2022 } })
  const render = new Function('Vue', outputText)(Vue) as NonNullable<typeof InstanceJobsSettings.render>
  const app = renderer.createApp({ ...InstanceJobsSettings, render })
  app.provide(ssrContextKey, { modules: new Set() })
  app.mount(root)
  await vi.waitFor(() => expect(text(root)).toContain('Workers'))
  return { root, app }
}

describe('worker reporting', () => {
  it('does not treat historical registrations as expected replica capacity', async () => {
    const { root, app } = await mount([worker('online'), worker('stale'), worker('stopped')])
    try {
      const count = find(root, target => target.props['aria-label'] === 'Online worker count')
      expect(count?.text).toBe('1')
      expect(text(root)).not.toContain('1/3')
      expect(text(root)).toContain('Stale records may belong to previous replicas.')
    } finally {
      app.unmount()
    }
  })

  it('keeps loop details collapsed and reveals every enabled loop on demand', async () => {
    const loops = ['membership_revalidation', 'device_auth_cleanup', 'retention', 'stale_pending', 'fixture_long_loop_name_without_breaks']
    const { root, app } = await mount([worker('online', { loops })])
    try {
      expect(text(root)).toContain('5 loops')
      expect(text(root)).not.toContain(loops[0])
      const toggle = find(root, target => target.props['aria-label'] === 'Show 5 enabled loops')
      expect(toggle).toBeDefined()
      ;(toggle!.props.onClick as () => void)()
      await nextTick()
      for (const loop of loops) expect(text(root)).toContain(loop)
      expect(find(root, target => target.props['aria-expanded'] === true && target.props['aria-label'] === 'Hide 5 enabled loops')).toBeDefined()
    } finally {
      app.unmount()
    }
  })

  it('counts self-reported work without double-counting claimed leases', async () => {
    const { root, app } = await mount([worker('online')])
    try {
      const jobs = find(root, target => target.props.title === 'self-reported 5, claimed leases 2')
      expect(jobs?.text).toBe('5')
      expect(text(root)).toContain('87.3%')
    } finally {
      app.unmount()
    }
  })

  it('hides stopped history by default and never shows stale resource samples', async () => {
    const { root, app } = await mount([
      worker('stale'),
      worker('stopped', { stopped_at: '2020-01-01T02:00:00Z' }),
    ])
    try {
      expect(text(root)).toContain('stale-fixture')
      expect(text(root)).not.toContain('stopped-fixture')
      expect(text(root)).not.toContain('87.3%')
      const toggle = find(root, target => typeof target.props.onClick === 'function' && text(target).includes('Show 1 stopped'))
      expect(toggle).toBeDefined()
      ;(toggle!.props.onClick as () => void)()
      await nextTick()
      expect(text(root)).toContain('stopped-fixture')
      expect(text(root)).toContain('ran 2h 00m')
      expect(text(root)).not.toContain('87.3%')
      expect(find(root, target => target.props.title === 'No current worker sample')?.text).toBe('—')
    } finally {
      app.unmount()
    }
  })

  it('highlights only multiple online versions', async () => {
    const { root, app } = await mount([
      worker('online'),
      worker('online', { id: 'second', version: 'v2' }),
      worker('stale', { version: 'v3' }),
    ])
    try {
      expect(text(root)).toContain('2 versions running')
      expect(text(root)).not.toContain('3 versions running')
    } finally {
      app.unmount()
    }
  })
})

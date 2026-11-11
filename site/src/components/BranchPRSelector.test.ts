import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'
import BranchPRSelector from './BranchPRSelector.vue'

describe('comparison branch selector labels', () => {
  it.each([
    ['left', 'base'],
    ['right', 'head'],
  ] as const)('describes the %s-hand selector as %s', async (align, role) => {
    const html = await renderToString(createSSRApp({
      render: () => h(BranchPRSelector, { refs: [], selectedRefName: 'main', hero: true, align }),
    }))
    expect(html).toContain(`change ${role}`)
  })
})

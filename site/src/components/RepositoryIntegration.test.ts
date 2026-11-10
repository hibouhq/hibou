import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'
import type { ScaCoverage } from '@/api/client'
import RepositoryIntegration from './RepositoryIntegration.vue'

async function render(mode?: ScaCoverage['integration']) {
  return renderToString(createSSRApp({ render: () => h(RepositoryIntegration, { mode }) }))
}

describe('repository integration badge', () => {
  it('distinguishes server scans from observed CI uploads', async () => {
    const scan = await render('monitored')
    expect(scan).toContain('Monitored')
    expect(scan).toContain('no CI analysis uploads')
    expect(scan).not.toContain('CI integrated')
    const ci = await render('ci_integrated')
    expect(ci).toContain('CI integrated')
    expect(ci).toContain('coverage, tests, SARIF or SBOMs')
    expect(ci).toContain('does not guarantee')
    expect(ci).toContain('text-accent')
  })

  it('does not invent integration status for an older server', async () => {
    expect(await render()).toContain('Integration unknown')
    expect(await render('not_monitored')).toContain('Not connected')
  })
})

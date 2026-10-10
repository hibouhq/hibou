import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'

import CvssCalculator from './CvssCalculator.vue'

async function render(props: Record<string, unknown>): Promise<string> {
  return renderToString(createSSRApp({ render: () => h(CvssCalculator, props) }))
}

describe('CvssCalculator', () => {
  it('explains and scores any version read-only', async () => {
    const html = await render({ modelValue: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' })
    expect(html).toContain('9.8')
    expect(html).toContain('CVSS 3.1 · critical')
    expect(html).toContain('Network: Remotely exploitable')
    expect(html).toContain('disabled')
  })

  it('scores v4.0 with the reference algorithm', async () => {
    const html = await render({ modelValue: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' })
    expect(html).toContain('9.3')
    expect(html).toContain('Subsequent system impact')
  })

  it('asks for every base metric before scoring a new vector', async () => {
    const html = await render({ editable: true })
    expect(html).toContain('11 required metrics left')
    expect(html).toContain('required')
  })

  it('shows why a vector is invalid', async () => {
    const html = await render({ modelValue: 'CVSS:3.1/AV:N/AC:L' })
    expect(html).toContain('Missing required metric')
  })
})

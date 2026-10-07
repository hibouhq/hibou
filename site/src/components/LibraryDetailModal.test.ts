import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'

import LibraryDetailModal from './LibraryDetailModal.vue'

describe('LibraryDetailModal', () => {
  it('renders dependency aliases as links to their own sources', async () => {
    const context: { teleports?: Record<string, string> } = {}
    await renderToString(createSSRApp({
      render: () => h(LibraryDetailModal, {
        component: {
          id: 'jquery', name: 'jquery', version: '3.4.1', ecosystem: 'npm',
          purl: 'pkg:npm/jquery@3.4.1', vuln_count: 1,
          advisories: [{
            id: 'advisory', canonical_id: 'CVE-2020-11023', title: 'XSS', severity: 'medium', is_malware: false,
            aliases: ['GHSA-jfh8-c2jp-5v3q', 'EUVD-2026-73069'],
          }],
        },
      }),
    }), context)

    const html = context.teleports?.body ?? ''
    expect(html).toContain('https://nvd.nist.gov/vuln/detail/CVE-2020-11023')
    expect(html).toContain('https://github.com/advisories/GHSA-jfh8-c2jp-5v3q')
    expect(html).toContain('https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-73069')
    expect(html).not.toContain('https://osv.dev/vulnerability/EUVD-')
  })
})
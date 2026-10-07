import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'

import type { FindingKEV } from '@/api/client'
import FindingKEVDetails from './FindingKEVDetails.vue'

async function render(kev: FindingKEV): Promise<string> {
    return renderToString(createSSRApp({
        render: () => h(FindingKEVDetails, { kev, identifier: 'CVE-2020-11023' }),
    }))
}

describe('FindingKEVDetails', () => {
    it('shows catalog evidence with official links and scoped deadline', async () => {
        const html = await render({
            sources: ['cisa', 'euvd'],
            entries: [
                { source: 'cisa', identifier: 'CVE-2020-11023', cve_id: 'CVE-2020-11023' },
                { source: 'euvd', identifier: 'EUVD-2026-73069', cve_id: 'CVE-2020-11023' },
            ],
            date_added: '2025-01-01',
            due_date: '2025-01-22',
            ransomware_use: true,
        })

        expect(html).toContain('Known exploitation')
        expect(html).toContain('CISA KEV')
        expect(html).toContain('search_api_fulltext=CVE-2020-11023')
        expect(html).toContain('ENISA EUVD')
        expect(html).toContain('https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-73069')
        expect(html).toContain('2025-01-01')
        expect(html).toContain('US federal due date')
        expect(html).toContain('2025-01-22')
        expect(html).toContain('Known campaigns')
        expect(html).toContain('rel="noopener noreferrer"')
    })

    it('does not fabricate unknown dates or ransomware status', async () => {
        const html = await render({ sources: ['euvd'] })

        expect(html).toContain('ENISA EUVD')
        expect(html).not.toContain('US federal due date')
        expect(html).not.toContain('Ransomware use')
        expect(html).toContain('removal does not prove')
    })

    it('does not misattribute unknown sources or invent missing EUVD identifiers', async () => {
        const html = await render({ sources: ['custom', 'euvd'] })
        expect(html).toContain('CUSTOM')
        expect(html).not.toContain('<a')
    })
})

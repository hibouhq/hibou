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

    it('shows where the component comes from and its chains, without backend TODO notes', async () => {
        const context: { teleports?: Record<string, string> } = {}
        await renderToString(createSSRApp({
            render: () => h(LibraryDetailModal, {
                component: {
                    id: 'qs', name: 'qs', version: '6.11.0', ecosystem: 'npm',
                    purl: 'pkg:npm/qs@6.11.0', vuln_count: 0,
                    relationship: 'indirect', resolution: 'recorded',
                    paths: ['web/package-lock.json'], modules: ['web'],
                    inventory_sources: ['hibou-dependencies.cdx.json'],
                    usage_paths: [['web', 'express', 'qs']],
                },
            }),
        }), context)

        const html = context.teleports?.body ?? ''
        expect(html).toContain('Where it comes from')
        expect(html).toContain('web/package-lock.json')
        expect(html).toContain('recorded in a lockfile')
        expect(html).toContain('express')
        expect(html).not.toContain('TODO-BACKEND')
    })

    it('lays the advisory table out without horizontal scrolling', async () => {
        const context: { teleports?: Record<string, string> } = {}
        await renderToString(createSSRApp({
            render: () => h(LibraryDetailModal, {
                component: {
                    id: 'django', name: 'django', version: '4.2.7', ecosystem: 'pypi',
                    purl: 'pkg:pypi/django@4.2.7', vuln_count: 1,
                    advisories: [{ id: 'a', canonical_id: 'CVE-2026-4277', title: 't', severity: 'critical', is_malware: false }],
                },
            }),
        }), context)

        const html = context.teleports?.body ?? ''
        expect(html).toContain('table-fixed')
        expect(html).toContain('overflow-x-hidden')
    })
})

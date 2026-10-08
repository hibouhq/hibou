import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { parse } from '@vue/compiler-sfc'
import { parse as parseTemplate, NodeTypes, type ElementNode } from '@vue/compiler-dom'

function templateFor(path: string) {
    const source = readFileSync(new URL(path, import.meta.url), 'utf8')
    const template = parse(source).descriptor.template?.content
    if (!template) throw new Error('Missing template')
    return { source, template: parseTemplate(template) }
}

function elements(children: ElementNode['children']): ElementNode[] {
    return children.filter(child => child.type === NodeTypes.ELEMENT) as ElementNode[]
}

describe('header-attached entity navigation', () => {
    it('uses the same offset for entity content as the fixed header height', () => {
        const { source } = templateFor('../layouts/AppLayout.vue')
        expect(source).toContain('z-50 h-14')
        expect(source).toContain("'pt-[calc(3.5rem+var(--app-banner-height,0px))]'")
    })

    it('preserves horizontal gutters and centered content on entity pages', () => {
        const { source } = templateFor('../layouts/AppLayout.vue')
        expect(source).toContain('class="min-h-screen px-4 pb-6 sm:px-6"')
        expect(source).toContain('<div class="mx-auto max-w-7xl">')
    })

    it.each(['./RepoDetailView.vue', './OrgDetailView.vue'])('renders tabs before controls in %s', path => {
        const { template } = templateFor(path)
        const root = elements(template.children)[0]
        const loaded = elements(root.children).find(element => element.tag === 'template')
        expect(loaded).toBeDefined()
        const band = elements(loaded!.children)[0]
        const classAttribute = band.props.find(prop => prop.type === NodeTypes.ATTRIBUTE && prop.name === 'class')
        expect(classAttribute && classAttribute.type === NodeTypes.ATTRIBUTE ? classAttribute.value?.content : '').not.toMatch(/\b(?:mt|pt)-/)
        expect(elements(band.children)[0].tag).toBe('nav')
    })
})

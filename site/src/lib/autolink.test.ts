import { describe, expect, it } from 'vitest'

import { autolinkSegments, type Autolink } from './autolink'

const links: Autolink[] = [
  { prefix: 'SEC-', url_template: 'https://tracker.example/browse/SEC-<num>', alphanumeric: false },
  { prefix: 'SECOPS-', url_template: 'https://tracker.example/browse/SECOPS-<num>', alphanumeric: false },
  { prefix: 'GH#', url_template: 'https://github.com/acme/app/issues/<num>', alphanumeric: false },
  { prefix: 'TICKET-', url_template: 'https://desk.example/t/<num>', alphanumeric: true },
]

describe('autolinkSegments', () => {
  it('links tracker references and keeps the surrounding text', () => {
    expect(autolinkSegments('Tracked in SEC-7, see also sec-12.', links)).toEqual([
      { kind: 'text', text: 'Tracked in ' },
      { kind: 'link', text: 'SEC-7', href: 'https://tracker.example/browse/SEC-7' },
      { kind: 'text', text: ', see also ' },
      { kind: 'link', text: 'sec-12', href: 'https://tracker.example/browse/SEC-12' },
      { kind: 'text', text: '.' },
    ])
  })

  it('prefers the longest prefix and respects word boundaries', () => {
    expect(autolinkSegments('SECOPS-3 ASEC-7 SEC-7a', links)).toEqual([
      { kind: 'link', text: 'SECOPS-3', href: 'https://tracker.example/browse/SECOPS-3' },
      { kind: 'text', text: ' ASEC-7 SEC-7a' },
    ])
  })

  it('accepts letters after an alphanumeric prefix', () => {
    expect(autolinkSegments('TICKET-ab12-x done', links)).toEqual([
      { kind: 'link', text: 'TICKET-ab12-x', href: 'https://desk.example/t/ab12-x' },
      { kind: 'text', text: ' done' },
    ])
  })

  it('links bare URLs and leaves references inside them alone', () => {
    expect(autolinkSegments('https://tracker.example/browse/SEC-7 and GH#42', links)).toEqual([
      { kind: 'link', text: 'https://tracker.example/browse/SEC-7', href: 'https://tracker.example/browse/SEC-7' },
      { kind: 'text', text: ' and ' },
      { kind: 'link', text: 'GH#42', href: 'https://github.com/acme/app/issues/42' },
    ])
  })

  it('refuses templates that do not produce an http(s) link', () => {
    const bad: Autolink[] = [{ prefix: 'X-', url_template: 'javascript:<num>', alphanumeric: false }]
    expect(autolinkSegments('X-1', bad)).toEqual([{ kind: 'text', text: 'X-1' }])
  })

  it('returns plain text without autolinks and nothing for empty text', () => {
    expect(autolinkSegments('SEC-7')).toEqual([{ kind: 'text', text: 'SEC-7' }])
    expect(autolinkSegments('', links)).toEqual([])
  })
})

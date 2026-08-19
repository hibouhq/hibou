import { describe, expect, it } from 'vitest'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'

import MarkdownText from './MarkdownText.vue'

async function render(text: string): Promise<string> {
  return renderToString(createSSRApp({ render: () => h(MarkdownText, { text }) }))
}

/** Every href in the output — the only attribute the input can influence. */
function hrefs(html: string): string[] {
  return [...html.matchAll(/href="([^"]*)"/g)].map((match) => match[1])
}

describe('MarkdownText', () => {
  it('renders the block shapes advisory text uses', async () => {
    const html = await render([
      '### Impact',
      '',
      'The affected functions set environment variables',
      'without synchronization.',
      '',
      '- `time::UtcOffset::local_offset_at`',
      '- second item',
      '',
      '1. first',
      '2. second',
      '',
      '```rust',
      'let x = 1;',
      '```',
    ].join('\n'))

    expect(html).toContain('Impact')
    // Soft line breaks join into one paragraph.
    expect(html).toContain('The affected functions set environment variables without synchronization.')
    expect(html).toContain('<ul')
    expect(html).toContain('<ol')
    expect(html).toContain('<code')
    expect(html).toContain('let x = 1;')
  })

  it('renders emphasis and links', async () => {
    const html = await render('See **the advisory** and _the fix_ at [OSV](https://osv.dev/x).')
    expect(html).toContain('<strong')
    expect(html).toContain('<em')
    expect(html).toContain('href="https://osv.dev/x"')
    expect(html).toContain('rel="noopener noreferrer"')
  })

  it('autolinks bare URLs', async () => {
    const html = await render('Details: https://nvd.nist.gov/vuln/detail/CVE-2020-26235')
    expect(html).toContain('href="https://nvd.nist.gov/vuln/detail/CVE-2020-26235"')
  })

  it('renders nothing for empty input', async () => {
    expect(await render('')).not.toContain('<p')
  })

  // ── Adversarial: the text is third-party and attacker-influenceable ────────

  it('never parses HTML — markup survives only as escaped text', async () => {
    const html = await render([
      '<img src=x onerror="alert(1)">',
      '',
      '<script>alert(2)</script>',
      '',
      '<svg/onload=alert(3)>',
      '',
      '<iframe src="https://evil.example"></iframe>',
      '',
      '<a href="https://evil.example" download>x</a>',
      '',
      '<style>*{display:none}</style>',
    ].join('\n'))

    for (const tag of ['<img', '<script', '<svg', '<iframe', '<style', '<a href="https://evil.example"']) {
      expect(html).not.toContain(tag)
    }
    expect(html).toContain('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;')
    expect(html).toContain('&lt;script&gt;')
  })

  it('HTML smuggled inside markdown constructs stays escaped too', async () => {
    const html = await render([
      '# <script>alert(1)</script>',
      '- <img src=x onerror=1>',
      '> <svg/onload=1>',
      '**<b>bold</b>**',
      '`<script>in code</script>`',
      '[<script>label</script>](https://example.com)',
    ].join('\n'))

    expect(html).not.toContain('<script')
    expect(html).not.toContain('<img')
    expect(html).not.toContain('<svg')
    expect(html).not.toContain('<b>')
    // The safe link still renders, with its markup label escaped.
    expect(hrefs(html)).toContain('https://example.com')
  })

  it('only http(s) ever becomes an href', async () => {
    const html = await render([
      '[js](javascript:alert(1))',
      '[js2](JaVaScRiPt:alert(1))',
      '[data](data:text/html;base64,PHNjcmlwdD4=)',
      '[vb](vbscript:msgbox)',
      '[file](file:///etc/passwd)',
      '[rel](//evil.example/x)',
      '[blob](blob:https://evil.example/x)',
      '[spaced]( javascript:alert(1))',
      '[ok](https://example.com/a)',
      '[ok2](http://example.com/b)',
    ].join('\n\n'))

    const links = hrefs(html)
    // The invariant: every emitted href is http(s). (The autolinker may pick
    // the https substring out of e.g. `blob:https://…` — that link carries no
    // more privilege than any markdown link, so it is fine.)
    expect(links.length).toBeGreaterThanOrEqual(2)
    for (const href of links) {
      expect(href).toMatch(/^https?:\/\//)
    }
    expect(links).toContain('https://example.com/a')
    expect(links).toContain('http://example.com/b')
    expect(html).not.toContain('href="javascript')
    expect(html).not.toContain('href="data:')
    expect(html).not.toContain('href="file:')
    expect(html).not.toContain('href="vbscript:')
    expect(html).not.toContain('href="//')
    // The rejected ones degrade to visible text, not silent removal.
    expect(html).toContain('[js](javascript:alert(1))')
  })

  it('href values cannot break out of the attribute', async () => {
    // A quote in the URL must not close the attribute and start a new one.
    const html = await render('[x](https://example.com/a"onmouseover="alert(1))')
    expect(html).not.toContain('onmouseover="alert(1)')
    for (const href of hrefs(html)) {
      expect(href.startsWith('https://') || href.startsWith('http://')).toBe(true)
      // Vue must have escaped any quote that made it into the value.
      expect(href).not.toContain('"')
    }
  })

  it('every emitted link is noopener noreferrer', async () => {
    const html = await render('[a](https://example.com) and https://example.org')
    const anchors = html.match(/<a\s[^>]*>/g) ?? []
    expect(anchors.length).toBe(2)
    for (const tag of anchors) {
      expect(tag).toContain('rel="noopener noreferrer"')
      expect(tag).toContain('target="_blank"')
    }
  })

  it('pathological inputs render in bounded time (no ReDoS, no hang)', async () => {
    const cases = [
      // Classic backtracking triggers for emphasis/code scanners.
      '*'.repeat(20_000),
      '`'.repeat(20_000),
      '[' .repeat(10_000) + ']('.repeat(10_000),
      ('**a'.repeat(10_000)),
      // Deep "nesting" and unterminated constructs.
      '> '.repeat(5_000) + 'q',
      '```\n' + 'x\n'.repeat(5_000), // unterminated fence
      ('- item\n').repeat(20_000),
      'a'.repeat(200_000), // over the char cap
    ]
    for (const source of cases) {
      const start = performance.now()
      const html = await render(source)
      expect(performance.now() - start).toBeLessThan(2_000)
      expect(html.length).toBeGreaterThan(0)
    }
  })

  it('tells the reader when the text was truncated', async () => {
    const html = await render('a'.repeat(200_000))
    expect(html).toContain('Description truncated')
  })
})

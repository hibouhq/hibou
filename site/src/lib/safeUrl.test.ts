import { describe, expect, it } from 'vitest'
import { isSafeUrl, safeHref } from './safeUrl'

describe('isSafeUrl', () => {
  it('accepts absolute http(s) URLs', () => {
    expect(isSafeUrl('https://nvd.nist.gov/vuln/detail/CVE-2024-1')).toBe(true)
    expect(isSafeUrl('  HTTP://example.com/x ')).toBe(true)
  })

  it('rejects script, data and relative URLs', () => {
    for (const url of ['javascript:alert(1)', ' JaVaScRiPt:alert(1)', 'data:text/html,<script>', 'vbscript:x', '//evil.example', '/api/v1', 'https:evil', '', null, undefined]) {
      expect(isSafeUrl(url)).toBe(false)
    }
  })
})

describe('safeHref', () => {
  it('returns undefined for unsafe values so no link is rendered', () => {
    expect(safeHref('javascript:alert(1)')).toBeUndefined()
    expect(safeHref(' https://example.com ')).toBe('https://example.com')
  })
})

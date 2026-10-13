import { beforeEach, describe, expect, it } from 'vitest'

import { isSafeReturnPath, rememberReturnTo, takeReturnTo } from './returnTo'

describe('returnTo', () => {
  beforeEach(() => sessionStorage.clear())

  it('accepts in-app paths only', () => {
    expect(isSafeReturnPath('/device?user_code=BCDF-GHJK')).toBe(true)
    expect(isSafeReturnPath('/orgs/github/acme')).toBe(true)
    for (const bad of ['', 'https://evil.example', '//evil.example', '/\\evil.example', '/\t/evil.example', 'device', null, 42]) {
      expect(isSafeReturnPath(bad)).toBe(false)
    }
  })

  it('remembers a path once', () => {
    rememberReturnTo('/device?user_code=BCDF-GHJK')
    expect(takeReturnTo()).toBe('/device?user_code=BCDF-GHJK')
    expect(takeReturnTo()).toBeNull()
  })

  it('ignores the root, the login page and unsafe values', () => {
    for (const path of ['/', '/login', '//evil.example']) {
      rememberReturnTo(path)
      expect(takeReturnTo()).toBeNull()
    }
  })

  it('drops a tampered stored value', () => {
    sessionStorage.setItem('hibou.returnTo', 'https://evil.example')
    expect(takeReturnTo()).toBeNull()
  })
})

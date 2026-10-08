import { describe, expect, it } from 'vitest'

import { visibleRepoTabCount } from './repoTabs'

describe('visibleRepoTabCount', () => {
  it.each([
    [9, 1360],
    [5, 960],
    [3, 640],
    [2, 460],
    [1, 459],
  ])('shows %i tabs at %ipx', (expected, viewportWidth) => {
    expect(visibleRepoTabCount(viewportWidth)).toBe(expected)
  })
})

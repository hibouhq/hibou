export function visibleRepoTabCount(viewportWidth: number) {
  if (viewportWidth >= 1360) {
    return 9
  }
  if (viewportWidth >= 960) {
    return 5
  }
  if (viewportWidth >= 640) {
    return 3
  }
  if (viewportWidth >= 460) {
    return 2
  }
  return 1
}
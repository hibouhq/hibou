// Where to go after sign-in. The OAuth callback always lands on `/`, so the
// router guard remembers the page that sent the user to /login (for example
// the ADR-043 /device approval link) in sessionStorage, which survives the
// round trip to the forge in the same tab. Only in-app paths are accepted, so
// a stored value can never send the user to another site.

const KEY = 'hibou.returnTo'
const MAX_LENGTH = 1024

export function isSafeReturnPath(path: unknown): path is string {
  if (typeof path !== 'string' || path.length === 0 || path.length > MAX_LENGTH) return false
  // One leading slash: "//host" and "/\host" are protocol-relative to browsers.
  if (!path.startsWith('/') || path.startsWith('//') || path.startsWith('/\\')) return false
  // Control characters (tab, newline) are stripped by URL parsers and can turn
  // "/\t/host" into "//host".
  // eslint-disable-next-line no-control-regex
  return !/[\u0000-\u001f\u007f]/.test(path)
}

export function rememberReturnTo(path: string): void {
  if (!isSafeReturnPath(path) || path === '/' || path.startsWith('/login')) return
  try {
    sessionStorage.setItem(KEY, path)
  } catch {
    // Storage blocked: the user lands on the default page instead.
  }
}

/** Returns the remembered path once, then forgets it. */
export function takeReturnTo(): string | null {
  let path: string | null = null
  try {
    path = sessionStorage.getItem(KEY)
    sessionStorage.removeItem(KEY)
  } catch {
    return null
  }
  return isSafeReturnPath(path) ? path : null
}

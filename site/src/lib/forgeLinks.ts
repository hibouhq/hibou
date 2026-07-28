// Deep links back to the forge for a ref, so reviewers can jump from a Hibou
// view straight to the branch, tag or pull request. Path shapes differ per
// forge, so callers pass the provider along with the repository's html_url.

// Providers come from the API as free-form strings; the literals are for
// autocomplete, `string & {}` keeps them from collapsing into plain string.
export type ForgeProvider = 'github' | 'gitlab' | 'gitea' | 'forgejo' | (string & {})

/** Strips the internal ref prefixes so only the branch/tag/PR part is left. */
function refBasename(refName: string): string {
  return refName
    .replace(/^refs\/heads\//, '')
    .replace(/^refs\/tags\//, '')
    .trim()
}

/** Extracts N from refs/pull/N/{head,merge} or refs/merge-requests/N/*. */
export function pullRequestNumber(refName: string): string | null {
  const match = /^refs\/(?:pull|merge-requests)\/(\d+)(?:\/.*)?$/.exec(refName.trim())
  return match ? match[1] : null
}

function encodeRef(ref: string): string {
  // Slashes are legal in branch names (feat/foo) and must stay unescaped in the
  // path, so encode each segment individually.
  return ref.split('/').map(encodeURIComponent).join('/')
}

/**
 * Builds the forge URL for a ref. Returns null when it cannot be constructed —
 * callers render no link rather than a broken one.
 */
export function forgeRefUrl(htmlUrl: string | undefined | null, provider: ForgeProvider, refName: string, refType?: string): string | null {
  const base = (htmlUrl ?? '').trim().replace(/\/+$/, '')
  const ref = refBasename(refName ?? '')
  if (!base || !ref) return null

  const prNumber = pullRequestNumber(refName)
  const isTag = refType === 'tag' || refName.startsWith('refs/tags/')

  switch (provider) {
    case 'gitlab':
      if (prNumber) return `${base}/-/merge_requests/${prNumber}`
      if (isTag) return `${base}/-/tags/${encodeRef(ref)}`
      return `${base}/-/tree/${encodeRef(ref)}`
    case 'gitea':
    case 'forgejo':
      if (prNumber) return `${base}/pulls/${prNumber}`
      if (isTag) return `${base}/src/tag/${encodeRef(ref)}`
      return `${base}/src/branch/${encodeRef(ref)}`
    default:
      // GitHub shape, and the safest guess for unknown forges.
      if (prNumber) return `${base}/pull/${prNumber}`
      if (isTag) return `${base}/releases/tag/${encodeRef(ref)}`
      return `${base}/tree/${encodeRef(ref)}`
  }
}

/** Link to a file's contents at an exact commit. */
export function forgeBlobAtCommitUrl(htmlUrl: string | undefined | null, provider: ForgeProvider, sha: string, filePath: string): string | null {
  const base = (htmlUrl ?? '').trim().replace(/\/+$/, '')
  const commit = (sha ?? '').trim()
  const path = (filePath ?? '').trim().replace(/^\/+/, '')
  if (!base || !commit || !path) return null

  switch (provider) {
    case 'gitlab':
      return `${base}/-/blob/${commit}/${encodeRef(path)}`
    case 'gitea':
    case 'forgejo':
      // Gitea's branch route rejects a raw sha; commit has its own path.
      return `${base}/src/commit/${commit}/${encodeRef(path)}`
    default:
      return `${base}/blob/${commit}/${encodeRef(path)}`
  }
}

/** Link to a specific commit. */
export function forgeCommitUrl(htmlUrl: string | undefined | null, provider: ForgeProvider, sha: string): string | null {
  const base = (htmlUrl ?? '').trim().replace(/\/+$/, '')
  const commit = (sha ?? '').trim()
  if (!base || !commit) return null
  switch (provider) {
    case 'gitlab':
      return `${base}/-/commit/${commit}`
    case 'gitea':
    case 'forgejo':
      return `${base}/commit/${commit}`
    default:
      return `${base}/commit/${commit}`
  }
}

/**
 * Link to a file as of a ref. PR refs go to the pull request's file list
 * instead of a blob: refs/pull/N/head is not a browsable path, and the merge
 * commit a PR snapshot records can be garbage-collected after a rebase.
 */
export function forgeFileUrl(htmlUrl: string | undefined | null, provider: ForgeProvider, refName: string, filePath: string): string | null {
  const base = (htmlUrl ?? '').trim().replace(/\/+$/, '')
  const ref = refBasename(refName ?? '')
  const path = (filePath ?? '').trim().replace(/^\/+/, '')
  if (!base || !ref) return null

  const prNumber = pullRequestNumber(refName)
  if (prNumber) {
    switch (provider) {
      case 'gitlab': return `${base}/-/merge_requests/${prNumber}/diffs`
      case 'gitea':
      case 'forgejo': return `${base}/pulls/${prNumber}/files`
      default: return `${base}/pull/${prNumber}/files`
    }
  }
  if (!path) return null

  switch (provider) {
    case 'gitlab':
      return `${base}/-/blob/${encodeRef(ref)}/${encodeRef(path)}`
    case 'gitea':
    case 'forgejo':
      return `${base}/src/branch/${encodeRef(ref)}/${encodeRef(path)}`
    default:
      return `${base}/blob/${encodeRef(ref)}/${encodeRef(path)}`
  }
}

/** Link to the forge's own base↔head comparison. */
export function forgeCompareUrl(htmlUrl: string | undefined | null, provider: ForgeProvider, base: string, head: string): string | null {
  const repo = (htmlUrl ?? '').trim().replace(/\/+$/, '')
  const from = refBasename(base ?? '')
  const to = refBasename(head ?? '')
  if (!repo || !from || !to) return null

  // A PR head has no meaningful three-dot compare on the forge; the PR page is
  // what the reviewer actually wants.
  const prNumber = pullRequestNumber(head)
  if (prNumber) return forgeRefUrl(htmlUrl, provider, head)

  switch (provider) {
    case 'gitlab':
      return `${repo}/-/compare/${encodeRef(from)}...${encodeRef(to)}`
    case 'gitea':
    case 'forgejo':
      return `${repo}/compare/${encodeRef(from)}...${encodeRef(to)}`
    default:
      return `${repo}/compare/${encodeRef(from)}...${encodeRef(to)}`
  }
}

/** Short human label for a link's tooltip/aria text. */
export function forgeLabel(provider: ForgeProvider): string {
  switch (provider) {
    case 'gitlab': return 'GitLab'
    case 'gitea': return 'Gitea'
    case 'forgejo': return 'Forgejo'
    case 'github': return 'GitHub'
    default: return 'forge'
  }
}

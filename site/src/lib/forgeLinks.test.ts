import { describe, expect, it } from 'vitest'

import { forgeBlobAtCommitUrl, forgeCommitUrl, forgeCompareUrl, forgeFileUrl, forgeRefUrl, pullRequestNumber } from './forgeLinks'

const gh = 'https://github.com/hibouhq/hibou-sample-project'
const gl = 'https://gitlab.com/acme/app'
const fj = 'https://forge.example.com/acme/app'

describe('pullRequestNumber', () => {
  it('reads both PR ref shapes', () => {
    expect(pullRequestNumber('refs/pull/7/head')).toBe('7')
    expect(pullRequestNumber('refs/pull/7/merge')).toBe('7')
    expect(pullRequestNumber('refs/pull/7')).toBe('7')
    expect(pullRequestNumber('refs/merge-requests/42/head')).toBe('42')
  })

  it('ignores branches and tags', () => {
    expect(pullRequestNumber('refs/heads/main')).toBeNull()
    expect(pullRequestNumber('refs/tags/v1.0.0')).toBeNull()
  })
})

describe('forgeRefUrl', () => {
  it('links branches per forge', () => {
    expect(forgeRefUrl(gh, 'github', 'refs/heads/main')).toBe(`${gh}/tree/main`)
    expect(forgeRefUrl(gl, 'gitlab', 'refs/heads/main')).toBe(`${gl}/-/tree/main`)
    expect(forgeRefUrl(fj, 'forgejo', 'refs/heads/main')).toBe(`${fj}/src/branch/main`)
  })

  it('links pull requests per forge', () => {
    expect(forgeRefUrl(gh, 'github', 'refs/pull/7/head')).toBe(`${gh}/pull/7`)
    expect(forgeRefUrl(gl, 'gitlab', 'refs/merge-requests/7/head')).toBe(`${gl}/-/merge_requests/7`)
    expect(forgeRefUrl(fj, 'forgejo', 'refs/pull/7/head')).toBe(`${fj}/pulls/7`)
  })

  it('links tags per forge', () => {
    expect(forgeRefUrl(gh, 'github', 'refs/tags/v1.0.0')).toBe(`${gh}/releases/tag/v1.0.0`)
    expect(forgeRefUrl(gl, 'gitlab', 'refs/tags/v1.0.0')).toBe(`${gl}/-/tags/v1.0.0`)
    expect(forgeRefUrl(fj, 'gitea', 'refs/tags/v1.0.0')).toBe(`${fj}/src/tag/v1.0.0`)
  })

  it('honours an explicit tag refType for bare names', () => {
    expect(forgeRefUrl(gh, 'github', 'v2.0.0', 'tag')).toBe(`${gh}/releases/tag/v2.0.0`)
    expect(forgeRefUrl(gh, 'github', 'v2.0.0', 'branch')).toBe(`${gh}/tree/v2.0.0`)
  })

  it('keeps slashes in branch names as path separators but escapes the rest', () => {
    expect(forgeRefUrl(gh, 'github', 'refs/heads/feat/os images')).toBe(`${gh}/tree/feat/os%20images`)
  })

  it('returns null instead of a broken link', () => {
    expect(forgeRefUrl('', 'github', 'refs/heads/main')).toBeNull()
    expect(forgeRefUrl(undefined, 'github', 'refs/heads/main')).toBeNull()
    expect(forgeRefUrl(gh, 'github', '')).toBeNull()
  })

  it('tolerates a trailing slash on the repo url', () => {
    expect(forgeRefUrl(`${gh}/`, 'github', 'refs/heads/main')).toBe(`${gh}/tree/main`)
  })

  it('falls back to the GitHub shape for unknown forges', () => {
    expect(forgeRefUrl(gh, 'bitbucket', 'refs/heads/main')).toBe(`${gh}/tree/main`)
  })
})

describe('forgeCompareUrl', () => {
  it('builds a three-dot compare for branches', () => {
    expect(forgeCompareUrl(gh, 'github', 'refs/heads/main', 'refs/heads/feat/x')).toBe(`${gh}/compare/main...feat/x`)
    expect(forgeCompareUrl(gl, 'gitlab', 'main', 'topic')).toBe(`${gl}/-/compare/main...topic`)
  })

  it('prefers the PR page when the head is a pull request', () => {
    expect(forgeCompareUrl(gh, 'github', 'refs/heads/main', 'refs/pull/7/head')).toBe(`${gh}/pull/7`)
  })

  it('returns null when either side is missing', () => {
    expect(forgeCompareUrl(gh, 'github', '', 'refs/heads/main')).toBeNull()
  })
})

describe('forgeFileUrl', () => {
  it('links a blob at a branch', () => {
    expect(forgeFileUrl(gh, 'github', 'refs/heads/main', 'go/text.go')).toBe(`${gh}/blob/main/go/text.go`)
    expect(forgeFileUrl(gl, 'gitlab', 'main', 'go/text.go')).toBe(`${gl}/-/blob/main/go/text.go`)
    expect(forgeFileUrl(fj, 'forgejo', 'main', 'go/text.go')).toBe(`${fj}/src/branch/main/go/text.go`)
  })

  it('sends PR refs to the file list, since the merge sha may be gone', () => {
    expect(forgeFileUrl(gh, 'github', 'refs/pull/2/merge', 'go/text.go')).toBe(`${gh}/pull/2/files`)
    expect(forgeFileUrl(gl, 'gitlab', 'refs/merge-requests/2/head', 'go/text.go')).toBe(`${gl}/-/merge_requests/2/diffs`)
    expect(forgeFileUrl(fj, 'gitea', 'refs/pull/2/head', 'go/text.go')).toBe(`${fj}/pulls/2/files`)
  })

  it('tolerates a leading slash on the path', () => {
    expect(forgeFileUrl(gh, 'github', 'main', '/go/text.go')).toBe(`${gh}/blob/main/go/text.go`)
  })

  it('returns null without a path on a branch ref', () => {
    expect(forgeFileUrl(gh, 'github', 'refs/heads/main', '')).toBeNull()
  })
})

describe('forgeBlobAtCommitUrl', () => {
  it('anchors a blob link on the finding\'s lines', () => {
    expect(forgeBlobAtCommitUrl(gh, 'github', 'abc1234', 'go/text.go', { startLine: 31 })).toBe(`${gh}/blob/abc1234/go/text.go#L31`)
    // GitHub repeats the prefix on a range, GitLab does not.
    expect(forgeBlobAtCommitUrl(gh, 'github', 'abc1234', 'go/text.go', { startLine: 31, endLine: 35 })).toBe(`${gh}/blob/abc1234/go/text.go#L31-L35`)
    expect(forgeBlobAtCommitUrl(gl, 'gitlab', 'abc1234', 'go/text.go', { startLine: 31, endLine: 35 })).toBe(`${gl}/-/blob/abc1234/go/text.go#L31-35`)
    // A single-line "range" and a missing line produce no range and no anchor.
    expect(forgeBlobAtCommitUrl(gh, 'github', 'abc1234', 'go/text.go', { startLine: 31, endLine: 31 })).toBe(`${gh}/blob/abc1234/go/text.go#L31`)
    expect(forgeBlobAtCommitUrl(gh, 'github', 'abc1234', 'go/text.go', {})).toBe(`${gh}/blob/abc1234/go/text.go`)
  })

  it('links a blob at an exact commit', () => {
    expect(forgeBlobAtCommitUrl(gh, 'github', 'abc1234', 'go/text.go')).toBe(`${gh}/blob/abc1234/go/text.go`)
    expect(forgeBlobAtCommitUrl(gl, 'gitlab', 'abc1234', 'go/text.go')).toBe(`${gl}/-/blob/abc1234/go/text.go`)
  })

  it('uses the commit route on gitea, which rejects a sha as a branch', () => {
    expect(forgeBlobAtCommitUrl(fj, 'forgejo', 'abc1234', 'go/text.go')).toBe(`${fj}/src/commit/abc1234/go/text.go`)
  })

  it('returns null when sha or path is missing', () => {
    expect(forgeBlobAtCommitUrl(gh, 'github', '', 'go/text.go')).toBeNull()
    expect(forgeBlobAtCommitUrl(gh, 'github', 'abc1234', '')).toBeNull()
  })
})

describe('forgeCommitUrl', () => {
  it('links commits per forge', () => {
    expect(forgeCommitUrl(gh, 'github', 'abc1234')).toBe(`${gh}/commit/abc1234`)
    expect(forgeCommitUrl(gl, 'gitlab', 'abc1234')).toBe(`${gl}/-/commit/abc1234`)
    expect(forgeCommitUrl(fj, 'forgejo', 'abc1234')).toBe(`${fj}/commit/abc1234`)
  })

  it('returns null without a sha', () => {
    expect(forgeCommitUrl(gh, 'github', '')).toBeNull()
  })
})

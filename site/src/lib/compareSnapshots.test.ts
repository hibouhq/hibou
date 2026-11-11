import { describe, expect, it } from 'vitest'
import type { EnhancedRef, Snapshot } from '@/api/client'
import { latestComparableSnapshot, preferredComparisonBase, previousCommitSnapshot, snapshotStatus } from './compareSnapshots'

function branch(name: string): EnhancedRef {
  return { id: name, repo_id: 'repo', name, ref_type: 'branch' }
}

describe('pull request comparison direction', () => {
  const pr: EnhancedRef = { id: 'pr', repo_id: 'repo', name: 'refs/pull/42/head', ref_type: 'pull_request', merge_target_ref_name: 'release' }

  it('uses the PR target branch rather than the repository default', () => {
    expect(preferredComparisonBase([branch('main'), branch('release'), pr], 'main', pr.name)).toBe('release')
  })

  it('uses a PR target even when it is absent from the loaded refs', () => {
    expect(preferredComparisonBase([branch('main'), pr], 'main', pr.name)).toBe('release')
  })

  it('falls back to the repository default when PR target metadata is absent', () => {
    expect(preferredComparisonBase([branch('main'), { ...pr, merge_target_ref_name: undefined }], 'main', pr.name)).toBe('main')
  })

  it('preserves ordinary branch comparison defaults', () => {
    expect(preferredComparisonBase([branch('feature'), branch('main')], 'main', 'feature')).toBe('main')
    expect(preferredComparisonBase([branch('feature')], 'main', '')).toBe('feature')
    expect(preferredComparisonBase([], 'main', '')).toBe('')
  })
})

function snapshot(id: string, commit: string, status = 'complete'): Snapshot {
  return { id, commit_sha: commit, status, ref_id: 'main', created_at: '2026-11-11T12:00:00Z' }
}

describe('comparison snapshot defaults', () => {
  it.each([
    ['complete', 'Build passed'],
    ['active', 'Build active'],
    ['failed', 'Build failed'],
    ['pending', 'Build running'],
    ['processing', 'Processing'],
    ['unexpected', 'Status unknown'],
  ])('labels status %s as %s without treating unknown states as passed', (status, label) => {
    expect(snapshotStatus(snapshot('test', 'a', status)).label).toBe(label)
  })

  it('uses the latest successful snapshot rather than a pending or failed run', () => {
    const snapshots = [
      snapshot('pending', 'c', 'pending'),
      snapshot('failed', 'b', 'failed'),
      snapshot('active', 'a', 'active'),
    ]
    expect(latestComparableSnapshot(snapshots)?.id).toBe('active')
  })

  it('falls back to the latest run when none succeeded, and handles empty history', () => {
    expect(latestComparableSnapshot([snapshot('failed', 'a', 'failed')])?.id).toBe('failed')
    expect(latestComparableSnapshot([])).toBeUndefined()
  })

  it('compares the previous distinct commit, skipping reruns and unsuccessful snapshots', () => {
    const snapshots = [
      snapshot('current', 'c'),
      snapshot('rerun', 'c'),
      snapshot('failed', 'b', 'failed'),
      snapshot('previous', 'b', 'active'),
      snapshot('oldest', 'a'),
    ]
    expect(previousCommitSnapshot(snapshots, 'current')?.id).toBe('previous')
  })

  it('finds an older commit relative to a historical selection, not the latest commit', () => {
    const snapshots = [snapshot('current', 'c'), snapshot('selected', 'b'), snapshot('previous', 'a')]
    expect(previousCommitSnapshot(snapshots, 'selected')?.id).toBe('previous')
  })

  it('does not invent a previous commit for missing, single-commit, or exhausted history', () => {
    expect(previousCommitSnapshot([], 'missing')).toBeUndefined()
    expect(previousCommitSnapshot([snapshot('a', 'same'), snapshot('b', 'same')], 'a')).toBeUndefined()
    expect(previousCommitSnapshot([snapshot('a', 'a')], 'a')).toBeUndefined()
    expect(previousCommitSnapshot([snapshot('a', 'a')], 'missing')).toBeUndefined()
  })
})

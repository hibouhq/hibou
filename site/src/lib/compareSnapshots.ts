import type { EnhancedRef, Snapshot } from '@/api/client'

export const comparisonRoleDescriptions = {
  base: 'The reference snapshot used for comparison. For a pull request, this is usually the branch it targets.',
  head: 'The snapshot you want to evaluate. Results show what changed from the base to this snapshot.',
}

export function preferredComparisonBase(refs: EnhancedRef[], defaultBranch: string, headName: string) {
  const head = refs.find(item => item.name === headName)
  if (head?.ref_type === 'pull_request') {
    return head.merge_target_ref_name || defaultBranch || refs[0]?.name || ''
  }
  return refs.find(item => item.name === defaultBranch)?.name || refs[0]?.name || ''
}

export function snapshotStatus(snapshot: Snapshot) {
  switch (snapshot.status) {
    case 'complete':
      return { label: 'Build passed', dotClass: 'bg-emerald-400', textClass: 'text-emerald-300' }
    case 'active':
      return { label: 'Build active', dotClass: 'bg-emerald-400', textClass: 'text-emerald-300' }
    case 'failed':
      return { label: 'Build failed', dotClass: 'bg-danger', textClass: 'text-danger' }
    case 'pending':
      return { label: 'Build running', dotClass: 'bg-amber-400 animate-pulse', textClass: 'text-amber-300' }
    case 'processing':
      return { label: 'Processing', dotClass: 'bg-amber-400 animate-pulse', textClass: 'text-amber-300' }
    default:
      return { label: 'Status unknown', dotClass: 'bg-gray-500', textClass: 'text-gray-400' }
  }
}

export function latestComparableSnapshot(snapshots: Snapshot[]) {
  return snapshots.find((snapshot) => snapshot.status === 'complete' || snapshot.status === 'active')
    ?? snapshots[0]
}

export function previousCommitSnapshot(snapshots: Snapshot[], currentId: string) {
  const index = snapshots.findIndex((snapshot) => snapshot.id === currentId)
  if (index < 0) return undefined
  const current = snapshots[index]
  return snapshots.slice(index + 1).find((snapshot) =>
    snapshot.commit_sha !== current.commit_sha
    && (snapshot.status === 'complete' || snapshot.status === 'active'),
  )
}

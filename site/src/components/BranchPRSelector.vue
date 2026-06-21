<template>
  <div
    ref="rootRef"
    class="relative flex flex-wrap items-center gap-3"
  >
    <button
      class="inline-flex items-center gap-2 rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-200 transition hover:border-accent/50 hover:text-white"
      type="button"
      @click.stop="isOpen = !isOpen"
    >
      <component
        :is="selectedIcon"
        class="h-4 w-4 shrink-0 text-gray-400"
      />
      <span class="max-w-[12rem] truncate">{{ selectedLabel }}</span>
      <ChevronDown class="h-3.5 w-3.5 text-gray-400" />
    </button>

    <div class="flex items-center gap-3 text-xs text-gray-400">
      <button
        type="button"
        class="flex items-center gap-1 rounded transition hover:text-white"
        title="Switch branches"
        @click.stop="open('branch')"
      >
        <GitBranch class="h-3.5 w-3.5" />
        {{ branchCount }} Branches
      </button>
      <button
        v-if="tagCount > 0"
        type="button"
        class="flex items-center gap-1 rounded transition hover:text-white"
        title="Switch tags"
        @click.stop="open('tag')"
      >
        <Tag class="h-3.5 w-3.5" />
        {{ tagCount }} Tags
      </button>
      <button
        v-if="prCount > 0"
        type="button"
        class="rounded transition hover:text-white"
        title="Switch pull requests"
        @click.stop="open('pull_request')"
      >
        {{ prCount }} Pull Requests
      </button>
    </div>

    <div
      v-if="isOpen"
      class="absolute left-0 top-[calc(100%+0.5rem)] z-30 w-80 max-w-[calc(100vw-2rem)] overflow-hidden rounded-xl border border-surface-border bg-surface-overlay shadow-2xl"
    >
      <div class="flex items-center justify-between border-b border-surface-border-subtle px-4 py-3">
        <h3 class="text-sm font-medium text-gray-100">
          Switch branches/tags
        </h3>
        <button
          class="rounded-md p-1 text-gray-500 transition hover:bg-surface-raised hover:text-white"
          type="button"
          aria-label="Close branch selector"
          @click="isOpen = false"
        >
          <X class="h-4 w-4" />
        </button>
      </div>

      <div class="border-b border-surface-border-subtle p-3">
        <label class="flex items-center gap-3 rounded-md border border-surface-border bg-surface-raised px-3 py-2 text-sm text-gray-300">
          <Search class="h-4 w-4 text-gray-500" />
          <input
            v-model="search"
            type="search"
            placeholder="Search branches, tags, PRs, or commit SHA"
            class="w-full bg-transparent text-sm text-gray-100 placeholder:text-gray-500 focus:outline-none"
          >
        </label>
      </div>

      <div class="flex border-b border-surface-border-subtle px-2">
        <button
          v-for="tab in tabs"
          :key="tab.value"
          class="border-b-2 border-transparent px-3 py-2 text-xs font-medium transition"
          :class="activeTab === tab.value ? 'border-accent text-accent' : 'text-gray-500 hover:text-gray-200'"
          type="button"
          @click="activeTab = tab.value"
        >
          {{ tab.label }}
        </button>
      </div>

      <div class="max-h-96 overflow-auto p-2">
        <div
          v-if="loading"
          class="px-3 py-10 text-sm text-gray-500"
        >
          Loading refs...
        </div>
        <div
          v-else-if="filteredRefs.length === 0"
          class="px-3 py-10 text-sm text-gray-500"
        >
          No refs match the current search.
        </div>
        <button
          v-for="refItem in filteredRefs"
          :key="refItem.id"
          class="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm transition hover:bg-surface-raised"
          :class="[
            isSelected(refItem) ? 'bg-accent-muted/40' : '',
            lifecycleRowClass(refItem),
          ]"
          type="button"
          @click="selectRef(refItem.name)"
        >
          <Check
            v-if="isSelected(refItem)"
            class="h-4 w-4 shrink-0 text-accent"
          />
          <span
            v-else
            class="h-4 w-4 shrink-0"
          />
          <Star
            v-if="refItem.name === defaultBranch"
            class="h-3 w-3 shrink-0 text-warning"
          />
          <component
            :is="refIcon(refItem)"
            class="h-4 w-4 shrink-0 text-gray-400"
          />
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2">
              <span
                class="min-w-0 truncate text-gray-100"
                :class="titleClass(refItem)"
              >{{ refPrimaryLabel(refItem) }}</span>
              <span
                v-if="refItem.name === defaultBranch"
                class="rounded border border-surface-border px-1.5 py-0.5 text-[10px] text-gray-400"
              >
                default
              </span>
              <span
                v-if="refItem.pr_state"
                :class="stateBadgeClass(refItem.pr_state)"
              >
                {{ refItem.pr_state }}
              </span>
            </div>
            <p
              v-if="refSecondaryLabel(refItem)"
              class="mt-0.5 truncate text-[11px] text-gray-500"
            >
              {{ refSecondaryLabel(refItem) }}
            </p>
          </div>
          <span class="ml-auto flex items-center gap-1.5">
            <span
              v-if="refItem.latest_snapshot_status"
              :class="compactStatusClass(refItem.latest_snapshot_status)"
              class="flex items-center gap-1 text-[11px]"
            >
              <span
                class="h-2 w-2 rounded-full"
                :class="statusDotClass(refItem.latest_snapshot_status)"
              />
              {{ capitalizeStatus(refItem.latest_snapshot_status) }}
            </span>
          </span>
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Check, ChevronDown, GitBranch, GitPullRequest, Search, Star, Tag, X } from 'lucide-vue-next'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

import type { EnhancedRef } from '@/api/client'

const props = defineProps<{
  refs: EnhancedRef[]
  selectedRefName: string
  defaultBranch?: string
  loading?: boolean
}>()

const emit = defineEmits<{
  select: [name: string]
}>()

const rootRef = ref<HTMLElement | null>(null)
const isOpen = ref(false)
const search = ref('')
const activeTab = ref<'all' | 'branch' | 'pull_request' | 'tag'>('all')

const tabs = [
  { label: 'All', value: 'all' as const },
  { label: 'Branches', value: 'branch' as const },
  { label: 'Tags', value: 'tag' as const },
  { label: 'Pull Requests', value: 'pull_request' as const },
]

const selectedRef = computed(() => props.refs.find((item) => item.name === props.selectedRefName) ?? null)
const selectedLabel = computed(() => selectedRef.value ? refPrimaryLabel(selectedRef.value) : props.selectedRefName || 'Select ref')
const selectedIcon = computed(() => selectedRef.value ? refIcon(selectedRef.value) : GitBranch)
const branchCount = computed(() => props.refs.filter((item) => item.ref_type === 'branch').length)
const tagCount = computed(() => props.refs.filter((item) => item.ref_type === 'tag').length)

const visiblePullRequestRefs = computed(() => {
  const pullRequestRefs = props.refs.filter((item) => item.ref_type === 'pull_request')

  return pullRequestRefs.filter((item) => {
    const kind = effectivePRRefKind(item)
    const number = effectivePRNumber(item)
    if (!number || (kind !== 'merge' && kind !== 'head')) {
      return true
    }

    return !pullRequestRefs.some((other) => (
      other.id !== item.id
      && effectivePRNumber(other) === number
      && effectivePRRefKind(other) !== 'merge'
    ))
  })
})

const displayRefs = computed(() => {
  const visiblePullRequestIDs = new Set(visiblePullRequestRefs.value.map((item) => item.id))
  return props.refs.filter((item) => item.ref_type !== 'pull_request' || visiblePullRequestIDs.has(item.id))
})

const prCount = computed(() => {
  const seen = new Set<string>()
  let count = 0

  for (const item of visiblePullRequestRefs.value) {
    const number = effectivePRNumber(item)
    const key = number ? `pr:${number}` : `ref:${item.id}`
    if (seen.has(key)) {
      continue
    }
    seen.add(key)
    count += 1
  }

  return count
})

const filteredRefs = computed(() => {
  const query = search.value.trim().toLowerCase()
  const items = displayRefs.value.filter((item) => {
    if (activeTab.value !== 'all' && item.ref_type !== activeTab.value) {
      return false
    }
    if (!query) {
      return true
    }
    return [
      item.name,
      item.pr_title,
      item.pr_number,
      item.pr_source_branch,
      item.merge_target_ref_name,
      effectivePRNumber(item),
      item.latest_commit_sha,
    ].some((value) => (value || '').toLowerCase().includes(query))
  })

  return [...items].sort((left, right) => {
    // Default branch always pinned first.
    const leftDefault = left.name === props.defaultBranch
    const rightDefault = right.name === props.defaultBranch
    if (leftDefault !== rightDefault) {
      return leftDefault ? -1 : 1
    }
    // Group order: branches, then tags, then pull requests.
    const groupDelta = refGroup(left) - refGroup(right)
    if (groupDelta !== 0) {
      return groupDelta
    }
    // PRs sort by number descending (newest PR first).
    if (refGroup(left) === 2) {
      const leftNum = Number.parseInt(effectivePRNumber(left) || '0', 10)
      const rightNum = Number.parseInt(effectivePRNumber(right) || '0', 10)
      if (leftNum !== rightNum) {
        return rightNum - leftNum
      }
    }
    // Otherwise newest first by latest activity, then name for stability.
    const timeDelta = refTimestamp(right) - refTimestamp(left)
    if (timeDelta !== 0) {
      return timeDelta
    }
    return refPrimaryLabel(left).localeCompare(refPrimaryLabel(right))
  })
})

function refGroup(item: EnhancedRef) {
  if (item.ref_type === 'branch') {
    return 0
  }
  if (item.ref_type === 'tag') {
    return 1
  }
  return 2
}

function refTimestamp(item: EnhancedRef) {
  const value = item.latest_snapshot_date || item.updated_at || item.created_at
  const time = value ? new Date(value).getTime() : 0
  return Number.isNaN(time) ? 0 : time
}

onMounted(() => {
  document.addEventListener('click', handleDocumentClick)
})

onBeforeUnmount(() => {
  document.removeEventListener('click', handleDocumentClick)
})

function handleDocumentClick(event: MouseEvent) {
  const target = event.target as Node | null
  if (target && rootRef.value && !rootRef.value.contains(target)) {
    isOpen.value = false
  }
}

function selectRef(name: string) {
  isOpen.value = false
  emit('select', name)
}

// Open the switcher, optionally jumping to a specific tab. Exposed so ref/PR
// info shown elsewhere can deep-open the picker.
function open(tab: typeof activeTab.value = 'all') {
  activeTab.value = tab
  isOpen.value = true
}

defineExpose({ open })

function isSelected(refItem: EnhancedRef) {
  return refItem.name === props.selectedRefName
}

function pullRequestNumber(name: string) {
  const match = name.match(/(?:pull|merge-requests)\/(\d+)/)
  return match?.[1] || ''
}

function effectivePRNumber(refItem: EnhancedRef) {
  return refItem.pr_number?.trim() || pullRequestNumber(refItem.name)
}

function syntheticRefKind(name: string) {
  if (/\/pull\/\d+\/merge$/i.test(name) || /\/merge$/i.test(name)) {
    return 'merge'
  }
  if (/\/pull\/\d+\/head$/i.test(name) || /\/head$/i.test(name)) {
    return 'head'
  }
  return ''
}

function effectivePRRefKind(refItem: EnhancedRef) {
  return refItem.pr_ref_kind?.trim() || syntheticRefKind(refItem.name)
}

function refPrimaryLabel(refItem: EnhancedRef) {
  if (refItem.ref_type === 'pull_request') {
    const number = effectivePRNumber(refItem)
    const kind = effectivePRRefKind(refItem)
    // Fall back to a clean label when the PR has no title (e.g. synthetic
    // refs/pull/N/merge|head refs) instead of dumping the raw ref name.
    const title = refItem.pr_title?.trim() || (kind ? `${kind} ref` : '')
    if (number) {
      return title ? `#${number} ${title}` : `#${number}`
    }
    return title || refItem.name
  }
  return refItem.name
}

function refSecondaryLabel(refItem: EnhancedRef) {
  if (refItem.ref_type !== 'pull_request') {
    return refItem.name === props.defaultBranch ? 'Default branch' : ''
  }
  const source = refItem.pr_source_branch?.trim()
  const target = refItem.merge_target_ref_name?.trim()
  if (source && target) {
    return `${source} → ${target}`
  }
  if (source) {
    return `from ${source}`
  }
  if (target) {
    return `→ ${target}`
  }
  return effectivePRRefKind(refItem) ? 'auto-generated ref' : ''
}

function refIcon(refItem: EnhancedRef) {
  if (refItem.ref_type === 'pull_request') {
    return GitPullRequest
  }
  if (refItem.ref_type === 'tag') {
    return Tag
  }
  return GitBranch
}

function titleClass(refItem: EnhancedRef) {
  return refItem.pr_state === 'merged' ? 'line-through' : ''
}

function lifecycleRowClass(refItem: EnhancedRef) {
  return refItem.pr_state === 'closed' ? 'opacity-50' : ''
}

function statusDotClass(status?: string) {
  switch ((status || '').toLowerCase()) {
    case 'active':
    case 'complete':
      return 'bg-emerald-400'
    case 'failed':
      return 'bg-danger'
    case 'processing':
    case 'pending':
      return 'bg-warning'
    default:
      return 'bg-gray-500'
  }
}

function compactStatusClass(status?: string) {
  switch ((status || '').toLowerCase()) {
    case 'active':
    case 'complete':
      return 'text-emerald-300'
    case 'failed':
      return 'text-danger'
    case 'processing':
    case 'pending':
      return 'text-warning'
    default:
      return 'text-gray-400'
  }
}

function capitalizeStatus(status?: string) {
  if (!status) {
    return 'Unknown'
  }

  return status.charAt(0).toUpperCase() + status.slice(1)
}

function stateBadgeClass(state: string) {
  switch (state) {
    case 'merged':
      return 'rounded-full bg-fuchsia-500/15 px-1.5 py-0.5 text-[10px] font-medium text-fuchsia-300'
    case 'closed':
      return 'rounded-full bg-danger/15 px-1.5 py-0.5 text-[10px] font-medium text-danger'
    default:
      return 'rounded-full bg-accent-muted px-1.5 py-0.5 text-[10px] font-medium text-accent'
  }
}
</script>

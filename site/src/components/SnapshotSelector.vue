<template>
  <div
    ref="rootRef"
    class="relative min-w-0"
    @keydown.esc="handleEscape"
  >
    <button
      ref="triggerRef"
      type="button"
      class="flex w-full items-center gap-2 rounded-lg border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-left transition hover:border-accent/50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-60"
      :aria-label="label"
      aria-haspopup="listbox"
      :aria-controls="listId"
      :aria-expanded="open"
      :disabled="loading || disabled || !snapshots.length"
      :title="selected ? `${selected.commit_sha} · ${snapshotStatus(selected).label} · ${snapshotDetails(selected)}` : undefined"
      @click.stop="toggle"
      @keydown.down.prevent="show"
      @keydown.up.prevent="show"
    >
      <span
        v-if="selected && !loading"
        class="h-2 w-2 shrink-0 rounded-full"
        :class="snapshotStatus(selected).dotClass"
      />
      <span class="min-w-0 flex-1 truncate whitespace-nowrap text-xs leading-5">
        <span
          v-if="loading"
          class="block text-xs text-gray-400"
        >Loading snapshots...</span>
        <template v-else-if="selected">
          <span class="font-mono font-medium text-gray-100">{{ selected.commit_sha.slice(0, 7) }}</span>
          <span class="text-gray-500"> · </span>
          <span :class="snapshotStatus(selected).textClass">{{ snapshotStatus(selected).label }}</span>
          <span class="text-gray-400"> · {{ snapshotDetails(selected) }}</span>
          <span
            v-if="selected.tag"
            class="ml-2 text-sky-300"
          >{{ selected.tag }}</span>
          <span
            v-if="allowLatest && !modelValue"
            class="ml-2 rounded bg-accent/10 px-1.5 py-0.5 text-[10px] text-accent"
          >Latest</span>
        </template>
        <span
          v-else
          class="block text-xs text-gray-400"
        >
          {{ modelValue ? `Selected snapshot ${modelValue.slice(0, 7)}` : 'No snapshots available' }}
        </span>
      </span>
      <ChevronDown
        class="h-3.5 w-3.5 shrink-0 text-gray-500"
        :class="open ? 'rotate-180' : ''"
      />
    </button>

    <div
      v-if="open"
      class="absolute inset-x-0 top-[calc(100%+0.375rem)] z-50 overflow-hidden rounded-xl border border-surface-border bg-surface-overlay shadow-2xl"
    >
      <div class="flex items-center justify-between gap-2 border-b border-surface-border-subtle px-3 py-2">
        <p class="text-xs font-medium text-gray-200">
          Snapshots
        </p>
        <button
          v-if="allowLatest && latest && selected?.id !== latest.id"
          type="button"
          class="inline-flex items-center gap-1.5 rounded px-1 py-0.5 text-xs text-accent transition hover:bg-accent/10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
          :aria-label="`Use latest ${latest.status === 'complete' || latest.status === 'active' ? 'successful' : 'available'} run`"
          :title="`Clear the pinned snapshot and default to ${latest.commit_sha.slice(0, 7)}.`"
          @click="select('')"
        >
          <RefreshCw class="h-3 w-3" />
          Use latest
        </button>
      </div>
      <div
        :id="listId"
        ref="listRef"
        role="listbox"
        :aria-label="`${label} options`"
        class="max-h-60 overflow-y-auto p-1"
        @keydown="handleListKeydown"
      >
        <button
          v-for="snapshot in snapshots"
          :key="snapshot.id"
          type="button"
          role="option"
          :aria-selected="selected?.id === snapshot.id"
          :title="`${snapshot.commit_sha} · ${snapshotStatus(snapshot).label} · ${snapshotDetails(snapshot)}`"
          class="flex w-full items-center gap-2 rounded-md px-2 py-2 text-left transition hover:bg-surface-raised focus-visible:bg-surface-raised focus-visible:outline-none"
          :class="selected?.id === snapshot.id ? 'bg-accent/10' : ''"
          @click="select(snapshot.id)"
        >
          <span
            class="h-2 w-2 shrink-0 rounded-full"
            :class="snapshotStatus(snapshot).dotClass"
          />
          <span class="min-w-0 flex-1 truncate whitespace-nowrap text-xs leading-5">
            <span
              class="font-mono"
              :class="selected?.id === snapshot.id ? 'text-accent' : 'text-gray-100'"
            >{{ snapshot.commit_sha.slice(0, 7) }}</span>
            <span class="text-gray-500"> · </span>
            <span :class="snapshotStatus(snapshot).textClass">{{ snapshotStatus(snapshot).label }}</span>
            <span class="text-gray-400"> · {{ snapshotDetails(snapshot) }}</span>
            <span
              v-if="snapshot.tag"
              class="ml-2 rounded bg-sky-500/10 px-1.5 text-[10px] text-sky-300"
            >{{ snapshot.tag }}</span>
            <span
              v-if="snapshot.id === latest?.id"
              class="ml-2 text-[10px] text-gray-500"
            >Latest {{ snapshot.status === 'complete' || snapshot.status === 'active' ? 'successful' : 'available' }}</span>
          </span>
          <Check
            v-if="selected?.id === snapshot.id"
            class="h-3.5 w-3.5 shrink-0 text-accent"
          />
        </button>
      </div>
    </div>
    <p
      v-if="error"
      role="alert"
      class="mt-1.5 text-xs text-danger"
    >
      {{ error }}
      <button
        type="button"
        class="ml-1 underline"
        @click="emit('retry')"
      >
        Retry
      </button>
    </p>
  </div>
</template>

<script setup lang="ts">
import { Check, ChevronDown, RefreshCw } from 'lucide-vue-next'
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import type { Snapshot } from '@/api/client'
import { latestComparableSnapshot, snapshotStatus } from '@/lib/compareSnapshots'
import { formatDateTime } from '@/lib/datetime'

const props = defineProps<{
  modelValue: string
  snapshots: Snapshot[]
  label: string
  loading?: boolean
  disabled?: boolean
  allowLatest?: boolean
  error?: string
}>()
const emit = defineEmits<{
  'update:modelValue': [id: string]
  retry: []
}>()
const rootRef = ref<HTMLElement | null>(null)
const triggerRef = ref<HTMLButtonElement | null>(null)
const listRef = ref<HTMLElement | null>(null)
const listId = useId()
const open = ref(false)
const latest = computed(() => latestComparableSnapshot(props.snapshots))
const selected = computed(() => props.modelValue
  ? props.snapshots.find(snapshot => snapshot.id === props.modelValue)
  : latest.value)

function snapshotDetails(snapshot: Snapshot) {
  const details = [formatDateTime(snapshot.created_at)]
  if (snapshot.run_number) details.push(`Run #${snapshot.run_number}`)
  else if (snapshot.run_id) details.push(`Run ${snapshot.run_id}`)
  if (snapshot.pr_number) details.push(`PR #${snapshot.pr_number}${snapshot.pr_target_branch ? ` -> ${snapshot.pr_target_branch}` : ''}`)
  if (snapshot.merge_commit_sha) details.push(`Tested as merge ${snapshot.merge_commit_sha.slice(0, 7)}`)
  if (snapshot.base_commit_sha) details.push(`Onto base ${snapshot.base_commit_sha.slice(0, 7)}`)
  return details.join(' · ')
}

async function show() {
  if (props.loading || props.disabled || !props.snapshots.length) return
  open.value = true
  await nextTick()
  const option = listRef.value?.querySelector<HTMLButtonElement>('[aria-selected="true"]')
    ?? listRef.value?.querySelector<HTMLButtonElement>('[role="option"]')
  option?.focus()
}

function toggle() {
  if (open.value) open.value = false
  else void show()
}

function select(id: string) {
  if (id !== props.modelValue && id !== selected.value?.id) emit('update:modelValue', id)
  open.value = false
  triggerRef.value?.focus()
}

function handleEscape(event: KeyboardEvent) {
  if (!open.value) return
  event.stopPropagation()
  open.value = false
  triggerRef.value?.focus()
}

function handleListKeydown(event: KeyboardEvent) {
  if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
  event.preventDefault()
  const options = Array.from(listRef.value?.querySelectorAll<HTMLButtonElement>('[role="option"]') ?? [])
  const index = options.findIndex(option => option === document.activeElement)
  let next = event.key === 'ArrowDown' ? (index + 1) % options.length : (index - 1 + options.length) % options.length
  if (event.key === 'Home') next = 0
  if (event.key === 'End') next = options.length - 1
  options[next]?.focus()
}

function handleDocumentClick(event: MouseEvent) {
  if (rootRef.value && !event.composedPath().includes(rootRef.value)) open.value = false
}

watch(() => [props.snapshots, props.loading, props.disabled], () => { open.value = false })
onMounted(() => document.addEventListener('click', handleDocumentClick, true))
onBeforeUnmount(() => document.removeEventListener('click', handleDocumentClick, true))
</script>

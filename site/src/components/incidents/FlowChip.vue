<template>
  <span
    ref="root"
    class="relative inline-flex"
  >
    <button
      type="button"
      class="inline-flex max-w-[14rem] items-center gap-1.5 rounded-md border px-2 py-1 text-left transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/60"
      :class="chipClass(node)"
      :aria-label="`${node.label}: ${FLOW_STATUS_LABELS[node.status]}`"
      @mouseenter="enter"
      @focus="enter"
      @blur="emit('hover', null)"
      @click="emit('open', node)"
    >
      <Check
        v-if="node.status === 'done'"
        class="h-3 w-3 shrink-0"
      />
      <Minus
        v-else-if="node.status === 'waived'"
        class="h-3 w-3 shrink-0"
      />
      <AlertTriangle
        v-else-if="node.status === 'overdue'"
        class="h-3 w-3 shrink-0"
      />
      <span class="truncate text-xs font-medium leading-tight">{{ node.label }}</span>
      <span
        v-if="meta"
        class="shrink-0 whitespace-nowrap text-[10px] leading-tight opacity-75"
      >{{ meta }}</span>
    </button>

    <div
      v-if="hovered"
      class="pointer-events-none absolute top-full z-20 mt-1.5 w-64 rounded-md border border-surface-border bg-surface-overlay p-2.5 text-xs shadow-lg"
      :class="alignRight ? 'right-0' : 'left-0'"
      role="tooltip"
    >
      <div class="flex items-center justify-between gap-2">
        <span class="font-medium text-gray-100">{{ node.label }}</span>
        <span
          class="shrink-0 rounded-full px-1.5 text-[10px]"
          :class="pillClass(node.status)"
        >{{ FLOW_STATUS_LABELS[node.status] }}{{ node.optional ? ' · optional' : '' }}</span>
      </div>
      <p class="mt-1 text-gray-400">
        {{ node.detail }}
      </p>
      <div class="mt-1.5 space-y-0.5 text-gray-500">
        <div v-if="node.at">
          {{ node.status === 'waived' ? 'Waived' : 'Done' }} <DateTime :value="node.at" /><template v-if="node.by"> by {{ nameOf(node.by) }}</template>
        </div>
        <div v-else-if="node.due">
          Due <CountdownText :at="node.due" />
        </div>
        <div v-if="node.progress">
          {{ node.progress }}
        </div>
      </div>
      <p
        v-if="node.anchor || node.tab !== 'overview'"
        class="mt-1.5 text-[10px] text-gray-600"
      >
        Click to open
      </p>
    </div>
  </span>
</template>

<script setup lang="ts">
import { AlertTriangle, Check, Minus } from 'lucide-vue-next'
import { computed, ref } from 'vue'

import { countdown } from '@/api/incidents'
import DateTime from '@/components/DateTime.vue'
import CountdownText from '@/components/incidents/CountdownText.vue'
import { formatDateTime } from '@/lib/datetime'
import { FLOW_STATUS_LABELS, type FlowNode, type FlowStatus } from '@/lib/incidentFlow'

// One step of the resolution map: a chip coloured by its status with a short
// meta (date, countdown or progress), and the hover card with the sentence,
// the actor and what is left. The card flips to the right edge when the chip
// sits in the right half of the window, so it never overflows.
const props = defineProps<{
  node: FlowNode
  hovered: boolean
  now: number
  names: Record<string, string>
}>()

const emit = defineEmits<{ hover: [id: string | null]; open: [node: FlowNode] }>()

const root = ref<HTMLSpanElement | null>(null)
const alignRight = ref(false)

const meta = computed(() => {
  const node = props.node
  if (node.progress) return node.progress
  if (node.at) return formatDateTime(node.at, props.now)
  if (node.due && (node.status === 'current' || node.status === 'overdue')) return countdown(node.due, props.now).text
  return ''
})

function enter() {
  const rect = root.value?.getBoundingClientRect()
  alignRight.value = rect ? rect.left + rect.width / 2 > window.innerWidth / 2 : false
  emit('hover', props.node.id)
}

function nameOf(id: string) {
  return props.names[id] ?? `${id.slice(0, 8)}…`
}

function chipClass(node: FlowNode) {
  const base = node.optional ? 'border-dashed ' : ''
  switch (node.status) {
    case 'done':
      return base + 'border-ok/50 bg-ok/10 text-green-200 hover:border-ok'
    case 'waived':
      return base + 'border-ok/30 bg-surface-raised text-gray-400 hover:border-ok/60'
    case 'current':
      return base + 'border-accent bg-accent/15 text-gray-100 shadow-[0_0_0_3px_rgba(88,166,255,0.15)] hover:bg-accent/25'
    case 'overdue':
      return base + 'border-danger bg-danger/15 text-red-100 hover:bg-danger/25'
    case 'remaining':
      return base + 'border-surface-border bg-surface-raised text-gray-300 hover:border-gray-500'
    case 'possible':
      return base + 'border-dashed border-surface-border bg-surface-raised/60 text-gray-400 hover:border-gray-500'
    case 'skipped':
      return base + 'border-dashed border-surface-border-subtle bg-transparent text-gray-600 hover:text-gray-500'
  }
}

function pillClass(status: FlowStatus) {
  switch (status) {
    case 'done': case 'waived': return 'bg-ok/15 text-green-300'
    case 'current': return 'bg-accent/15 text-accent'
    case 'overdue': return 'bg-danger/15 text-danger'
    default: return 'bg-surface-raised text-gray-400'
  }
}
</script>

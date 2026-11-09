<template>
  <section
    :class="ui.card"
    aria-label="Resolution map"
  >
    <div class="flex flex-wrap items-start justify-between gap-2">
      <div class="min-w-0">
        <h2 :class="ui.heading">
          Resolution map
        </h2>
        <p class="mt-0.5 text-xs text-gray-500">
          {{ subtitle }}
        </p>
      </div>
      <div class="flex items-center gap-3">
        <ul
          v-if="!collapsed"
          class="hidden flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-gray-500 md:flex"
          aria-label="Legend"
        >
          <li
            v-for="entry in legend"
            :key="entry.status"
            class="flex items-center gap-1"
          >
            <span
              class="inline-block h-2.5 w-2.5 rounded-sm border"
              :class="swatchClass(entry.status)"
            />
            {{ entry.label }}
          </li>
        </ul>
        <button
          type="button"
          :class="ui.secondary"
          :aria-expanded="!collapsed"
          @click="toggle"
        >
          {{ collapsed ? 'Show' : 'Hide' }}
        </button>
      </div>
    </div>

    <div
      v-if="!collapsed"
      ref="container"
      class="relative mt-3"
      @mouseleave="hovered = null"
    >
      <!-- Trunk: what every incident goes through before the paths fork. -->
      <div class="flex flex-wrap items-center gap-y-1.5">
        <template
          v-for="(node, index) in trunk"
          :key="node.id"
        >
          <ChevronRight
            v-if="index > 0"
            class="mx-0.5 h-3.5 w-3.5 shrink-0"
            :class="chevronClass(edgeInto(node.id))"
            aria-hidden="true"
          />
          <FlowChip
            :node="node"
            :hovered="hovered === node.id"
            :now="now"
            :names="names"
            @hover="hover"
            @open="open"
          />
        </template>
      </div>

      <!-- Paths: one row each, forking from the decision. -->
      <ol
        v-if="rows.length > 0"
        class="ml-3 mt-1.5 border-l-2 border-surface-border pl-4"
        aria-label="Paths"
      >
        <li
          v-for="row in rows"
          :key="row.branch.id"
          class="relative -ml-4 flex flex-wrap items-center gap-x-1 gap-y-1.5 rounded-md py-1.5 pl-4 pr-2 transition"
          :class="row.branch.taken ? 'bg-accent/[0.06]' : ''"
        >
          <span
            class="absolute -left-[5px] top-1/2 h-2 w-2 -translate-y-1/2 rounded-full border-2 border-surface-raised"
            :class="row.branch.taken ? 'bg-accent' : row.branch.taken === false ? 'bg-gray-700' : 'bg-gray-500'"
            aria-hidden="true"
          />
          <span
            class="mr-1 w-[11.5rem] shrink-0 truncate text-[11px] leading-tight"
            :class="row.branch.taken === false ? 'text-gray-600' : row.branch.taken ? 'font-medium text-gray-200' : 'text-gray-400'"
            :title="`${row.branch.label}. ${row.branch.detail}`"
          >
            <span class="mr-1 font-mono text-[10px] opacity-70">{{ row.branch.row + 1 }}</span>{{ row.branch.label }}
          </span>
          <template
            v-for="node in row.nodes"
            :key="node.id"
          >
            <ChevronRight
              class="h-3.5 w-3.5 shrink-0"
              :class="chevronClass(edgeInto(node.id, row.branch))"
              aria-hidden="true"
            />
            <FlowChip
              :node="node"
              :hovered="hovered === node.id"
              :now="now"
              :names="names"
              @hover="hover"
              @open="open"
            />
          </template>
        </li>
      </ol>
    </div>
  </section>
</template>

<script setup lang="ts">
import { ChevronRight } from 'lucide-vue-next'
import { computed, nextTick, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { KIND_LABELS, type IncidentDetail } from '@/api/incidents'
import FlowChip from '@/components/incidents/FlowChip.vue'
import { ui } from '@/components/incidents/ui'
import { useNow } from '@/composables/useNow'
import { FLOW_STATUS_LABELS, buildFlow, type FlowBranch, type FlowEdge, type FlowNode, type FlowStatus } from '@/lib/incidentFlow'

// The incident's steps as a map that fits the card at any width: the trunk
// (signal, decision) on top, then one row per path the decision could take,
// its steps as chips that wrap, closing on the shared "Closed" step. Built
// in the browser from the detail; nothing is fetched.
const props = defineProps<{
  detail: IncidentDetail
  names: Record<string, string>
}>()

const COLLAPSED_KEY = 'incident-flow-collapsed'

const route = useRoute()
const router = useRouter()
const now = useNow()
const container = ref<HTMLDivElement | null>(null)
const hovered = ref<string | null>(null)
const collapsed = ref(readCollapsed())

const flow = computed(() => buildFlow(props.detail, now.value))
const byId = computed(() => new Map(flow.value.nodes.map(node => [node.id, node])))
const closeNode = computed(() => byId.value.get('close')!)

const trunk = computed<FlowNode[]>(() => {
  const nodes = [byId.value.get('signal')!, byId.value.get('decision')!]
  if (props.detail.incident.state === 'withdrawn') nodes.push(closeNode.value)
  return nodes
})

interface Row { branch: FlowBranch; nodes: FlowNode[] }

// Each path ends on the shared close step, drawn once per row in the row's
// own state so a path not taken shows a greyed end too.
const rows = computed<Row[]>(() => {
  if (props.detail.incident.state === 'withdrawn') return []
  return flow.value.branches.map((branch) => {
    const nodes = flow.value.nodes.filter(node => node.branch === branch.id).sort((a, b) => a.layer - b.layer)
    const close: FlowNode = {
      ...closeNode.value,
      id: `${branch.id}.close`,
      status: branch.taken === false ? 'skipped' : branch.taken === null ? 'possible' : closeNode.value.status,
    }
    return { branch, nodes: [...nodes, close] }
  })
})

const subtitle = computed(() => {
  const taken = flow.value.branches.find(branch => branch.taken)
  const kind = KIND_LABELS[props.detail.incident.kind]
  if (props.detail.incident.state === 'withdrawn') return `${kind}: withdrawn, no path was taken.`
  if (taken) return `${kind}: path ${taken.row + 1} was taken. The other paths stay greyed.`
  return `${kind}: ${flow.value.branches.length} paths are possible until a decision is recorded.`
})

const legend = computed(() => {
  const present = new Set([...flow.value.nodes, ...rows.value.flatMap(row => row.nodes)].map(node => node.status))
  const order: FlowStatus[] = ['done', 'current', 'overdue', 'remaining', 'possible', 'skipped', 'waived']
  return order.filter(status => present.has(status)).map(status => ({ status, label: FLOW_STATUS_LABELS[status] }))
})

// The edge arriving at a node; a row's close chip takes its branch's last edge.
function edgeInto(id: string, branch?: FlowBranch): FlowEdge['status'] {
  if (branch && id === `${branch.id}.close`) {
    const last = rows.value.find(row => row.branch.id === branch.id)?.nodes.at(-2)
    return flow.value.edges.find(edge => edge.to === 'close' && edge.from === (last?.id ?? 'decision'))?.status ?? 'remaining'
  }
  return flow.value.edges.find(edge => edge.to === id)?.status ?? 'remaining'
}

function chevronClass(status: FlowEdge['status']) {
  switch (status) {
    case 'done': return 'text-ok/70'
    case 'active': return 'text-accent'
    case 'remaining': return 'text-gray-500'
    case 'possible': return 'text-gray-600'
    case 'skipped': return 'text-gray-700'
  }
}

function swatchClass(status: FlowStatus) {
  switch (status) {
    case 'done': return 'border-ok/50 bg-ok/30'
    case 'waived': return 'border-ok/30 bg-transparent'
    case 'current': return 'border-accent bg-accent/30'
    case 'overdue': return 'border-danger bg-danger/30'
    case 'remaining': return 'border-surface-border bg-surface-raised'
    case 'possible': return 'border-dashed border-surface-border bg-transparent'
    case 'skipped': return 'border-dashed border-surface-border-subtle bg-transparent'
  }
}

function hover(id: string | null) {
  hovered.value = id
}

async function open(node: FlowNode) {
  const tab = node.tab === 'overview' ? undefined : node.tab
  if (route.query.tab !== tab) {
    await router.replace({ query: { ...route.query, tab } })
    await nextTick()
  }
  if (!node.anchor) return
  const target = document.getElementById(node.anchor)
  if (!target) return
  target.scrollIntoView({ behavior: 'smooth', block: 'center' })
  target.classList.add('ring-2', 'ring-accent/60')
  window.setTimeout(() => target.classList.remove('ring-2', 'ring-accent/60'), 1600)
}

function readCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSED_KEY) === '1'
  } catch {
    return false
  }
}

function toggle() {
  collapsed.value = !collapsed.value
  try {
    localStorage.setItem(COLLAPSED_KEY, collapsed.value ? '1' : '0')
  } catch {
    // Storage unavailable: the choice lasts for this page only.
  }
}
</script>

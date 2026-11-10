<template>
  <div :class="compact ? 'flex min-w-0 max-w-full items-center gap-2 text-xs' : 'space-y-2 text-xs'">
    <RepositoryIntegration
      v-if="!compact"
      :mode="integration ?? sca?.integration"
    />
    <div
      class="flex min-w-0 flex-wrap items-center gap-2"
      :title="tooltip"
    >
      <span class="inline-flex min-w-0 items-center gap-1.5 font-medium text-gray-300">
        <Package
          class="h-3.5 w-3.5 shrink-0 text-gray-500"
          aria-hidden="true"
        />
        {{ inventorySource(sca, components) }}
      </span>
      <span
        class="rounded border px-1.5 py-0.5 text-[11px]"
        :class="statusClass"
        role="status"
      >
        {{ scaLabel(sca, enrolled, components, findings) }}
      </span>
    </div>
    <template v-if="!compact">
      <p
        v-if="sca?.state === 'partial'"
        class="text-gray-400"
      >
        Known results only; dependency coverage or version evidence is incomplete.
      </p>
      <details
        v-if="sca?.detail"
        class="max-w-3xl rounded-lg border border-surface-border-subtle px-3 py-2"
      >
        <summary class="cursor-pointer font-medium text-gray-300 hover:text-white">
          Analysis details<span
            v-if="detailItems.length > 1"
            class="ml-1 text-gray-500"
          >({{ detailItems.length }})</span>
        </summary>
        <ul class="mt-2 max-h-60 space-y-2 overflow-y-auto text-gray-400">
          <li
            v-for="(detail, index) in detailItems"
            :key="index"
            class="break-words leading-relaxed [overflow-wrap:anywhere]"
          >
            {{ detail }}
          </li>
        </ul>
      </details>
      <div class="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-gray-500">
        <span
          v-if="inventoryCommit"
          class="font-mono"
          :title="inventoryCommit"
        >Inventory {{ inventoryCommit.slice(0, 12) }}</span>
        <span
          v-if="sca?.head_commit_sha && sca.head_commit_sha !== inventoryCommit"
          class="font-mono"
          :title="sca.head_commit_sha"
        >Head {{ sca.head_commit_sha.slice(0, 12) }}</span>
        <span v-if="sca?.last_assessed">Last analysis {{ new Date(sca.last_assessed).toLocaleString() }}</span>
        <span v-if="sca?.last_attempt">Last attempt {{ new Date(sca.last_attempt).toLocaleString() }}</span>
        <span v-if="sca?.enabled && !sca.on_push">Automatic push monitoring off</span>
      </div>
      <p
        v-if="sca?.state === 'not_monitored' && !enrolled && !canManage"
        class="text-gray-400"
      >
        Not monitored — ask an organization admin.
      </p>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Package } from 'lucide-vue-next'
import RepositoryIntegration from './RepositoryIntegration.vue'
import type { ScaCoverage } from '@/api/client'
import { hasInventory, inventorySource, inventorySourceTitle, scaLabel, scaPending } from '@/lib/sca'

const props = withDefaults(defineProps<{
  sca?: ScaCoverage; integration?: ScaCoverage['integration']; enrolled?: boolean; canManage?: boolean; compact?: boolean; components?: number; findings?: number
}>(), { sca: undefined, integration: undefined, enrolled: true, canManage: false, compact: false, components: 0, findings: 0 })
const detailItems = computed(() => props.sca?.detail?.split(';').map(detail => detail.trim()).filter(Boolean) ?? [])
const inventoryCommit = computed(() => props.sca?.inventory_commit_sha
  || (props.sca?.has_inventory === true || (props.sca?.has_inventory === undefined && hasInventory(props.sca, props.components)) ? props.sca?.commit_sha : undefined))
const tooltip = computed(() => [
  inventorySourceTitle(props.sca, props.components),
  props.sca?.detail,
  inventoryCommit.value ? `Inventory commit: ${inventoryCommit.value}` : '',
  props.sca?.head_commit_sha ? `Current head: ${props.sca.head_commit_sha}` : '',
  props.sca?.previous_results ? 'Counts include the latest available results; they may predate the current head.' : '',
  props.sca?.state === 'not_monitored' && !props.enrolled && !props.canManage ? 'Ask an organization admin to enable monitoring.' : '',
].filter(Boolean).join('\n'))
const statusClass = computed(() => scaPending(props.sca)
  ? 'border-accent/25 bg-accent/5 text-accent'
  : ['failed', 'outdated'].includes(props.sca?.state ?? '')
    ? 'border-amber-500/20 bg-amber-500/5 text-amber-200/90'
    : 'border-surface-border-subtle bg-surface-overlay/40 text-gray-400')
</script>

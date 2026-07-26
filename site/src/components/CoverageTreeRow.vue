<template>
  <div>
    <button
      type="button"
      class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm transition hover:bg-white/5"
      :style="{ paddingLeft: `${12 + depth * 20}px` }"
      @click="onClick"
    >
      <component
        :is="rowIcon"
        class="h-3.5 w-3.5 shrink-0"
        :class="node.isFile ? 'text-gray-500' : 'text-accent/80'"
      />
      <span
        class="min-w-0 truncate font-mono text-xs"
        :class="node.isFile ? 'text-gray-200' : 'text-gray-100'"
      >{{ node.name }}<span
        v-if="!node.isFile"
        class="text-gray-500"
      >/</span></span>

      <span
        v-if="!node.isFile"
        class="shrink-0 text-[10px] text-gray-500"
      >{{ node.fileCount }} files</span>

      <span class="ml-auto flex shrink-0 items-center gap-3">
        <span
          v-if="showDelta && node.delta !== null"
          class="text-xs font-medium tabular-nums"
          :class="deltaClass"
        >{{ deltaLabel }}</span>
        <span class="hidden text-xs tabular-nums text-gray-500 sm:inline">{{ node.covered }}/{{ node.valid }}</span>
        <span
          class="w-14 text-right text-xs font-semibold tabular-nums"
          :style="{ color: coverageRateColor(node.rate) }"
        >
          {{ formatCoverageRate(node.rate) }}
        </span>
        <span class="hidden h-1.5 w-24 rounded-full bg-surface-overlay sm:block">
          <span
            class="block h-1.5 rounded-full"
            :style="{ width: `${Math.max(0, Math.min(100, (node.rate ?? 0) * 100))}%`, backgroundColor: coverageRateColor(node.rate) }"
          />
        </span>
      </span>
    </button>

    <template v-if="!node.isFile && isExpanded">
      <CoverageTreeRow
        v-for="child in node.children"
        :key="child.path"
        :node="child"
        :depth="depth + 1"
        :expanded="expanded"
        :show-delta="showDelta"
        @toggle="(path) => emit('toggle', path)"
        @select-file="(path) => emit('select-file', path)"
      />
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { ChevronDown, ChevronRight, FileCode2 } from 'lucide-vue-next'

import { coverageRateColor, formatCoverageRate, type CoverageTreeNode } from '@/lib/coverageTree'

const props = defineProps<{
  node: CoverageTreeNode
  depth: number
  expanded: Set<string>
  showDelta: boolean
}>()

const emit = defineEmits<{
  (e: 'toggle', path: string): void
  (e: 'select-file', path: string): void
}>()

const isExpanded = computed(() => props.expanded.has(props.node.path))

const rowIcon = computed(() => {
  if (props.node.isFile) return FileCode2
  return isExpanded.value ? ChevronDown : ChevronRight
})

const deltaLabel = computed(() => {
  const delta = props.node.delta
  if (delta === null) return ''
  const percent = delta * 100
  const sign = percent > 0 ? '+' : ''
  return `${sign}${percent.toFixed(1)}%`
})

const deltaClass = computed(() => {
  const delta = props.node.delta ?? 0
  if (delta > 0.0001) return 'text-[#3fb950]'
  if (delta < -0.0001) return 'text-[#f85149]'
  return 'text-gray-500'
})

function onClick() {
  if (props.node.isFile) {
    emit('select-file', props.node.path)
    return
  }
  emit('toggle', props.node.path)
}
</script>

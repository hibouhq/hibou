<template>
  <div>
    <div class="flex items-center gap-2 border-b border-surface-border-subtle px-3 py-1.5">
      <button
        type="button"
        class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-gray-400 transition hover:bg-white/5 hover:text-white"
        @click="expandAll"
      >
        <ChevronsUpDown class="h-3 w-3" /> Expand all
      </button>
      <button
        type="button"
        class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-gray-400 transition hover:bg-white/5 hover:text-white"
        @click="collapseAll"
      >
        <ChevronsDownUp class="h-3 w-3" /> Collapse all
      </button>
    </div>
    <div class="divide-y divide-surface-border-subtle">
      <CoverageTreeRow
        v-for="child in tree.children"
        :key="child.path"
        :node="child"
        :depth="0"
        :expanded="expanded"
        :show-delta="showDelta"
        @toggle="toggle"
        @select-file="(path) => emit('select-file', path)"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
// Code tree where folders carry coverage computed from their descendants;
// in a PR context each row also shows its aggregated delta.
import { computed, ref, watch } from 'vue'
import { ChevronsDownUp, ChevronsUpDown } from 'lucide-vue-next'

import CoverageTreeRow from '@/components/CoverageTreeRow.vue'
import { buildCoverageTree, type CoverageTreeFile, type CoverageTreeNode } from '@/lib/coverageTree'

const props = defineProps<{ files: CoverageTreeFile[] }>()
const emit = defineEmits<{ (e: 'select-file', path: string): void }>()

const expanded = ref(new Set<string>())

const tree = computed(() => buildCoverageTree(props.files))

const showDelta = computed(() => props.files.some((file) => typeof file.delta === 'number'))

watch(
  () => props.files,
  () => {
    expanded.value = new Set()
  },
)

function toggle(path: string) {
  const next = new Set(expanded.value)
  if (next.has(path)) {
    next.delete(path)
  } else {
    next.add(path)
  }
  expanded.value = next
}

function expandAll() {
  const next = new Set<string>()
  const visit = (node: CoverageTreeNode) => {
    if (!node.isFile && node.path) next.add(node.path)
    node.children.forEach(visit)
  }
  visit(tree.value)
  expanded.value = next
}

function collapseAll() {
  expanded.value = new Set()
}
</script>

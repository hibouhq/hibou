<template>
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
</template>

<script setup lang="ts">
// Code tree where folders carry coverage computed from their descendants;
// in a PR context each row also shows its aggregated delta.
import { computed, ref, watch } from 'vue'

import CoverageTreeRow from '@/components/CoverageTreeRow.vue'
import { buildCoverageTree, type CoverageTreeFile } from '@/lib/coverageTree'

const props = defineProps<{ files: CoverageTreeFile[] }>()
const emit = defineEmits<{ (e: 'select-file', path: string): void }>()

const expanded = ref(new Set<string>())

const tree = computed(() => buildCoverageTree(props.files))

const showDelta = computed(() => props.files.some((file) => typeof file.delta === 'number'))

// Expand the first level by default; reset when the file set changes.
watch(
  tree,
  (root) => {
    expanded.value = new Set(root.children.filter((child) => !child.isFile).map((child) => child.path))
  },
  { immediate: true },
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
</script>

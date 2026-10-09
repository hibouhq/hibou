<template>
  <span
    v-if="visible.length > 0"
    class="inline-flex flex-wrap items-center gap-1"
  >
    <component
      :is="clickable ? 'button' : 'span'"
      v-for="item in visible"
      :key="item.id"
      :type="clickable ? 'button' : undefined"
      class="inline-flex items-center rounded border px-1.5 py-px font-mono text-[11px] leading-4"
      :class="[
        item.deprecated ? 'border-surface-border text-gray-500 line-through decoration-gray-600' : 'border-sky-500/30 bg-sky-500/10 text-sky-200',
        clickable ? 'transition hover:border-sky-400/60 hover:text-sky-100' : '',
      ]"
      :title="tooltip(item)"
      :aria-label="tooltip(item)"
      @click.stop="clickable && $emit('select', item.id)"
    >
      CWE-{{ item.id }}
    </component>
    <span
      v-if="hidden > 0"
      class="text-[11px] text-gray-500"
      :title="hiddenTooltip"
    >+{{ hidden }}</span>
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

import type { CWESetRef } from '@/api/client'
import { displaySets } from '@/lib/cweCatalog'

// A CWE as any response carries it: at least the id and title, sometimes the
// category and named sets (finding detail, CWE list).
interface ChipCWE {
  id: number
  name?: string
  deprecated?: boolean
  category?: CWESetRef
  sets?: CWESetRef[]
}

const props = withDefaults(defineProps<{
  cwes?: ChipCWE[]
  // Rows show a couple of chips and "+n"; detail views show all.
  max?: number
  clickable?: boolean
}>(), {
  cwes: () => [],
  max: Number.POSITIVE_INFINITY,
  clickable: false,
})

defineEmits<{
  (event: 'select', id: number): void
}>()

const visible = computed(() => props.cwes.slice(0, props.max))
const hidden = computed(() => Math.max(0, props.cwes.length - visible.value.length))
const hiddenTooltip = computed(() => props.cwes.slice(visible.value.length).map(tooltip).join('\n'))

// The title is the point: a bare CWE-1321 tells a developer nothing.
function tooltip(item: ChipCWE): string {
  const lines = [item.name ? `CWE-${item.id} · ${item.name}` : `CWE-${item.id}`]
  if (item.category?.name) lines.push(`Category: ${item.category.name}`)
  for (const set of displaySets(item.sets)) lines.push(set.rank ? `${set.name} #${set.rank}` : set.name)
  if (item.deprecated) lines.push('Deprecated in the CWE catalog')
  return lines.join('\n')
}
</script>

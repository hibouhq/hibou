<template>
  <span
    class="inline-flex cursor-help items-center rounded px-1.5 py-0.5 font-mono text-[11px] font-semibold"
    :class="priorityClass"
    :title="PRIORITY_DESCRIPTIONS[priority]"
  >
    {{ priority }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

import { PRIORITY_DESCRIPTIONS } from '@/api/incidents'

const props = defineProps<{ priority: string }>()

const priorityClass = computed(() => {
  switch (props.priority) {
    case 'P1':
      return 'bg-danger/15 text-red-300'
    case 'P2':
      return 'bg-warn/15 text-amber-300'
    default:
      return 'bg-surface-overlay text-gray-400'
  }
})
</script>

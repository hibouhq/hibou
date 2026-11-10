<template>
  <span
    class="inline-flex w-fit items-center gap-1.5 whitespace-nowrap rounded-md border px-2 py-1 text-[11px] font-medium"
    :class="mode === 'ci_integrated'
      ? 'border-accent/30 bg-accent/10 text-accent'
      : mode === 'monitored'
        ? 'border-surface-border bg-surface-overlay text-gray-300'
        : 'border-surface-border-subtle text-gray-500'"
    :title="description"
  >
    <Workflow
      v-if="mode === 'ci_integrated'"
      class="h-3.5 w-3.5"
      aria-hidden="true"
    />
    <ScanSearch
      v-else-if="mode === 'monitored'"
      class="h-3.5 w-3.5"
      aria-hidden="true"
    />
    {{ label }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { ScanSearch, Workflow } from 'lucide-vue-next'
import type { ScaCoverage } from '@/api/client'

const props = defineProps<{ mode?: ScaCoverage['integration'] }>()
const label = computed(() => props.mode === 'ci_integrated' ? 'CI integrated'
  : props.mode === 'monitored' ? 'Monitored'
    : props.mode === 'not_monitored' ? 'Not connected' : 'Integration unknown')
const description = computed(() => props.mode === 'ci_integrated'
  ? 'Hibou has received CI analysis uploads for this repository, such as coverage, tests, SARIF or SBOMs. This does not guarantee that the current CI run is healthy or complete.'
  : props.mode === 'monitored'
    ? 'Repository monitoring only: no CI analysis uploads have been recorded. Server-side dependency extraction does not establish a CI integration.'
    : props.mode === 'not_monitored'
      ? 'Repository discovered on the forge; monitoring and CI uploads have not been enabled.'
      : 'This server did not report whether CI analysis uploads have been received.')
</script>

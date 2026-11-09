<template>
  <span
    class="inline-flex cursor-help items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium"
    :class="PILL_CLASSES[statusTone(status)]"
    :title="description"
  >
    {{ label || humanize(status) }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

import { STATE_DESCRIPTIONS, STATUS_DESCRIPTIONS, type IncidentState } from '@/api/incidents'
import { humanize, PILL_CLASSES, statusTone } from '@/lib/incidentView'

// One pill for incident states, scope rows, actions and deliveries: the tone
// follows the status, the text defaults to the status in words, the hover
// says what it means.
const props = withDefaults(defineProps<{ status: string; label?: string }>(), { label: '' })

const description = computed(() => STATE_DESCRIPTIONS[props.status as IncidentState] ?? STATUS_DESCRIPTIONS[props.status])
</script>

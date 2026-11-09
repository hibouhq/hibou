<template>
  <time
    :datetime="at ?? undefined"
    class="tabular-nums"
    :class="state.overdue ? 'font-medium text-danger' : 'text-gray-200'"
    :title="at ? dateTitle(at) : undefined"
  >{{ state.text }}</time>
</template>

<script setup lang="ts">
import { computed } from 'vue'

import { countdown } from '@/api/incidents'
import { useNow } from '@/composables/useNow'
import { dateTitle } from '@/lib/datetime'

// A live countdown to a due time, computed in the browser every second; red
// once overdue. The hover gives the date.
const props = withDefaults(defineProps<{ at: string | null }>(), { at: null })

const now = useNow()
const state = computed(() => countdown(props.at, now.value))
</script>

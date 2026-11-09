<template>
  <time
    v-if="value"
    :datetime="value"
    :title="dateTitle(value)"
  >{{ formatDateTime(value) }}</time>
  <span v-else>{{ placeholder }}</span>
</template>

<script setup lang="ts">
import { dateTitle, formatDateTime } from '@/lib/datetime'

// A short date ("Oct 24, 03:23 PM", the year only when not this year); the
// hover gives "4 days ago" and the full date.
withDefaults(defineProps<{ value: string | null | undefined; placeholder?: string }>(), { placeholder: '—' })
</script>

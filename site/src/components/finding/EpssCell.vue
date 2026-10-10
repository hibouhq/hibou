<template>
  <span
    v-if="epss"
    class="whitespace-nowrap tabular-nums"
    :class="epss.percentile >= 0.95 ? 'font-medium text-orange-300' : 'text-gray-300'"
    :title="`${formatEPSS(epss.score)} chance of exploitation in the next 30 days (${epss.cve_id})\n${formatPercentile(epss.percentile)} percentile of all scored CVEs${epss.date ? `\nScored ${epss.date}` : ''}`"
  >{{ formatEPSS(epss.score) }}</span>
  <span
    v-else
    class="text-gray-600"
  >–</span>
</template>

<script setup lang="ts">
import type { EPSSScore } from '@/api/client'
import { formatEPSS, formatPercentile } from '@/lib/riskMetrics'

defineProps<{ epss?: EPSSScore }>()
</script>

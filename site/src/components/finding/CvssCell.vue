<template>
  <span
    class="inline-flex items-baseline gap-1 whitespace-nowrap tabular-nums"
    :title="title"
  >
    <span
      v-if="score !== undefined"
      class="font-medium"
      :class="bandTextClass(score)"
    >{{ score.toFixed(1) }}</span>
    <span
      v-else
      class="text-gray-600"
    >–</span>
    <!-- Raters fall in different severity bands: visible without hovering,
         hover says who (ADR-038 §7). -->
    <span
      v-if="finding.ratings_disagree"
      class="text-[10px] text-amber-300"
      role="img"
      aria-label="Raters disagree on this vulnerability's severity"
    >◆</span>
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

import type { Vulnerability } from '@/api/client'
import { bandTextClass, cvssVersionLabel, raterName, ratingsSummary } from '@/lib/riskMetrics'

const props = defineProps<{ finding: Vulnerability }>()

const score = computed(() => props.finding.cvss?.score)

const title = computed(() => {
  const lines: string[] = []
  const cvss = props.finding.cvss
  if (cvss?.score !== undefined) {
    const by = props.finding.rated_by ? ` · ${raterName(props.finding.rated_by)}` : ''
    lines.push(`CVSS ${cvssVersionLabel(cvss.version)} ${cvss.score.toFixed(1)}${by}`)
    if (cvss.vector) lines.push(cvss.vector)
  } else if (props.finding.severity === 'unknown') {
    lines.push('No source rates this vulnerability yet')
  }
  if (props.finding.ratings_disagree) {
    lines.push('', 'Raters disagree:', ratingsSummary(props.finding.ratings))
  }
  return lines.join('\n') || undefined
})
</script>

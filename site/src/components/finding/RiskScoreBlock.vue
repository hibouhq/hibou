<template>
  <FindingSection
    v-if="visible"
    title="Score"
    boxed
  >
    <!-- The verdict: the severity gates and sorting use, and who gave it. -->
    <div class="flex flex-wrap items-baseline gap-x-3 gap-y-1">
      <span
        class="text-2xl font-semibold tabular-nums"
        :class="bandTextClass(headlineScore ?? finding.severity)"
      >{{ headlineScore !== undefined ? headlineScore.toFixed(1) : severityLabel }}</span>
      <span class="text-xs text-gray-400">
        <template v-if="headlineScore !== undefined">
          CVSS{{ finding.cvss?.version ? ` v${cvssVersionLabel(finding.cvss.version)}` : '' }} · {{ severityLabel }}
        </template>
        <template v-else-if="finding.severity === 'unknown'">
          No source rates this vulnerability yet
        </template>
        <template v-else>severity</template>
        <template v-if="finding.rated_by"> · rated by {{ raterName(finding.rated_by) }}<span v-if="distroRated"> (the distribution's own rating)</span></template>
      </span>
    </div>
    <p
      v-if="finding.severity_override_reason"
      class="mt-1 text-[11px] text-gray-500"
    >
      Severity overridden here: {{ finding.severity_override_reason }}
    </p>

    <!-- How likely: EPSS beside CVSS, never merged into it (ADR-038 §5). -->
    <div
      v-if="finding.epss"
      class="mt-3 flex flex-wrap items-baseline gap-x-2 text-xs"
    >
      <span class="uppercase tracking-[0.14em] text-gray-500">EPSS</span>
      <span
        class="text-sm font-semibold tabular-nums"
        :class="finding.epss.percentile >= 0.95 ? 'text-orange-300' : 'text-gray-200'"
      >{{ formatEPSS(finding.epss.score) }}</span>
      <span class="text-gray-400">chance of exploitation in the next 30 days · {{ formatPercentile(finding.epss.percentile) }} percentile</span>
      <span
        v-if="finding.epss.date"
        class="text-gray-600"
      >· scored {{ finding.epss.date }}</span>
    </div>

    <!-- Who rated what, always visible: hover is the quick look in the list,
         this is the full answer (ADR-038 §7). -->
    <div
      v-if="ratings.length > 0"
      class="mt-3 border-t border-surface-border-subtle pt-2"
    >
      <p class="mb-1 text-[11px] uppercase tracking-[0.14em] text-gray-500">
        Ratings
        <span
          v-if="finding.ratings_disagree"
          class="ml-1 normal-case tracking-normal text-amber-300"
        >◆ raters disagree</span>
      </p>
      <ul class="space-y-1">
        <li
          v-for="rating in ratings"
          :key="`${rating.rater}-${rating.version ?? 'label'}`"
          class="grid grid-cols-[1rem_7rem_2.75rem_4.5rem_minmax(0,1fr)] items-baseline gap-x-2 text-xs"
          :class="rating.used ? 'text-white' : 'text-gray-300'"
        >
          <span
            class="text-accent"
            :title="rating.used ? 'The rating this finding uses' : undefined"
          >{{ rating.used ? '▸' : '' }}</span>
          <span class="truncate">{{ raterName(rating.rater) }}</span>
          <span
            class="tabular-nums"
            :class="bandTextClass(rating.score)"
          >{{ rating.score !== undefined ? rating.score.toFixed(1) : '—' }}</span>
          <span :class="bandTextClass(rating.severity)">{{ rating.severity }}<span
            v-if="rating.label && rating.score !== undefined && rating.label !== bandOf(rating.score)"
            class="text-gray-500"
            title="The rater's own severity word, which wins over the band of its score"
          > (label)</span></span>
          <span class="min-w-0">
            <button
              v-if="rating.vector"
              type="button"
              class="break-all text-left font-mono text-[11px] text-gray-500 underline decoration-gray-700 underline-offset-2 hover:text-accent"
              title="Explain this vector: every metric and what it means"
              @click="explained = { vector: rating.vector, title: `${raterName(rating.rater)} rating` }"
            >{{ rating.vector }}</button>
            <span
              v-else
              class="text-[11px] text-gray-600"
            >label only, no CVSS score</span>
            <span
              v-if="vectorDifferences(usedRating, rating).length"
              class="ml-1 text-[11px] text-amber-300"
            >differs: {{ vectorDifferences(usedRating, rating).join(' ') }}</span>
          </span>
        </li>
      </ul>
    </div>
    <CvssCalculatorDialog
      :vector="explained?.vector ?? ''"
      :title="explained?.title"
      @close="explained = null"
    />
  </FindingSection>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'

import type { FindingRating, Vulnerability } from '@/api/client'
import CvssCalculatorDialog from '@/components/cvss/CvssCalculatorDialog.vue'
import FindingSection from '@/components/finding/FindingSection.vue'
import {
  bandTextClass,
  cvssBand,
  cvssVersionLabel,
  formatEPSS,
  formatPercentile,
  raterName,
  vectorDifferences,
} from '@/lib/riskMetrics'

// The drawer's answer to "how bad, how likely, and says who" (ADR-038 §7).
const props = defineProps<{ finding: Vulnerability }>()

// The vector being explained in the calculator dialog.
const explained = ref<{ vector: string; title: string } | null>(null)

const DISTRO_RATERS = new Set(['redhat', 'debian', 'ubuntu', 'oracle', 'alma', 'rocky', 'amazon', 'azure', 'cbl-mariner', 'photon', 'suse', 'fedora'])

const headlineScore = computed(() => props.finding.cvss?.score)
const severityLabel = computed(() => props.finding.severity)
const distroRated = computed(() => DISTRO_RATERS.has(props.finding.rated_by ?? ''))

// Used rating first, then by strength, so the eye lands on the verdict.
const ratings = computed<FindingRating[]>(() =>
  [...(props.finding.ratings ?? [])].sort((a, b) =>
    Number(Boolean(b.used)) - Number(Boolean(a.used)) || (b.score ?? -1) - (a.score ?? -1) || a.rater.localeCompare(b.rater)))
const usedRating = computed(() => ratings.value.find(rating => rating.used))

const visible = computed(() => headlineScore.value !== undefined || props.finding.epss || ratings.value.length > 0 || props.finding.severity === 'unknown')

function bandOf(score: number): string {
  const band = cvssBand(score)
  return band === 'none' ? 'info' : band
}
</script>

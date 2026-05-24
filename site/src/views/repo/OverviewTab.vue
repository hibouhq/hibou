<template>
  <div class="space-y-5">
    <div v-if="loading" class="py-8 text-center text-sm text-gray-400">
      Loading overview...
    </div>

    <div v-else-if="error" class="rounded-xl border border-danger/30 bg-danger/10 px-4 py-5 text-sm text-red-200">
      {{ error }}
    </div>

    <div v-else-if="!summary || !summary.snapshot_date" class="rounded-2xl border border-dashed border-surface-border-subtle bg-surface-overlay/40 px-5 py-10 text-center text-sm text-gray-400">
      No analysis data available for this ref.
    </div>

    <template v-else>
      <div class="space-y-3">
        <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
          <div class="flex flex-wrap items-end gap-3 text-sm">
            <div class="flex items-end gap-1.5">
              <span class="text-lg font-semibold text-white">{{ findingsTotal }}</span>
              <span class="text-xs text-gray-400">findings</span>
            </div>
            <span class="h-1 w-1 rounded-full bg-gray-600"></span>
            <div class="flex items-end gap-1.5">
              <span class="text-lg font-semibold text-white">{{ vulnsTotal }}</span>
              <span class="text-xs text-gray-400">vulnerabilities</span>
            </div>
            <span class="h-1 w-1 rounded-full bg-gray-600"></span>
            <div class="flex items-end gap-1.5">
              <span class="text-lg font-semibold text-white">{{ summary.components_total }}</span>
              <span class="text-xs text-gray-400">components</span>
            </div>
          </div>

          <span class="text-xs text-gray-500">{{ formatSnapshotDate(summary.snapshot_date) }}</span>
        </div>

        <div class="space-y-2">
          <div class="flex h-1.5 overflow-hidden rounded-full bg-surface-border-subtle">
            <div
              v-for="segment in findingBarSegments"
              :key="`findings-bar-${segment.key}`"
              :class="segment.barClass"
              :style="{ width: `${segment.width}%` }"
            ></div>
          </div>

          <div class="flex flex-wrap gap-x-3 gap-y-1 text-[11px] font-medium">
            <span
              v-for="item in findingCells"
              :key="`finding-label-${item.key}`"
              :class="item.valueClass"
            >
              {{ item.value }} {{ item.label }}
            </span>
          </div>
        </div>
      </div>

      <div class="grid gap-3 lg:grid-cols-3">
        <section class="flex min-h-[148px] flex-col rounded-lg bg-surface-overlay/30 p-3">
          <div class="flex items-start justify-between gap-3">
            <div>
              <h2 class="text-[11px] font-medium uppercase tracking-[0.18em] text-gray-500">
                Findings
              </h2>
              <p class="mt-1 text-xl font-semibold text-white">
                {{ findingsTotal }}
              </p>
            </div>
            <span class="rounded-md bg-sev-critical/10 px-1.5 py-0.5 text-[10px] uppercase tracking-[0.14em] text-sev-critical">
              priority
            </span>
          </div>

          <div class="mt-4 flex h-1 overflow-hidden rounded-full bg-surface-border-subtle">
            <div
              v-for="segment in findingBarSegments"
              :key="`finding-card-${segment.key}`"
              :class="segment.barClass"
              :style="{ width: `${segment.width}%` }"
            ></div>
          </div>

          <div class="mt-3 grid grid-cols-5 gap-2 text-[11px]">
            <div v-for="item in findingCells" :key="`finding-${item.key}`" class="space-y-1">
              <div :class="item.valueClass" class="font-semibold">{{ item.value }}</div>
              <div class="uppercase tracking-[0.14em] text-gray-500">{{ item.label }}</div>
            </div>
          </div>

          <RouterLink :to="tabLink('repo-weaknesses')" class="mt-auto self-end text-[11px] font-medium text-accent transition hover:text-white">
            View ->
          </RouterLink>
        </section>

        <section class="flex min-h-[148px] flex-col rounded-lg bg-surface-overlay/30 p-3">
          <div class="flex items-start justify-between gap-3">
            <div>
              <h2 class="text-[11px] font-medium uppercase tracking-[0.18em] text-gray-500">
                Vulnerabilities
              </h2>
              <p class="mt-1 text-xl font-semibold text-white">
                {{ vulnsTotal }}
              </p>
            </div>
            <span class="rounded-md bg-sev-high/10 px-1.5 py-0.5 text-[10px] uppercase tracking-[0.14em] text-sev-high">
              advisories
            </span>
          </div>

          <div class="mt-4 flex h-1 overflow-hidden rounded-full bg-surface-border-subtle">
            <div
              v-for="segment in vulnBarSegments"
              :key="`vuln-card-${segment.key}`"
              :class="segment.barClass"
              :style="{ width: `${segment.width}%` }"
            ></div>
          </div>

          <div class="mt-3 grid grid-cols-5 gap-2 text-[11px]">
            <div v-for="item in vulnCells" :key="`vuln-${item.key}`" class="space-y-1">
              <div :class="item.valueClass" class="font-semibold">{{ item.value }}</div>
              <div class="uppercase tracking-[0.14em] text-gray-500">{{ item.label }}</div>
            </div>
          </div>

          <RouterLink :to="tabLink('repo-dependencies')" class="mt-auto self-end text-[11px] font-medium text-accent transition hover:text-white">
            View ->
          </RouterLink>
        </section>

        <section class="flex min-h-[148px] flex-col rounded-lg bg-surface-overlay/30 p-3">
          <div class="flex items-start justify-between gap-3">
            <div>
              <h2 class="text-[11px] font-medium uppercase tracking-[0.18em] text-gray-500">
                Components
              </h2>
              <p class="mt-1 text-xl font-semibold text-white">
                {{ summary.components_total }}
              </p>
            </div>
            <span class="rounded-md bg-accent-muted px-1.5 py-0.5 text-[10px] uppercase tracking-[0.14em] text-accent">
              inventory
            </span>
          </div>

          <div class="mt-4 h-1 overflow-hidden rounded-full bg-surface-border-subtle">
            <div class="h-full w-full bg-accent/60"></div>
          </div>

          <p class="mt-3 text-sm text-gray-300">
            packages tracked
          </p>

          <RouterLink :to="tabLink('repo-trends')" class="mt-auto self-end text-[11px] font-medium text-accent transition hover:text-white">
            View ->
          </RouterLink>
        </section>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api, type RefSummary } from '@/api/client'

type SeverityKey = keyof RefSummary['findings']

type SeveritySegment = {
  key: SeverityKey | 'empty'
  width: number
  barClass: string
}

const route = useRoute()

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const loading = ref(true)
const error = ref('')
const summary = ref<RefSummary | null>(null)

const severityMeta: Array<{ key: SeverityKey; label: string; valueClass: string; barClass: string }> = [
  { key: 'critical', label: 'crit', valueClass: 'text-sev-critical', barClass: 'bg-sev-critical' },
  { key: 'high', label: 'high', valueClass: 'text-sev-high', barClass: 'bg-sev-high' },
  { key: 'medium', label: 'med', valueClass: 'text-sev-medium', barClass: 'bg-sev-medium' },
  { key: 'low', label: 'low', valueClass: 'text-gray-300', barClass: 'bg-gray-500/80' },
  { key: 'info', label: 'info', valueClass: 'text-sev-info', barClass: 'bg-sev-info' },
]

const findingsTotal = computed(() => totalCounts(summary.value?.findings))
const vulnsTotal = computed(() => totalCounts(summary.value?.vulns))

const findingCells = computed(() => severityMeta.map((item) => ({
  ...item,
  value: summary.value?.findings[item.key] ?? 0,
})))

const vulnCells = computed(() => severityMeta.map((item) => ({
  ...item,
  value: summary.value?.vulns[item.key] ?? 0,
})))

const findingBarSegments = computed(() => buildSeveritySegments(summary.value?.findings))
const vulnBarSegments = computed(() => buildSeveritySegments(summary.value?.vulns))

watch(
  [provider, slug, repoSlug, () => route.query.ref],
  () => {
    void loadSummary()
  },
  { immediate: true },
)

async function loadSummary() {
  if (!provider.value || !slug.value || !repoSlug.value) {
    summary.value = null
    loading.value = false
    return
  }

  loading.value = true
  error.value = ''
  try {
    const response = await api.getRefSummary(provider.value, slug.value, repoSlug.value, {
      ref: typeof route.query.ref === 'string' ? route.query.ref : undefined,
    })
    summary.value = response.data
  } catch {
    summary.value = null
    error.value = 'Failed to load overview data. Please try again later.'
  } finally {
    loading.value = false
  }
}

function totalCounts(counts?: RefSummary['findings']) {
  if (!counts) {
    return 0
  }

  return counts.critical + counts.high + counts.medium + counts.low + counts.info
}

function buildSeveritySegments(counts?: RefSummary['findings']): SeveritySegment[] {
  const total = totalCounts(counts)

  if (!counts || total === 0) {
    return [{ key: 'empty', width: 100, barClass: 'bg-surface-border-subtle' }]
  }

  return severityMeta
    .filter((item) => counts[item.key] > 0)
    .map((item) => ({
      key: item.key,
      width: (counts[item.key] / total) * 100,
      barClass: item.barClass,
    }))
}

function tabLink(name: string) {
  return {
    name,
    params: route.params,
    query: route.query,
  }
}

function formatSnapshotDate(value: string) {
  return new Intl.DateTimeFormat('en', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  }).format(new Date(value))
}
</script>

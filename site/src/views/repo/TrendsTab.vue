<template>
  <div class="space-y-5">
    <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-end">
      <div class="flex flex-wrap gap-2">
        <button
          v-for="option in rangeOptions"
          :key="option.value"
          class="rounded-full border px-3 py-1.5 text-xs font-medium uppercase tracking-[0.18em] transition"
          :class="selectedRange === option.value ? 'border-accent/50 bg-accent-muted text-accent-hover' : 'border-surface-border text-gray-300 hover:text-white'"
          type="button"
          @click="selectedRange = option.value"
        >
          {{ option.label }}
        </button>
      </div>
    </div>

    <div
      v-if="loading"
      class="rounded-2xl border border-dashed border-surface-border-subtle px-4 py-10 text-sm text-gray-400"
    >
      Loading trend data...
    </div>

    <div
      v-else-if="error"
      class="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-5 text-sm text-danger"
    >
      {{ error }}
    </div>

    <div
      v-else-if="trendPoints.length < 2"
      class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/60 px-4 py-10 text-sm text-gray-400"
    >
      Not enough data for trends.
    </div>

    <template v-else>
      <div class="space-y-4 rounded-2xl border border-surface-border-subtle bg-surface-overlay/60 p-4">
        <div>
          <h3 class="text-lg font-medium text-white">
            Findings Trend
          </h3>
          <p class="mt-1 text-sm text-gray-300">
            Stacked severity bars across recent snapshots.
          </p>
        </div>

        <div class="space-y-3">
          <div
            v-for="point in trendPoints"
            :key="`findings-${point.snapshot_id}`"
            class="grid cursor-pointer gap-3 rounded-2xl border border-transparent p-3 transition hover:border-accent/30 hover:bg-white/5 lg:grid-cols-[200px_minmax(0,1fr)]"
            role="link"
            tabindex="0"
            @click="openSnapshot(point.snapshot_id)"
            @keydown.enter="openSnapshot(point.snapshot_id)"
            @keydown.space.prevent="openSnapshot(point.snapshot_id)"
          >
            <div>
              <p class="text-sm font-medium text-white">
                {{ formatDate(point.date) }}
              </p>
              <p class="mt-1 font-mono text-xs text-gray-400">
                <a
                  v-if="commitUrl(point.commit_sha)"
                  :href="commitUrl(point.commit_sha) || undefined"
                  target="_blank"
                  rel="noopener"
                  class="hover:text-accent hover:underline"
                  @click.stop
                >{{ point.commit_sha.slice(0, 12) }}</a>
                <span v-else>{{ point.commit_sha.slice(0, 12) }}</span>
              </p>
            </div>

            <div>
              <div class="flex h-4 overflow-hidden rounded-full bg-surface-border-subtle">
                <div
                  v-for="segment in findingsSegments(point)"
                  :key="segment.key"
                  :class="segment.color"
                  :style="{ width: `${segment.width}%` }"
                  :title="`${segment.label}: ${segment.count}`"
                />
              </div>
              <p class="mt-2 text-xs text-gray-400">
                Total {{ findingsTotal(point) }} findings
              </p>
            </div>
          </div>
        </div>
      </div>

      <div class="space-y-4 rounded-2xl border border-surface-border-subtle bg-surface-overlay/60 p-4">
        <div>
          <h3 class="text-lg font-medium text-white">
            Vulnerability Trend
          </h3>
          <p class="mt-1 text-sm text-gray-300">
            Distinct advisory counts per snapshot.
          </p>
        </div>

        <div class="space-y-3">
          <div
            v-for="point in trendPoints"
            :key="`vulns-${point.snapshot_id}`"
            class="grid cursor-pointer gap-3 rounded-2xl border border-transparent p-3 transition hover:border-accent/30 hover:bg-white/5 lg:grid-cols-[200px_minmax(0,1fr)]"
            role="link"
            tabindex="0"
            @click="openSnapshot(point.snapshot_id)"
            @keydown.enter="openSnapshot(point.snapshot_id)"
            @keydown.space.prevent="openSnapshot(point.snapshot_id)"
          >
            <div>
              <p class="text-sm font-medium text-white">
                {{ formatDate(point.date) }}
              </p>
              <p class="mt-1 font-mono text-xs text-gray-400">
                <a
                  v-if="commitUrl(point.commit_sha)"
                  :href="commitUrl(point.commit_sha) || undefined"
                  target="_blank"
                  rel="noopener"
                  class="hover:text-accent hover:underline"
                  @click.stop
                >{{ point.commit_sha.slice(0, 12) }}</a>
                <span v-else>{{ point.commit_sha.slice(0, 12) }}</span>
              </p>
            </div>

            <div>
              <div class="flex h-4 overflow-hidden rounded-full bg-surface-border-subtle">
                <div
                  v-for="segment in vulnSegments(point)"
                  :key="segment.key"
                  :class="segment.color"
                  :style="{ width: `${segment.width}%` }"
                  :title="`${segment.label}: ${segment.count}`"
                />
              </div>
              <p class="mt-2 text-xs text-gray-400">
                Total {{ vulnTotal(point) }} vulnerabilities
              </p>
            </div>
          </div>
        </div>
      </div>

      <div class="space-y-4 rounded-2xl border border-surface-border-subtle bg-surface-overlay/60 p-4">
        <div>
          <h3 class="text-lg font-medium text-white">
            Component Count Trend
          </h3>
          <p class="mt-1 text-sm text-gray-300">
            Total tracked components per snapshot.
          </p>
        </div>

        <div class="space-y-3">
          <div
            v-for="point in trendPoints"
            :key="`components-${point.snapshot_id}`"
            class="grid cursor-pointer gap-3 rounded-2xl border border-transparent p-3 transition hover:border-accent/30 hover:bg-white/5 lg:grid-cols-[200px_minmax(0,1fr)]"
            role="link"
            tabindex="0"
            @click="openSnapshot(point.snapshot_id)"
            @keydown.enter="openSnapshot(point.snapshot_id)"
            @keydown.space.prevent="openSnapshot(point.snapshot_id)"
          >
            <div>
              <p class="text-sm font-medium text-white">
                {{ formatDate(point.date) }}
              </p>
              <p class="mt-1 font-mono text-xs text-gray-400">
                <a
                  v-if="commitUrl(point.commit_sha)"
                  :href="commitUrl(point.commit_sha) || undefined"
                  target="_blank"
                  rel="noopener"
                  class="hover:text-accent hover:underline"
                  @click.stop
                >{{ point.commit_sha.slice(0, 12) }}</a>
                <span v-else>{{ point.commit_sha.slice(0, 12) }}</span>
              </p>
            </div>

            <div>
              <div class="h-4 overflow-hidden rounded-full bg-surface-border-subtle">
                <div
                  class="h-full rounded-full bg-sky-400/70"
                  :style="{ width: `${componentWidth(point.components_total)}%` }"
                  :title="`Components: ${point.components_total}`"
                />
              </div>
              <p class="mt-2 text-xs text-gray-400">
                Total {{ point.components_total }} components
              </p>
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, inject, ref, watch, type Ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, forgeCommitUrl, type TrendPoint } from '@/api/client'

type RangeValue = '7' | '30' | '90' | 'all'
type Segment = {
  key: string
  label: string
  count: number
  width: number
  color: string
}

const route = useRoute()
const router = useRouter()

const trendPoints = ref<TrendPoint[]>([])
const loading = ref(true)
const error = ref('')
const selectedRange = ref<RangeValue>('30')
const forgeUrl = inject<Ref<string>>('forgeUrl', ref(''))
const repoProviderID = inject<Ref<string>>('repoProviderID', ref(''))

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const rangeOptions: Array<{ label: string; value: RangeValue; days?: number; limit?: number }> = [
  { label: 'Last 7 days', value: '7', days: 7 },
  { label: 'Last 30 days', value: '30', days: 30 },
  { label: 'Last 90 days', value: '90', days: 90 },
  { label: 'Latest 365 scans', value: 'all', limit: 365 },
]

const maxComponents = computed(() => Math.max(...trendPoints.value.map((point) => point.components_total), 1))

watch(
  [provider, slug, repoSlug, () => route.query.ref, selectedRange],
  () => {
    void loadTrends()
  },
  { immediate: true },
)

async function loadTrends() {
  loading.value = true
  error.value = ''

  try {
    const selectedOption = rangeOptions.find((option) => option.value === selectedRange.value)
    trendPoints.value = await api.getTrends(provider.value, slug.value, repoSlug.value, {
      ref: typeof route.query.ref === 'string' ? route.query.ref : undefined,
      since: selectedOption?.days ? isoDaysAgo(selectedOption.days) : undefined,
      limit: selectedOption?.limit,
    })
  } catch (err) {
    trendPoints.value = []
    error.value = err instanceof Error ? err.message : 'Failed to load trend data.'
  } finally {
    loading.value = false
  }
}

function isoDaysAgo(days: number) {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString()
}

function findingsTotal(point: TrendPoint) {
  return point.findings_critical + point.findings_high + point.findings_medium + point.findings_low + point.findings_info
}

function vulnTotal(point: TrendPoint) {
  return point.vulns_critical + point.vulns_high + point.vulns_medium + point.vulns_low + point.vulns_info
}

function findingsSegments(point: TrendPoint): Segment[] {
  return buildSegments(findingsTotal(point), [
    { key: 'critical', label: 'Critical', count: point.findings_critical, color: 'bg-rose-500' },
    { key: 'high', label: 'High', count: point.findings_high, color: 'bg-orange-500' },
    { key: 'medium', label: 'Medium', count: point.findings_medium, color: 'bg-amber-400' },
    { key: 'low', label: 'Low', count: point.findings_low, color: 'bg-sky-500' },
    { key: 'info', label: 'Info', count: point.findings_info, color: 'bg-slate-500' },
  ])
}

function vulnSegments(point: TrendPoint): Segment[] {
  return buildSegments(vulnTotal(point), [
    { key: 'critical', label: 'Critical', count: point.vulns_critical, color: 'bg-rose-500' },
    { key: 'high', label: 'High', count: point.vulns_high, color: 'bg-orange-500' },
    { key: 'medium', label: 'Medium', count: point.vulns_medium, color: 'bg-amber-400' },
    { key: 'low', label: 'Low', count: point.vulns_low, color: 'bg-sky-500' },
    { key: 'info', label: 'Info', count: point.vulns_info, color: 'bg-slate-500' },
  ])
}

function buildSegments(total: number, segments: Array<Omit<Segment, 'width'>>) {
  if (total <= 0) {
    return [{ key: 'empty', label: 'Empty', count: 0, width: 100, color: 'bg-surface-border-subtle' }]
  }

  return segments
    .filter((segment) => segment.count > 0)
    .map((segment) => ({
      ...segment,
      width: (segment.count / total) * 100,
    }))
}

function componentWidth(count: number) {
  return (count / maxComponents.value) * 100
}

function commitUrl(sha: string): string | null {
  return forgeCommitUrl(forgeUrl.value, repoProviderID.value, sha)
}

function openSnapshot(snapshotId: string) {
  void router.push(snapshotLink(snapshotId))
}

function snapshotLink(snapshotId: string) {
  return {
    name: 'repo-trends',
    params: route.params,
    query: {
      ...route.query,
      snapshot: snapshotId,
    },
  }
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium' }).format(new Date(value))
}
</script>

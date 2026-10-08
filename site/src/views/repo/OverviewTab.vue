<template>
  <div class="space-y-5">
    <div
      v-if="loading"
      class="py-8 text-center text-sm text-gray-400"
    >
      Loading overview...
    </div>

    <div
      v-else-if="error"
      class="rounded-xl border border-danger/30 bg-danger/10 px-4 py-5 text-sm text-red-200"
    >
      {{ error }}
    </div>

    <div class="grid gap-5 lg:grid-cols-[1fr_18rem]">
      <!-- Main column -->
      <div class="min-w-0 space-y-4 lg:order-1">
        <div
          v-if="scanFailed"
          class="flex items-start gap-2.5 rounded-xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
        >
          <span class="mt-0.5 text-base leading-none">⚠</span>
          <div>
            <p class="font-medium">
              Latest scan for this ref failed.
            </p>
            <p class="mt-0.5 text-xs text-red-300/80">
              Figures below come from a failed snapshot and may be incomplete or empty. Pick a
              different snapshot above, or check the build logs.
            </p>
          </div>
        </div>

        <div
          v-if="!summary || !summary.snapshot_date"
          class="rounded-xl border border-dashed border-surface-border bg-surface-overlay/40 px-5 py-12 text-center text-sm text-gray-400"
        >
          No analysis data available for this ref yet.
        </div>

        <template v-else>
          <!-- Security posture card -->
          <section class="rounded-xl border border-surface-border bg-surface-raised/40">
            <div class="flex items-center justify-between border-b border-surface-border-subtle px-4 py-2.5">
              <h2 class="flex items-center gap-2 text-sm font-semibold text-white">
                <ShieldAlert class="h-4 w-4 text-gray-500" />
                Security posture
              </h2>
              <span class="text-xs text-gray-500">{{ formatSnapshotDate(summary.snapshot_date) }}</span>
            </div>

            <div class="space-y-4 px-4 py-4">
              <RouterLink
                v-if="malwareOpen > 0"
                :to="malwareLink()"
                class="flex items-center gap-2.5 rounded-lg border border-danger/50 bg-danger/10 px-3 py-2.5 transition hover:border-danger"
              >
                <Biohazard class="h-5 w-5 shrink-0 text-danger" />
                <span class="text-sm font-semibold text-red-200">
                  {{ malwareOpen }} malicious {{ malwareOpen === 1 ? 'package' : 'packages' }} detected
                </span>
                <span class="ml-auto text-xs text-red-300/80">Review immediately →</span>
              </RouterLink>

              <RouterLink
                v-if="kevOpen !== null"
                :to="kevLink()"
                class="flex flex-wrap items-center gap-2.5 border-l-2 px-3 py-2.5 transition hover:bg-surface-overlay"
                :class="kevOpen > 0 ? 'border-danger/60 bg-danger/5' : 'border-surface-border bg-surface-overlay/30'"
                title="Known exploited vulnerabilities"
              >
                <Flame
                  class="h-5 w-5 shrink-0"
                  :class="kevOpen > 0 ? 'text-danger' : 'text-gray-500'"
                />
                <span class="text-sm font-semibold text-gray-200">
                  {{ kevOpen }} known exploited {{ kevOpen === 1 ? 'vulnerability' : 'vulnerabilities' }}
                </span>
                <span class="ml-auto text-xs text-accent">View findings</span>
              </RouterLink>
              <p
                v-else-if="kevOpen === null"
                class="text-xs text-gray-500"
              >
                Known exploited status unavailable
              </p>

              <div class="flex items-end gap-2">
                <span class="text-3xl font-semibold text-white">{{ vulnerabilitiesTotal }}</span>
                <span class="pb-1 text-sm text-gray-400">open vulnerabilities</span>
              </div>

              <div class="h-2 overflow-hidden rounded-full bg-surface-border-subtle">
                <div class="flex h-full">
                  <div
                    v-for="segment in vulnerabilityBarSegments"
                    :key="`bar-${String(segment.key)}`"
                    :class="segment.barClass"
                    :style="{ width: `${segment.width}%` }"
                  />
                </div>
              </div>

              <div class="grid grid-cols-5 gap-2">
                <RouterLink
                  v-for="item in vulnerabilityCells"
                  :key="`cell-${String(item.key)}`"
                  :to="severityLink(item.key)"
                  class="rounded-lg border border-surface-border-subtle bg-surface-overlay/40 px-2 py-2 text-center transition hover:border-accent/40"
                >
                  <div
                    class="text-lg font-semibold"
                    :class="item.valueClass"
                  >
                    {{ item.value }}
                  </div>
                  <div class="text-[10px] uppercase tracking-[0.14em] text-gray-500">
                    {{ item.label }}
                  </div>
                </RouterLink>
              </div>
            </div>
          </section>

          <!-- Quick stat cards -->
          <div class="grid gap-4 sm:grid-cols-2">
            <RouterLink
              :to="tabLink('repo-dependencies')"
              class="group rounded-xl border border-surface-border bg-surface-raised/40 p-4 transition hover:border-accent/40"
            >
              <div class="flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
                <Package class="h-4 w-4" />
                Components
              </div>
              <p class="mt-2 text-2xl font-semibold text-white">
                {{ summary.components_total }}
              </p>
              <p class="mt-0.5 text-xs text-gray-500">
                packages tracked in the SBOM
              </p>
              <span class="mt-3 inline-flex items-center gap-1 text-xs font-medium text-accent">
                View dependencies
                <ArrowRight class="h-3.5 w-3.5 transition group-hover:translate-x-0.5" />
              </span>
            </RouterLink>

            <RouterLink
              :to="tabLink('repo-coverage')"
              class="group rounded-xl border border-surface-border bg-surface-raised/40 p-4 transition hover:border-accent/40"
            >
              <div class="flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
                <Activity class="h-4 w-4" />
                Coverage
              </div>
              <p class="mt-2 text-2xl font-semibold text-white">
                {{ coverageLabel }}
              </p>
              <p class="mt-0.5 text-xs text-gray-500">
                latest reported line coverage
              </p>
              <span class="mt-3 inline-flex items-center gap-1 text-xs font-medium text-accent">
                View coverage
                <ArrowRight class="h-3.5 w-3.5 transition group-hover:translate-x-0.5" />
              </span>
            </RouterLink>
          </div>
        </template>
      </div>

      <!-- About sidebar -->
      <aside class="space-y-3 lg:order-2">
        <section class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
          <h2 class="text-sm font-semibold text-white">
            About
          </h2>
          <p
            v-if="repo?.description"
            class="mt-2 text-sm text-gray-300"
          >
            {{ repo.description }}
          </p>
          <p
            v-else
            class="mt-2 text-sm text-gray-500"
          >
            No description provided.
          </p>

          <dl class="mt-4 space-y-2.5 text-sm">
            <div class="flex items-center gap-2 text-gray-400">
              <component
                :is="repo?.private ? Lock : Globe"
                class="h-4 w-4 shrink-0 text-gray-500"
              />
              <span>{{ repo?.private ? 'Private' : 'Public' }} repository</span>
            </div>
            <div class="flex items-center gap-2 text-gray-400">
              <GitBranch class="h-4 w-4 shrink-0 text-gray-500" />
              <span>Default branch <span class="font-mono text-gray-300">{{ repo?.default_branch || '—' }}</span></span>
            </div>
            <div class="flex items-center gap-2 text-gray-400">
              <Clock class="h-4 w-4 shrink-0 text-gray-500" />
              <span>Last scanned {{ lastScannedLabel }}</span>
            </div>
            <div
              v-if="latestSnapshot"
              class="flex items-center gap-2 text-gray-400"
            >
              <span
                class="h-2 w-2 shrink-0 rounded-full"
                :class="statusDot(latestSnapshot.status)"
              />
              <span>Latest snapshot <span class="capitalize text-gray-300">{{ latestSnapshot.status }}</span></span>
            </div>
          </dl>

          <a
            v-if="repo?.html_url"
            :href="repo.html_url"
            target="_blank"
            rel="noopener"
            class="mt-4 inline-flex items-center gap-1.5 text-xs font-medium text-accent transition hover:text-accent-hover"
          >
            <ExternalLink class="h-3.5 w-3.5" />
            Open on forge
          </a>
        </section>

        <!-- Snapshot files -->
        <section
          v-if="shownSnapshotId"
          class="rounded-xl border border-surface-border bg-surface-raised/40 p-4"
        >
          <div class="flex items-center justify-between gap-2">
            <h2 class="text-sm font-semibold text-white">
              Files
            </h2>
            <a
              v-if="files.length > 0"
              :href="archiveUrl"
              class="inline-flex items-center gap-1.5 rounded-lg border border-surface-border px-2 py-1 text-xs text-gray-300 transition hover:border-accent/50 hover:text-white"
              title="Download all files as a zip"
            >
              <FileArchive class="h-3.5 w-3.5" />
              Download all
            </a>
          </div>

          <p
            v-if="filesLoading"
            class="mt-3 text-xs text-gray-500"
          >
            Loading files…
          </p>
          <p
            v-else-if="files.length === 0"
            class="mt-3 text-xs text-gray-500"
          >
            No files in this snapshot.
          </p>
          <ul
            v-else
            class="mt-3 max-h-72 space-y-1.5 overflow-y-auto pr-1"
          >
            <li
              v-for="file in files"
              :key="file.id"
              class="flex items-center gap-2 rounded-lg border border-surface-border-subtle bg-surface-overlay/40 px-2.5 py-2"
            >
              <FileText class="h-4 w-4 shrink-0 text-gray-500" />
              <div class="min-w-0 flex-1">
                <div
                  class="truncate font-mono text-xs text-gray-200"
                  :title="file.filename"
                >
                  {{ file.filename }}
                </div>
                <div class="text-[11px] text-gray-500">
                  {{ file.kind }}<span v-if="file.tool_name"> · {{ file.tool_name }}</span> · {{ humanSize(file.size_bytes) }}
                </div>
              </div>
              <RouterLink
                v-if="file.kind === 'sbom'"
                :to="{ name: 'sbom-compare', query: { base_artifact: file.id, base_snapshot: effectiveSnapshotId } }"
                class="shrink-0 rounded-md p-1.5 text-gray-400 transition hover:bg-accent-muted hover:text-white"
                title="Compare this SBOM"
                aria-label="Compare this SBOM"
              >
                <ArrowLeftRight class="h-4 w-4" />
              </RouterLink>
              <a
                :href="file.download_url"
                :download="file.filename"
                class="shrink-0 rounded-md p-1.5 text-gray-400 transition hover:bg-accent-muted hover:text-white"
                :title="`Download ${file.filename}`"
                :aria-label="`Download ${file.filename}`"
              >
                <Download class="h-4 w-4" />
              </a>
            </li>
          </ul>
        </section>
      </aside>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Activity, ArrowLeftRight, ArrowRight, Biohazard, Clock, Download, ExternalLink, FileArchive, FileText, Flame, GitBranch, Globe, Lock, Package, ShieldAlert } from 'lucide-vue-next'
import { computed, inject, ref, watch, type Ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api, type RefSummary, type Repository, type SeverityCounts, type Snapshot, type SnapshotFile } from '@/api/client'
import { relativeTime } from '@/lib/datetime'
import { OPEN_RISK_KEV_QUERY } from '@/lib/openRiskPreset'

type SeverityKey = keyof SeverityCounts

type SeveritySegment = {
  key: SeverityKey | 'empty'
  width: number
  barClass: string
}

const route = useRoute()

const repo = inject<Ref<Repository | null>>('repo', ref(null))
const latestSnapshot = inject<Ref<Snapshot | null>>('latestSnapshot', ref(null))

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const loading = ref(true)
const error = ref('')
const summary = ref<RefSummary | null>(null)
const malwareOpen = computed(() => summary.value?.malware_open ?? 0)
const kevOpen = computed(() => summary.value?.kev_open ?? null)
const coverageRate = ref<number | null>(null)
const files = ref<SnapshotFile[]>([])
const filesLoading = ref(false)

// The snapshot whose files we show: an explicitly selected one, else the latest.
const shownSnapshotId = computed(() => {
  const q = route.query.snapshot
  if (typeof q === 'string' && q) {
    return q
  }
  return latestSnapshot?.value?.id ?? ''
})
const effectiveSnapshotId = computed(() => shownSnapshotId.value)
const archiveUrl = computed(() =>
  shownSnapshotId.value
    ? api.snapshotArchiveUrl(provider.value, slug.value, repoSlug.value, shownSnapshotId.value)
    : '',
)

const severityMeta: Array<{ key: SeverityKey; label: string; valueClass: string; barClass: string }> = [
  { key: 'critical', label: 'crit', valueClass: 'text-sev-critical', barClass: 'bg-sev-critical' },
  { key: 'high', label: 'high', valueClass: 'text-sev-high', barClass: 'bg-sev-high' },
  { key: 'medium', label: 'med', valueClass: 'text-sev-medium', barClass: 'bg-sev-medium' },
  { key: 'low', label: 'low', valueClass: 'text-sev-low', barClass: 'bg-sev-low' },
  { key: 'info', label: 'info', valueClass: 'text-sev-info', barClass: 'bg-sev-info' },
]

const vulnerabilitiesTotal = computed(() => totalCounts(summary.value?.vulnerabilities))
const vulnerabilityCells = computed(() => severityMeta.map((item) => ({
  ...item,
  value: summary.value?.vulnerabilities[item.key] ?? 0,
})))
const vulnerabilityBarSegments = computed(() => buildSeveritySegments(summary.value?.vulnerabilities))
const scanFailed = computed(() => summary.value?.snapshot_status === 'failed')

const coverageLabel = computed(() => coverageRate.value === null ? '—' : `${Math.round(coverageRate.value * 100)}%`)
const lastScannedLabel = computed(() => {
  const value = repo?.value?.last_scanned
  return value ? relativeTime(value) : 'never'
})

watch(
  [provider, slug, repoSlug, () => route.query.ref, () => route.query.snapshot],
  () => {
    void loadSummary()
    void loadCoverage()
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
      snapshot: typeof route.query.snapshot === 'string' ? route.query.snapshot : undefined,
    })
    summary.value = response.data
  } catch {
    summary.value = null
    error.value = 'Failed to load overview data. Please try again later.'
  } finally {
    loading.value = false
  }
}

async function loadCoverage() {
  if (!provider.value || !slug.value || !repoSlug.value) {
    coverageRate.value = null
    return
  }

  try {
    const response = await api.getCoverage(provider.value, slug.value, repoSlug.value, {
      ref: typeof route.query.ref === 'string' ? route.query.ref : undefined,
      snapshot: typeof route.query.snapshot === 'string' ? route.query.snapshot : undefined,
    })
    coverageRate.value = response.data?.line_rate ?? null
  } catch {
    coverageRate.value = null
  }
}

watch(
  shownSnapshotId,
  () => {
    void loadFiles()
  },
  { immediate: true },
)

async function loadFiles() {
  const snapshotId = shownSnapshotId.value
  if (!provider.value || !slug.value || !repoSlug.value || !snapshotId) {
    files.value = []
    return
  }

  filesLoading.value = true
  try {
    const response = await api.listSnapshotFiles(provider.value, slug.value, repoSlug.value, snapshotId)
    files.value = response.data
  } catch {
    files.value = []
  } finally {
    filesLoading.value = false
  }
}

function humanSize(bytes: number) {
  if (!bytes || bytes < 0) {
    return '0 B'
  }
  const units = ['B', 'KB', 'MB', 'GB']
  let size = bytes
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  return `${size >= 10 || unit === 0 ? Math.round(size) : size.toFixed(1)} ${units[unit]}`
}

function totalCounts(counts?: SeverityCounts) {
  if (!counts) {
    return 0
  }
  return counts.critical + counts.high + counts.medium + counts.low + counts.info
}

function buildSeveritySegments(counts?: SeverityCounts): SeveritySegment[] {
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
  return { name, params: route.params, query: route.query }
}

function severityLink(key: SeverityKey) {
  return {
    name: 'repo-vulnerabilities',
    params: route.params,
    query: { ...route.query, severity: key },
  }
}

function malwareLink() {
  return {
    name: 'repo-vulnerabilities',
    params: route.params,
    query: { ...route.query, type: 'malware' },
  }
}

function kevLink() {
  return {
    name: 'repo-vulnerabilities',
    params: route.params,
    query: { ref: route.query.ref, snapshot: route.query.snapshot, q: OPEN_RISK_KEV_QUERY },
  }
}

function statusDot(status: string) {
  switch ((status || '').toLowerCase()) {
    case 'active':
    case 'complete':
      return 'bg-emerald-400'
    case 'failed':
      return 'bg-danger'
    case 'pending':
    case 'processing':
      return 'bg-warning'
    default:
      return 'bg-gray-500'
  }
}

function formatSnapshotDate(value: string) {
  return new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', year: 'numeric' }).format(new Date(value))
}
</script>

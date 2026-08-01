<template>
  <div class="space-y-5">
    <div
      v-if="loading"
      class="space-y-5"
    >
      <section class="rounded-xl border border-surface-border bg-surface-raised p-5">
        <div class="animate-pulse space-y-4">
          <div class="h-5 w-40 rounded bg-surface-overlay" />
          <div class="grid gap-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(280px,1fr)]">
            <div class="space-y-4">
              <div class="space-y-2">
                <div class="h-3 w-28 rounded bg-surface-overlay" />
                <div class="h-2 w-full rounded-full bg-surface-overlay" />
              </div>
              <div class="space-y-2">
                <div class="h-3 w-32 rounded bg-surface-overlay" />
                <div class="h-2 w-full rounded-full bg-surface-overlay" />
              </div>
            </div>
            <div class="grid gap-3 sm:grid-cols-2">
              <div
                v-for="index in 4"
                :key="`coverage-stat-skeleton-${index}`"
                class="rounded-lg border border-surface-border bg-surface-overlay/60 p-3"
              >
                <div class="h-3 w-20 rounded bg-surface-overlay" />
                <div class="mt-3 h-5 w-24 rounded bg-surface-overlay" />
              </div>
            </div>
          </div>
        </div>
      </section>

      <section class="overflow-hidden rounded-xl border border-surface-border bg-surface-raised">
        <div class="animate-pulse divide-y divide-surface-border-subtle">
          <div class="grid grid-cols-[minmax(240px,1.6fr)_140px_140px_120px_120px] gap-3 px-4 py-3">
            <div
              v-for="index in 5"
              :key="`coverage-header-skeleton-${index}`"
              class="h-4 rounded bg-surface-overlay"
            />
          </div>
          <div
            v-for="index in 6"
            :key="`coverage-row-skeleton-${index}`"
            class="grid grid-cols-[minmax(240px,1.6fr)_140px_140px_120px_120px] gap-3 px-4 py-4"
          >
            <div
              v-for="cell in 5"
              :key="`coverage-cell-skeleton-${index}-${cell}`"
              class="h-4 rounded bg-surface-overlay/80"
            />
          </div>
        </div>
      </section>
    </div>

    <div
      v-else-if="error"
      class="rounded-xl border border-danger/30 bg-danger/10 px-4 py-5 text-sm text-red-200"
    >
      {{ error }}
    </div>

    <div
      v-else-if="!report"
      class="rounded-xl border border-dashed border-surface-border-subtle bg-surface-overlay/40 px-6 py-10 text-center"
    >
      <div class="mx-auto flex h-11 w-11 items-center justify-center rounded-xl border border-surface-border bg-surface-overlay text-accent">
        <Upload class="h-5 w-5" />
      </div>
      <h2 class="mt-3 text-base font-semibold text-white">
        No coverage report for this ref
      </h2>
      <p class="mt-2 text-sm text-gray-400">
        Upload a Cobertura, LCOV, JaCoCo, Clover, or Go cover report to populate coverage metrics for this repository ref.
      </p>
    </div>

    <template v-else-if="activeReport">
      <section class="rounded-xl border border-surface-border bg-surface-raised p-5">
        <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div class="flex items-center gap-2">
              <BarChart3 class="h-4 w-4 text-accent" />
              <h2 class="text-base font-semibold text-white">
                Coverage summary
              </h2>
            </div>
            <p class="mt-1 text-sm text-gray-400">
              {{ activeLabel }}
            </p>
          </div>

          <!-- New-code baseline: "of the code added since X, how much is
               tested?" Empty = classic whole-tree view. -->
          <label class="flex items-center gap-2 text-xs text-gray-400">
            <span class="whitespace-nowrap">New code since</span>
            <select
              :value="sinceParam"
              class="rounded-md border border-surface-border bg-surface-overlay px-2 py-1.5 text-xs text-gray-200"
              @change="selectBaseline(($event.target as HTMLSelectElement).value)"
            >
              <option value="">
                — whole tree —
              </option>
              <option
                v-for="option in baselineOptions"
                :key="option"
                :value="option"
              >
                {{ option }}
              </option>
            </select>
          </label>
        </div>

        <div
          v-if="sinceParam"
          class="mt-4 rounded-lg border border-surface-border bg-surface-overlay/50 p-3"
        >
          <div class="flex flex-wrap items-center justify-between gap-2">
            <span class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
              New code coverage since {{ sinceParam }}
            </span>
            <span
              v-if="newCode?.truncated"
              class="rounded border border-warning/40 bg-warning/10 px-2 py-0.5 text-[11px] text-warning"
              title="The forge capped the compared file list, so this covers only the first files."
            >partial — forge truncated the file list</span>
          </div>
          <div
            v-if="newCode && newCode.line_rate !== null"
            class="mt-2 flex flex-wrap items-baseline gap-3"
          >
            <span
              class="text-2xl font-semibold"
              :style="{ color: rateColorValue(newCode.line_rate) }"
            >{{ formatRate(newCode.line_rate) }}</span>
            <span class="text-sm text-gray-400">
              {{ newCode.covered }}/{{ newCode.lines }} changed lines covered across {{ newCode.file_paths.length }}
              {{ newCode.file_paths.length === 1 ? 'file' : 'files' }}
            </span>
          </div>
          <p
            v-else
            class="mt-2 text-sm text-gray-500"
          >
            {{ newCodeEmptyReason }}
          </p>
        </div>

        <div class="mt-5 grid gap-5 lg:grid-cols-[minmax(0,1.6fr)_minmax(280px,1fr)]">
          <div class="space-y-4">
            <div class="space-y-2.5">
              <div class="flex items-center justify-between gap-3">
                <div class="flex items-center gap-2 text-sm text-gray-300">
                  <FileCode2 class="h-4 w-4 text-gray-500" />
                  <span>Line coverage</span>
                </div>
                <span
                  class="text-sm font-semibold"
                  :style="{ color: rateColorValue(activeReport.line_rate) }"
                >
                  {{ formatRate(activeReport.line_rate) }}
                </span>
              </div>
              <div class="h-2 w-full rounded-full bg-surface-overlay">
                <div
                  class="h-2 rounded-full transition-all"
                  :style="coverageBarStyle(activeReport.line_rate)"
                />
              </div>
            </div>

            <div class="space-y-2.5">
              <div class="flex items-center justify-between gap-3">
                <div class="flex items-center gap-2 text-sm text-gray-300">
                  <GitBranch class="h-4 w-4 text-gray-500" />
                  <span>Branch coverage</span>
                </div>
                <span
                  class="text-sm font-semibold"
                  :style="{ color: rateColorValue(activeReport.branch_rate) }"
                >
                  {{ formatRate(activeReport.branch_rate) }}
                </span>
              </div>
              <div class="h-2 w-full rounded-full bg-surface-overlay">
                <div
                  class="h-2 rounded-full transition-all"
                  :style="coverageBarStyle(activeReport.branch_rate)"
                />
              </div>
            </div>
          </div>

          <div class="grid gap-3 sm:grid-cols-2">
            <div class="rounded-lg border border-surface-border bg-surface-overlay/50 p-3">
              <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
                Lines
              </div>
              <div class="mt-2 text-lg font-semibold text-white">
                {{ activeReport.lines_covered }}/{{ activeReport.lines_valid }}
              </div>
              <div class="mt-1 text-xs text-gray-500">
                covered / total
              </div>
            </div>
            <div class="rounded-lg border border-surface-border bg-surface-overlay/50 p-3">
              <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
                Branches
              </div>
              <div class="mt-2 text-lg font-semibold text-white">
                {{ activeReport.branches_covered }}/{{ activeReport.branches_valid }}
              </div>
              <div class="mt-1 text-xs text-gray-500">
                covered / total
              </div>
            </div>
            <div class="rounded-lg border border-surface-border bg-surface-overlay/50 p-3">
              <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
                Best line rate
              </div>
              <div
                class="mt-2 text-lg font-semibold"
                :style="{ color: rateColorValue(highestLineRate) }"
              >
                {{ formatRate(highestLineRate) }}
              </div>
              <div class="mt-1 text-xs text-gray-500">
                highest file result
              </div>
            </div>
            <div class="rounded-lg border border-surface-border bg-surface-overlay/50 p-3">
              <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
                Files with data
              </div>
              <div class="mt-2 text-lg font-semibold text-white">
                {{ filesWithLineData }}
              </div>
              <div class="mt-1 text-xs text-gray-500">
                line coverage reported
              </div>
            </div>
          </div>
        </div>
      </section>

      <FilterBar
        v-model="activeFilters"
        v-model:search-query="searchQuery"
        v-model:sort-value="currentSort"
        v-model:sort-direction="currentSortDirection"
        :filters="filterDefs"
        :sort-options="sortOptions"
        :sort-direction-options="sortDirectionOptions"
        :total-count="activeFiles.length"
        :filtered-count="filteredFiles.length"
        placeholder="Filter files… (format:lcov file:go/)"
      />

      <section class="overflow-hidden rounded-xl border border-surface-border bg-surface-raised">
        <div class="flex flex-wrap items-center justify-between gap-3 border-b border-surface-border-subtle px-4 py-3">
          <h3 class="text-sm font-semibold text-white">
            Files
          </h3>
          <div class="flex overflow-hidden rounded-lg border border-surface-border">
            <button
              v-for="mode in viewModes"
              :key="mode.key"
              type="button"
              class="px-2.5 py-1.5 transition"
              :class="viewMode === mode.key ? 'bg-accent/15 text-white' : 'bg-surface-overlay text-gray-400 hover:text-white'"
              :aria-label="mode.label"
              :title="mode.label"
              @click="viewMode = mode.key"
            >
              <component
                :is="mode.icon"
                class="h-3.5 w-3.5"
              />
            </button>
          </div>
        </div>

        <div
          v-if="activeFiles.length === 0"
          class="px-4 py-10 text-sm text-gray-500"
        >
          Coverage totals were parsed, but this report did not include per-file data.
        </div>

        <div
          v-else-if="filteredFiles.length === 0"
          class="px-4 py-10 text-sm text-gray-500"
        >
          No files match the current filters.
        </div>

        <CoverageTreeView
          v-else-if="viewMode === 'tree'"
          :files="treeFiles"
          @select-file="onSelectFile"
        />

        <div
          v-else-if="viewMode === 'treemap'"
          class="p-4"
        >
          <CoverageTreemap
            :files="treeFiles"
            @select-file="onSelectFile"
          />
        </div>

        <div
          v-else
          class="overflow-x-auto"
        >
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="sticky top-0 bg-surface-overlay text-left text-xs uppercase tracking-[0.18em] text-gray-500">
              <tr>
                <th
                  v-for="column in columnHeaders"
                  :key="column.field"
                  class="px-3 py-2 font-medium"
                >
                  <button
                    class="inline-flex items-center gap-1.5 transition hover:text-gray-200"
                    type="button"
                    @click="toggle(column.field)"
                  >
                    {{ column.label }}
                    <component
                      :is="icon(column.field)"
                      class="h-3.5 w-3.5"
                    />
                  </button>
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="file in sortedFiles"
                :key="file.file_path"
                class="cursor-pointer transition hover:bg-white/5"
                @click="onSelectFile(file.canonical_path || file.file_path)"
              >
                <td class="px-3 py-3 align-top text-gray-200">
                  <div
                    class="font-mono text-xs leading-6 text-gray-200"
                    :title="file.file_path"
                  >
                    {{ file.canonical_path || file.file_path }}
                  </div>
                </td>
                <td class="px-3 py-3 align-top">
                  <div class="space-y-2">
                    <div
                      class="font-medium"
                      :style="{ color: rateColorValue(file.line_rate) }"
                    >
                      {{ formatRate(file.line_rate) }}
                    </div>
                    <div class="h-2 w-full rounded-full bg-surface-overlay">
                      <div
                        class="h-2 rounded-full"
                        :style="coverageBarStyle(file.line_rate)"
                      />
                    </div>
                  </div>
                </td>
                <td class="px-3 py-3 align-top">
                  <div class="space-y-2">
                    <div
                      class="font-medium"
                      :style="{ color: rateColorValue(file.branch_rate) }"
                    >
                      {{ formatRate(file.branch_rate) }}
                    </div>
                    <div class="h-2 w-full rounded-full bg-surface-overlay">
                      <div
                        class="h-2 rounded-full"
                        :style="coverageBarStyle(file.branch_rate)"
                      />
                    </div>
                  </div>
                </td>
                <td class="px-3 py-3 align-top text-gray-300">
                  {{ file.lines_covered }}/{{ file.lines_valid }}
                </td>
                <td class="px-3 py-3 align-top text-gray-300">
                  {{ file.branches_covered }}/{{ file.branches_valid }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <CoverageSourceModal
        v-if="sourceFile && report"
        :provider="provider"
        :slug="slug"
        :repo-slug="repoSlug"
        :snapshot-id="report.snapshot_id"
        :path="sourceFile"
        :repo-html-url="repo?.html_url"
        @close="sourceFile = null"
      />
    </template>

    <div
      v-else
      class="rounded-xl border border-dashed border-surface-border-subtle bg-surface-overlay/40 px-6 py-10 text-center text-sm text-gray-400"
    >
      Coverage data is temporarily unavailable for the selected format.
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, inject, ref, watch, type Ref } from 'vue'
import { BarChart3, FileCode2, FolderTree, GitBranch, LayoutGrid, TableProperties, Upload } from 'lucide-vue-next'
import { type LocationQueryRaw, useRoute, useRouter } from 'vue-router'

import { api, type CoverageFile, type CoverageReport, type EnhancedRef, type Repository } from '@/api/client'
import CoverageSourceModal from '@/components/CoverageSourceModal.vue'
import CoverageTreemap from '@/components/CoverageTreemap.vue'
import CoverageTreeView from '@/components/CoverageTreeView.vue'
import FilterBar from '@/components/FilterBar.vue'
import { useTableSort } from '@/composables/useTableSort'

const route = useRoute()
const router = useRouter()

const repo = inject<Ref<Repository | null>>('repo', ref(null))
const refs = inject<Ref<EnhancedRef[]>>('refs', ref([]))

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)
const refParam = computed(() => route.query.ref as string | undefined)
const snapshotParam = computed(() => route.query.snapshot as string | undefined)
// New-code baseline (ADR-019): "coverage of code added since <ref>". Lives in
// the URL so a view is shareable; empty means the classic whole-tree view.
const sinceParam = computed(() => (route.query.since as string | undefined) ?? '')
const newCode = computed(() => report.value?.new_code ?? null)

// Why the new-code number is absent, stated plainly rather than showing 0%.
const newCodeEmptyReason = computed(() => {
  if (!newCode.value) {
    return `Could not compare against ${sinceParam.value} — the baseline ref has no snapshot yet, or this forge cannot provide comparisons.`
  }
  return 'No measurable new code since this baseline — the changed lines are not instrumented (docs, comments, or files without coverage).'
})

// Baselines worth offering: the repo's other branches and tags. A release tag is
// the usual pick ("new code since v1.4.0").
const baselineOptions = computed(() => {
  const names = (refs.value ?? [])
    .filter((item) => item.ref_type === 'branch' || item.ref_type === 'tag')
    .map((item) => item.name)
    .filter((name) => name && name !== refParam.value)
  return Array.from(new Set(names)).sort((a, b) => a.localeCompare(b))
})

function selectBaseline(value: string) {
  const query: LocationQueryRaw = { ...route.query }
  if (value) {
    query.since = value
  } else {
    delete query.since
  }
  void router.replace({ query })
}

const loading = ref(true)
const error = ref('')
const report = ref<CoverageReport | null>(null)
const viewMode = ref<'tree' | 'table' | 'treemap'>('tree')

const activeFilters = ref<Record<string, string>>({})
const searchQuery = ref('')
const currentSort = ref('')
const currentSortDirection = ref('')

const viewModes = [
  { key: 'tree', label: 'Tree view', icon: FolderTree },
  { key: 'table', label: 'Table view', icon: TableProperties },
  { key: 'treemap', label: 'Treemap view', icon: LayoutGrid },
] as const

const reportOptions = computed(() => report.value?.reports ?? [])

const activeReport = computed(() => report.value)

const activeLabel = computed(() => {
  const active = report.value
  if (!active) return ''
  if (reportOptions.value.length > 1) {
    return `${active.files.length} files aggregated across ${reportOptions.value.length} reports`
  }
  return `${active.files.length} files in ${active.format || 'unknown'} format`
})

const formatOptions = computed(() => [...new Set(reportOptions.value.map((option) => option.format || 'unknown'))].sort())
const fileOptions = computed(() => (report.value?.files ?? []).map((file) => file.canonical_path || file.file_path).sort())

const filterDefs = computed(() => [
  { key: 'format', label: 'Format', options: formatOptions.value, multi: true },
  { key: 'file', label: 'File', options: fileOptions.value, multi: true, freeform: true },
])

const sortOptions = [
  { key: 'coverage', label: 'Line coverage', ascLabel: 'Least covered', descLabel: 'Most covered' },
  { key: 'lines', label: 'Instrumented lines', ascLabel: 'Smallest', descLabel: 'Largest' },
  { key: 'path', label: 'File path', ascLabel: 'Path A→Z', descLabel: 'Path Z→A' },
]
const sortDirectionOptions = [
  { key: 'asc', label: '↑ Ascending' },
  { key: 'desc', label: '↓ Descending' },
]

const activeFiles = computed<CoverageFile[]>(() => {
  const formats = splitFilter(activeFilters.value.format)
  if (formats.length === 0) {
    return report.value?.files ?? []
  }
  const best = new Map<string, CoverageFile>()
  for (const option of reportOptions.value) {
    if (!formats.includes((option.format || 'unknown').toLowerCase())) continue
    for (const file of option.files) {
      const key = file.canonical_path || file.file_path
      const existing = best.get(key)
      if (!existing || file.lines_covered > existing.lines_covered) {
        best.set(key, file)
      }
    }
  }
  return [...best.values()]
})

const filteredFiles = computed(() => {
  const patterns = splitFilter(activeFilters.value.file)
  const search = searchQuery.value.trim().toLowerCase()
  return activeFiles.value.filter((file) => {
    const path = (file.canonical_path || file.file_path).toLowerCase()
    if (patterns.length > 0 && !patterns.some((pattern) => matchPathPattern(path, pattern))) {
      return false
    }
    return search.length === 0 || path.includes(search)
  })
})

function splitFilter(value: string | undefined): string[] {
  return (value ?? '').split(',').map((entry) => entry.trim().toLowerCase()).filter(Boolean)
}

function matchPathPattern(path: string, pattern: string): boolean {
  if (!pattern.includes('*')) {
    return path.includes(pattern)
  }
  const regex = new RegExp(pattern.split('*').map(escapeRegex).join('.*'))
  return regex.test(path)
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

const presortedFiles = computed(() => {
  const sort = currentSort.value
  if (!sort) return filteredFiles.value
  const direction = currentSortDirection.value === 'desc' ? -1 : 1
  return [...filteredFiles.value].sort((a, b) => {
    if (sort === 'coverage') return ((a.line_rate ?? -1) - (b.line_rate ?? -1)) * direction
    if (sort === 'lines') return (a.lines_valid - b.lines_valid) * direction
    return (a.canonical_path || a.file_path).localeCompare(b.canonical_path || b.file_path) * direction
  })
})

type ColumnField = 'file_path' | 'line_rate' | 'branch_rate' | 'lines' | 'branches'

const columnHeaders: Array<{ field: ColumnField; label: string }> = [
  { field: 'file_path', label: 'File path' },
  { field: 'line_rate', label: 'Line coverage' },
  { field: 'branch_rate', label: 'Branch coverage' },
  { field: 'lines', label: 'Lines' },
  { field: 'branches', label: 'Branches' },
]

const { sorted: sortedFiles, toggle, icon } = useTableSort<CoverageFile, ColumnField>(
  presortedFiles,
  {
    file_path: { value: (file) => file.canonical_path || file.file_path },
    line_rate: { value: (file) => file.line_rate, initial: 'asc' },
    branch_rate: { value: (file) => file.branch_rate, initial: 'asc' },
    lines: { value: (file) => file.lines_valid, initial: 'desc' },
    branches: { value: (file) => file.branches_valid, initial: 'desc' },
  },
  'line_rate',
)

const treeFiles = computed(() =>
  filteredFiles.value.map((file) => ({
    path: file.canonical_path || file.file_path,
    valid: file.lines_valid,
    covered: file.lines_covered,
    rate: file.line_rate,
  })),
)

const sourceFile = ref<string | null>(null)

function onSelectFile(path: string) {
  sourceFile.value = path
}

const highestLineRate = computed(() => {
  const rates = (activeReport.value?.files ?? [])
    .map((file) => file.line_rate)
    .filter((rate): rate is number => typeof rate === 'number')

  if (rates.length === 0) {
    return null
  }

  return Math.max(...rates)
})

const filesWithLineData = computed(() => (activeReport.value?.files ?? []).filter((file) => file.line_rate !== null).length)

watch(
  [provider, slug, repoSlug, refParam, snapshotParam, sinceParam],
  () => {
    void loadCoverage()
  },
  { immediate: true },
)

async function loadCoverage() {
  if (!provider.value || !slug.value || !repoSlug.value) {
    report.value = null
    loading.value = false
    return
  }

  loading.value = true
  error.value = ''

  try {
    const response = await api.getCoverage(provider.value, slug.value, repoSlug.value, {
      ref: refParam.value,
      snapshot: snapshotParam.value,
      since: sinceParam.value || undefined,
    })
    report.value = response.data ?? null
  } catch {
    report.value = null
    error.value = 'Failed to load coverage data. Please try again later.'
  } finally {
    loading.value = false
    activeFilters.value = {}
    searchQuery.value = ''
  }
}

function formatRate(rate: number | null) {
  if (rate === null) {
    return 'n/a'
  }

  return `${(rate * 100).toFixed(1)}%`
}

function coverageBarStyle(rate: number | null) {
  return {
    width: `${Math.max(0, Math.min(100, (rate ?? 0) * 100))}%`,
    backgroundColor: rateColorValue(rate),
  }
}

function rateColorValue(rate: number | null) {
  if (rate === null) {
    return 'var(--color-text-muted, #6b7280)'
  }

  const percent = rate * 100
  if (percent >= 80) {
    return 'var(--color-ok, #3fb950)'
  }
  if (percent >= 60) {
    return 'var(--color-warn, #d29922)'
  }
  return 'var(--color-danger, #f85149)'
}
</script>

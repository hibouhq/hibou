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

    <template v-else>
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
              {{ sortedFiles.length }} files in {{ report.format || 'unknown' }} format
            </p>
          </div>

          <span class="inline-flex items-center rounded-full border border-surface-border bg-surface-overlay px-3 py-1 text-[11px] font-medium uppercase tracking-[0.16em] text-gray-300">
            {{ report.format || 'unknown' }}
          </span>
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
                  :style="{ color: rateColorValue(report.line_rate) }"
                >
                  {{ formatRate(report.line_rate) }}
                </span>
              </div>
              <div class="h-2 w-full rounded-full bg-surface-overlay">
                <div
                  class="h-2 rounded-full transition-all"
                  :style="coverageBarStyle(report.line_rate)"
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
                  :style="{ color: rateColorValue(report.branch_rate) }"
                >
                  {{ formatRate(report.branch_rate) }}
                </span>
              </div>
              <div class="h-2 w-full rounded-full bg-surface-overlay">
                <div
                  class="h-2 rounded-full transition-all"
                  :style="coverageBarStyle(report.branch_rate)"
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
                {{ report.lines_covered }}/{{ report.lines_valid }}
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
                {{ report.branches_covered }}/{{ report.branches_valid }}
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

      <section class="overflow-hidden rounded-xl border border-surface-border bg-surface-raised">
        <div class="flex items-center justify-between gap-3 border-b border-surface-border-subtle px-4 py-3">
          <div>
            <h3 class="text-sm font-semibold text-white">
              File coverage
            </h3>
            <p class="mt-1 text-xs text-gray-500">
              Sort by file path or line coverage to spot weak files quickly.
            </p>
          </div>
          <div class="text-xs text-gray-500">
            {{ sortedFiles.length }} rows
          </div>
        </div>

        <div
          v-if="sortedFiles.length === 0"
          class="px-4 py-10 text-sm text-gray-500"
        >
          Coverage totals were parsed, but this report did not include per-file data.
        </div>

        <div
          v-else
          class="overflow-x-auto"
        >
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="sticky top-0 bg-surface-overlay text-left text-xs uppercase tracking-[0.18em] text-gray-500">
              <tr>
                <th class="px-3 py-2 font-medium">
                  <button
                    class="inline-flex items-center gap-1.5 transition hover:text-gray-200"
                    type="button"
                    @click="toggleSort('file_path')"
                  >
                    File path
                    <component
                      :is="sortIcon('file_path')"
                      class="h-3.5 w-3.5"
                    />
                  </button>
                </th>
                <th class="px-3 py-2 font-medium">
                  <button
                    class="inline-flex items-center gap-1.5 transition hover:text-gray-200"
                    type="button"
                    @click="toggleSort('line_rate')"
                  >
                    Line coverage
                    <component
                      :is="sortIcon('line_rate')"
                      class="h-3.5 w-3.5"
                    />
                  </button>
                </th>
                <th class="px-3 py-2 font-medium">
                  Branch coverage
                </th>
                <th class="px-3 py-2 font-medium">
                  Lines
                </th>
                <th class="px-3 py-2 font-medium">
                  Branches
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="file in sortedFiles"
                :key="file.file_path"
                class="transition hover:bg-white/5"
              >
                <td class="px-3 py-3 align-top text-gray-200">
                  <div class="font-mono text-xs leading-6 text-gray-200">
                    {{ file.file_path }}
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
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ArrowUpDown, BarChart3, ChevronDown, ChevronUp, FileCode2, GitBranch, Upload } from 'lucide-vue-next'
import { useRoute } from 'vue-router'

import { api, type CoverageReport } from '@/api/client'

type SortField = 'file_path' | 'line_rate'
type SortDirection = 'asc' | 'desc'

const route = useRoute()

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)
const refParam = computed(() => route.query.ref as string | undefined)

const loading = ref(true)
const error = ref('')
const report = ref<CoverageReport | null>(null)
const sortField = ref<SortField>('line_rate')
const sortDirection = ref<SortDirection>('asc')

const sortedFiles = computed(() => {
  const files = [...(report.value?.files ?? [])]

  files.sort((left, right) => {
    if (sortField.value === 'file_path') {
      const comparison = left.file_path.localeCompare(right.file_path)
      return sortDirection.value === 'asc' ? comparison : -comparison
    }

    const leftRate = sortableRate(left.line_rate)
    const rightRate = sortableRate(right.line_rate)
    if (leftRate !== rightRate) {
      return sortDirection.value === 'asc' ? leftRate - rightRate : rightRate - leftRate
    }

    return left.file_path.localeCompare(right.file_path)
  })

  return files
})

const highestLineRate = computed(() => {
  const rates = (report.value?.files ?? [])
    .map((file) => file.line_rate)
    .filter((rate): rate is number => typeof rate === 'number')

  if (rates.length === 0) {
    return null
  }

  return Math.max(...rates)
})

const filesWithLineData = computed(() => (report.value?.files ?? []).filter((file) => file.line_rate !== null).length)

watch(
  [provider, slug, repoSlug, refParam],
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
    const response = await api.getCoverage(provider.value, slug.value, repoSlug.value, { ref: refParam.value })
    report.value = response.data ?? null
  } catch {
    report.value = null
    error.value = 'Failed to load coverage data. Please try again later.'
  } finally {
    loading.value = false
  }
}

function toggleSort(field: SortField) {
  if (sortField.value === field) {
    sortDirection.value = sortDirection.value === 'asc' ? 'desc' : 'asc'
    return
  }

  sortField.value = field
  sortDirection.value = field === 'file_path' ? 'asc' : 'desc'
}

function sortIcon(field: SortField) {
  if (sortField.value !== field) {
    return ArrowUpDown
  }

  return sortDirection.value === 'asc' ? ChevronUp : ChevronDown
}

function sortableRate(rate: number | null) {
  return rate ?? -1
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

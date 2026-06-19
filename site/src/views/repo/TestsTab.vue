<template>
  <div class="space-y-5">
    <div
      v-if="loading"
      class="py-10 text-center text-sm text-gray-500"
    >
      Loading test results...
    </div>

    <div
      v-else-if="!report"
      class="rounded-xl border border-dashed border-surface-border bg-surface-overlay/40 px-5 py-12 text-center text-sm text-gray-400"
    >
      No test results for this {{ snapshotParam ? 'snapshot' : 'ref' }}.
      <p class="mt-1 text-[11px] text-gray-600">
        Upload a JUnit XML report (e.g. gotestsum, pytest, jest/vitest) to populate this tab.
      </p>
    </div>

    <template v-else>
      <!-- Summary tiles -->
      <div class="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <div class="rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-4 py-3">
          <div class="text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
            Pass rate
          </div>
          <div
            class="mt-1.5 text-2xl font-semibold"
            :class="passRateClass"
          >
            {{ passRate }}
          </div>
          <div class="mt-0.5 text-[11px] text-gray-500">
            {{ formatDuration(report.duration_seconds) }}
          </div>
        </div>
        <div class="rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-4 py-3">
          <div class="text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
            Total
          </div>
          <div class="mt-1.5 text-2xl font-semibold text-white">
            {{ report.total }}
          </div>
        </div>
        <div class="rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-4 py-3">
          <div class="text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
            Passed
          </div>
          <div class="mt-1.5 text-2xl font-semibold text-ok">
            {{ report.passed }}
          </div>
        </div>
        <div
          class="rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-4 py-3"
          :class="(report.failed + report.errors) > 0 ? 'border-l-2 border-l-danger/70' : ''"
        >
          <div class="text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
            Failed
          </div>
          <div
            class="mt-1.5 text-2xl font-semibold"
            :class="(report.failed + report.errors) > 0 ? 'text-danger' : 'text-gray-500'"
          >
            {{ report.failed + report.errors }}
          </div>
        </div>
        <div class="rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-4 py-3">
          <div class="text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
            Skipped
          </div>
          <div class="mt-1.5 text-2xl font-semibold text-gray-300">
            {{ report.skipped }}
          </div>
        </div>
      </div>

      <!-- Pass/fail bar -->
      <div class="h-1.5 overflow-hidden rounded-full bg-surface-border-subtle">
        <div class="flex h-full">
          <div
            v-for="segment in barSegments"
            :key="segment.key"
            :class="segment.barClass"
            :style="{ width: `${segment.width}%` }"
          />
        </div>
      </div>

      <FilterBar
        v-model="activeFilters"
        v-model:search-query="searchQuery"
        :filters="filterDefs"
        :total-count="report.cases.length"
        :filtered-count="hasActiveFilters ? filteredCases.length : undefined"
        placeholder="Filter tests... (e.g. status:failed auth)"
      />

      <div class="overflow-hidden rounded-2xl border border-surface-border-subtle">
        <div
          v-if="filteredCases.length === 0"
          class="px-4 py-10 text-sm text-gray-500"
        >
          No tests match the current filters.
        </div>
        <div
          v-else
          class="overflow-x-auto"
        >
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.16em] text-gray-500">
              <tr>
                <th class="px-3 py-2 font-medium">
                  Status
                </th>
                <th class="px-3 py-2 font-medium">
                  Test
                </th>
                <th class="px-3 py-2 font-medium">
                  Duration
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="(testCase, index) in filteredCases"
                :key="`${testCase.suite}-${testCase.name}-${index}`"
                class="align-top transition hover:bg-white/5"
                :class="isFailure(testCase.status) ? 'border-l-2 border-l-danger/70' : 'border-l-2 border-l-transparent'"
              >
                <td class="px-3 py-2.5">
                  <span
                    class="rounded-full px-2.5 py-1 text-xs font-medium"
                    :class="statusClass(testCase.status)"
                  >{{ testCase.status }}</span>
                </td>
                <td class="px-3 py-2.5">
                  <div class="font-medium text-gray-200">
                    {{ testCase.name }}
                  </div>
                  <div class="text-[11px] text-gray-500">
                    <span v-if="testCase.suite">{{ testCase.suite }}</span>
                    <span v-if="testCase.classname"> · {{ testCase.classname }}</span>
                  </div>
                  <pre
                    v-if="testCase.message"
                    class="mt-1.5 max-h-32 overflow-auto whitespace-pre-wrap rounded-md bg-surface-overlay/60 px-2.5 py-1.5 font-mono text-[11px] text-red-300"
                  >{{ testCase.message }}</pre>
                </td>
                <td class="px-3 py-2.5 font-mono text-xs text-gray-400">
                  {{ formatDuration(testCase.duration_seconds) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import { api, type TestCase, type TestReport } from '@/api/client'
import FilterBar from '@/components/FilterBar.vue'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)
const refParam = computed(() => (typeof route.query.ref === 'string' ? route.query.ref : undefined))
const snapshotParam = computed(() => (typeof route.query.snapshot === 'string' ? route.query.snapshot : undefined))

const report = ref<TestReport | null>(null)
const loading = ref(true)
const activeFilters = ref<Record<string, string>>({})
const searchQuery = ref('')

const filterDefs = [
  { key: 'status', label: 'Status', options: ['passed', 'failed', 'error', 'skipped'], multi: true },
]

const hasActiveFilters = computed(() => Object.values(activeFilters.value).some(Boolean) || searchQuery.value.trim().length > 0)

const passRate = computed(() => {
  if (!report.value || report.value.total === 0) {
    return '—'
  }
  return `${Math.round((report.value.passed / report.value.total) * 100)}%`
})
const passRateClass = computed(() => {
  if (!report.value || report.value.total === 0) {
    return 'text-gray-500'
  }
  const rate = report.value.passed / report.value.total
  if (rate >= 0.95) return 'text-ok'
  if (rate >= 0.8) return 'text-sev-medium'
  return 'text-danger'
})

const barSegments = computed(() => {
  if (!report.value || report.value.total === 0) {
    return [{ key: 'empty', width: 100, barClass: 'bg-surface-border-subtle' }]
  }
  const total = report.value.total
  return [
    { key: 'passed', width: (report.value.passed / total) * 100, barClass: 'bg-ok' },
    { key: 'failed', width: ((report.value.failed + report.value.errors) / total) * 100, barClass: 'bg-danger' },
    { key: 'skipped', width: (report.value.skipped / total) * 100, barClass: 'bg-gray-500/70' },
  ].filter((segment) => segment.width > 0)
})

const filteredCases = computed(() => {
  if (!report.value) {
    return []
  }
  const statusFilter = (activeFilters.value.status ?? '').split(',').map((value) => value.trim()).filter(Boolean)
  const query = searchQuery.value.trim().toLowerCase()
  return report.value.cases.filter((testCase) => {
    if (statusFilter.length && !statusFilter.includes(testCase.status)) {
      return false
    }
    if (query) {
      const haystack = [testCase.name, testCase.suite, testCase.classname, testCase.message]
      if (!haystack.some((value) => value.toLowerCase().includes(query))) {
        return false
      }
    }
    return true
  })
})

watch(
  [provider, slug, repoSlug, refParam, snapshotParam],
  async () => {
    if (!provider.value || !slug.value || !repoSlug.value) {
      report.value = null
      return
    }
    loading.value = true
    try {
      const res = await api.getTests(provider.value, slug.value, repoSlug.value, {
        ref: refParam.value,
        snapshot: snapshotParam.value,
      })
      report.value = res.data ?? null
    } catch {
      report.value = null
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

function isFailure(status: string) {
  return status === 'failed' || status === 'error'
}

function statusClass(status: TestCase['status']) {
  const classes: Record<string, string> = {
    passed: 'bg-emerald-500/15 text-emerald-300',
    failed: 'bg-red-500/15 text-red-400',
    error: 'bg-orange-500/15 text-orange-400',
    skipped: 'bg-gray-500/15 text-gray-400',
  }
  return classes[status] || classes.skipped
}

function formatDuration(seconds: number) {
  if (!seconds || seconds <= 0) {
    return '—'
  }
  if (seconds < 1) {
    return `${Math.round(seconds * 1000)}ms`
  }
  if (seconds < 60) {
    return `${seconds.toFixed(2)}s`
  }
  const minutes = Math.floor(seconds / 60)
  return `${minutes}m ${Math.round(seconds % 60)}s`
}
</script>

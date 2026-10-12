<template>
  <div class="space-y-4">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h2 class="text-base font-semibold text-white">
          Scanner coverage
        </h2>
        <p class="mt-1 text-sm text-gray-500">
          What each repository is asked to scan and what actually ran. An enabled scanner that never reported is a gap, not a green cell.
        </p>
      </div>
      <div class="flex items-center gap-2">
        <a
          :href="csvUrl"
          class="rounded-md border border-surface-border px-3 py-1.5 text-xs text-gray-300 transition hover:border-accent/50 hover:text-white"
        >Export CSV</a>
        <button
          v-if="isOrgAdmin"
          type="button"
          class="rounded-md border border-surface-border px-3 py-1.5 text-xs text-gray-300 transition hover:border-accent/50 hover:text-white disabled:opacity-50"
          :disabled="refreshing"
          @click="refresh"
        >
          {{ refreshing ? 'Recomputing…' : 'Recompute' }}
        </button>
      </div>
    </div>

    <section
      v-if="isOrgAdmin"
      class="rounded-lg border border-surface-border p-3 text-xs"
    >
      <div class="flex flex-wrap items-center gap-2">
        <span class="text-gray-400">Change a scanner on every repository where it applies:</span>
        <select
          v-model="bulk.scanner"
          class="rounded-md border border-surface-border bg-surface-overlay px-2 py-1 text-gray-200"
        >
          <option
            v-for="scanner in scannerIds"
            :key="scanner"
            :value="scanner"
          >
            {{ scanner }}
          </option>
        </select>
        <select
          v-model="bulk.mode"
          class="rounded-md border border-surface-border bg-surface-overlay px-2 py-1 text-gray-200"
        >
          <option value="enabled">
            Enable
          </option>
          <option value="disabled">
            Disable
          </option>
        </select>
        <button
          type="button"
          class="rounded-md border border-surface-border px-2 py-1 text-gray-200 hover:border-accent/50 disabled:opacity-50"
          :disabled="!bulk.scanner || bulk.busy"
          @click="previewBulk"
        >
          Preview
        </button>
      </div>
      <div
        v-if="bulk.preview"
        class="mt-2 space-y-1"
      >
        <p class="text-gray-300">
          {{ bulk.preview.changes.length }} {{ bulk.preview.changes.length === 1 ? 'repository' : 'repositories' }} would change<template v-if="bulk.preview.changes.length">
            : {{ bulk.preview.changes.map(change => change.repo_slug).join(', ') }}
          </template>.
        </p>
        <p
          v-if="bulk.preview.kept.length"
          class="text-amber-300"
        >
          Kept, required by the organization: {{ bulk.preview.kept.map(change => change.repo_slug).join(', ') }}.
        </p>
        <button
          v-if="bulk.preview.changes.length"
          type="button"
          class="rounded-md border border-accent/50 px-2 py-1 text-accent disabled:opacity-50"
          :disabled="bulk.busy"
          @click="applyBulk"
        >
          Apply to {{ bulk.preview.changes.length }}
        </button>
      </div>
    </section>

    <div class="flex flex-wrap gap-2 text-xs">
      <button
        v-for="item in summaryChips"
        :key="item.state"
        type="button"
        class="rounded-full border px-2.5 py-1 transition"
        :class="filter.state === item.state ? 'border-accent/60 bg-accent/10 text-white' : 'border-surface-border text-gray-400 hover:text-white'"
        @click="toggleState(item.state)"
      >
        {{ stateLabel(item.state) }} <span class="text-gray-500">{{ item.cells }}</span>
      </button>
      <label class="ml-auto inline-flex items-center gap-1.5 text-gray-400">
        <input
          v-model="filter.required"
          type="checkbox"
          @change="load(1)"
        >
        Required only
      </label>
    </div>

    <p
      v-if="loadError"
      class="text-sm text-danger"
    >
      {{ loadError }}
    </p>
    <p
      v-else-if="!loading && cells.length === 0"
      class="text-sm text-gray-500"
    >
      No cells. Repositories appear here once their scanners are detected; “Recompute” refreshes the whole organization.
    </p>

    <div
      v-if="cells.length"
      class="overflow-x-auto rounded-lg border border-surface-border"
    >
      <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
        <thead class="bg-surface-overlay/60 text-left text-xs uppercase tracking-wide text-gray-500">
          <tr>
            <th class="px-3 py-2">
              Repository
            </th>
            <th class="px-3 py-2">
              Scanner
            </th>
            <th class="px-3 py-2">
              Configured
            </th>
            <th class="px-3 py-2">
              Observed
            </th>
            <th class="px-3 py-2">
              Last run
            </th>
          </tr>
        </thead>
        <tbody class="divide-y divide-surface-border-subtle">
          <tr
            v-for="cell in cells"
            :key="`${cell.repo_id}-${cell.scanner_id}`"
          >
            <td class="px-3 py-2">
              <RouterLink
                :to="{ name: 'repo-settings-scanners', params: { provider, slug, repoSlug: cell.repo_slug } }"
                class="text-gray-200 hover:text-accent"
              >
                {{ cell.repo_slug }}
              </RouterLink>
            </td>
            <td class="px-3 py-2 font-mono text-xs text-gray-300">
              {{ cell.scanner_id }}
            </td>
            <td class="px-3 py-2 text-xs text-gray-400">
              {{ cell.configured }}<span
                v-if="cell.required"
                class="ml-1 rounded-full bg-accent/15 px-1.5 text-[10px] text-accent"
              >{{ cell.enforcement || 'required' }}</span>
            </td>
            <td
              class="px-3 py-2 text-xs"
              :title="cell.reason"
            >
              <span
                class="rounded-full px-2 py-0.5"
                :class="stateClass(cell.state)"
              >{{ stateLabel(cell.state) }}</span>
            </td>
            <td class="px-3 py-2 text-xs text-gray-500">
              <template v-if="cell.last_run_at">
                {{ relativeTime(cell.last_run_at) }} · <span class="font-mono">{{ (cell.last_commit || '').slice(0, 7) }}</span>
              </template>
              <template v-else>
                never
              </template>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div
      v-if="cells.length"
      class="flex items-center justify-end gap-3 text-xs text-gray-400"
    >
      <button
        type="button"
        class="rounded border border-surface-border px-2 py-1 disabled:opacity-40"
        :disabled="page <= 1"
        @click="load(page - 1)"
      >
        Previous
      </button>
      <span>Page {{ page }}</span>
      <button
        type="button"
        class="rounded border border-surface-border px-2 py-1 disabled:opacity-40"
        :disabled="cells.length < perPage"
        @click="load(page + 1)"
      >
        Next
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api, type ScanCoverageCell } from '@/api/client'
import { useOrgRole } from '@/composables/useOrgRole'
import { relativeTime } from '@/lib/datetime'
import { coverageStateClass as stateClass, coverageStateLabel as stateLabel } from '@/lib/scanCoverage'

const route = useRoute()
const provider = route.params.provider as string
const slug = route.params.slug as string
const { isOrgAdmin } = useOrgRole()

const cells = ref<ScanCoverageCell[]>([])
const summary = ref<Array<{ state: string; required: boolean; cells: number }>>([])
const page = ref(1)
const perPage = ref(50)
const loading = ref(true)
const loadError = ref('')
const refreshing = ref(false)
const filter = reactive({ state: '', required: false })

type BulkPreview = { changes: Array<{ repo_slug: string }>; kept: Array<{ repo_slug: string }> }
const bulk = reactive<{ scanner: string; mode: 'enabled' | 'disabled'; busy: boolean; preview: BulkPreview | null }>({ scanner: '', mode: 'enabled', busy: false, preview: null })
const scannerIds = computed(() => [...new Set(cells.value.map(cell => cell.scanner_id))].sort())

async function previewBulk() {
  bulk.busy = true
  try {
    const response = await api.bulkScannerSetting(provider, slug, { scanner_id: bulk.scanner, mode: bulk.mode, dry_run: true })
    bulk.preview = response.data ?? null
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'Could not preview'
  } finally {
    bulk.busy = false
  }
}

async function applyBulk() {
  bulk.busy = true
  try {
    await api.bulkScannerSetting(provider, slug, { scanner_id: bulk.scanner, mode: bulk.mode, dry_run: false })
    bulk.preview = null
    await load(page.value)
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'Could not apply'
  } finally {
    bulk.busy = false
  }
}

// Counts per state; not-applicable cells are shown too, so the denominator
// is disclosed rather than silently dropped (ADR-035 §6).
const summaryChips = computed(() => {
  const byState = new Map<string, number>()
  for (const entry of summary.value) {
    if (filter.required && !entry.required) continue
    byState.set(entry.state, (byState.get(entry.state) ?? 0) + entry.cells)
  }
  return [...byState.entries()].map(([state, count]) => ({ state, cells: count })).sort((a, b) => b.cells - a.cells)
})

const csvUrl = computed(() => api.orgScanCoverageCsvUrl(provider, slug, { state: filter.state, required: filter.required }))

async function load(target = 1) {
  loading.value = true
  loadError.value = ''
  try {
    const response = await api.getOrgScanCoverage(provider, slug, { state: filter.state, required: filter.required, page: target })
    cells.value = response.data?.cells ?? []
    summary.value = response.data?.summary ?? []
    page.value = response.data?.page ?? target
    perPage.value = response.data?.per_page ?? 50
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'Could not load scanner coverage'
  } finally {
    loading.value = false
  }
}

function toggleState(state: string) {
  filter.state = filter.state === state ? '' : state
  void load(1)
}

async function refresh() {
  refreshing.value = true
  try {
    await api.refreshOrgScanCoverage(provider, slug)
  } finally {
    refreshing.value = false
  }
}

onMounted(() => load(1))
</script>

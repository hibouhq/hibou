<template>
  <div class="space-y-5">
    <!-- Tiles -->
    <div class="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <div
        v-for="tile in tiles"
        :key="tile.label"
        class="rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-4 py-3"
        :class="tile.accent"
      >
        <div class="text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
          {{ tile.label }}
        </div>
        <div
          class="mt-1.5 text-2xl font-semibold"
          :class="tile.valueClass"
        >
          {{ tile.value }}
        </div>
      </div>
    </div>

    <!-- Ecosystem breakdown -->
    <section class="overflow-hidden rounded-2xl border border-surface-border-subtle bg-surface-raised/40">
      <div class="border-b border-surface-border-subtle px-4 py-3">
        <h2 class="text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-400">
          Dependency breakdown
        </h2>
      </div>
      <div class="px-4 py-6">
        <div
          v-if="loading"
          class="py-10 text-center text-sm text-gray-500"
        >
          Loading dependencies...
        </div>
        <div
          v-else-if="components.length === 0"
          class="py-10 text-center text-sm text-gray-500"
        >
          No components across this organization.
        </div>
        <EcosystemSunburst
          v-else
          :components="components"
          @select="applyEcosystem"
        />
      </div>
    </section>

    <!-- Components -->
    <section class="space-y-3">
      <div class="flex items-center justify-between">
        <h2 class="text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-400">
          Components
        </h2>
        <div class="flex items-center gap-3">
          <span class="text-xs text-gray-500">{{ components.length }} total</span>
          <button
            type="button"
            class="inline-flex items-center gap-1.5 rounded-lg border border-surface-border bg-surface-overlay/40 px-2.5 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/40 hover:text-accent disabled:cursor-not-allowed disabled:opacity-60"
            :disabled="scanning"
            title="Scan every enrolled repository's current snapshot against enabled advisory providers"
            @click="runOrgComponentScan"
          >
            <RefreshCw
              class="h-3.5 w-3.5"
              :class="scanning ? 'animate-spin' : ''"
            />
            {{ scanning ? 'Scanning...' : 'Scan components' }}
          </button>
        </div>
      </div>

      <p
        v-if="scanMessage || scanError"
        class="text-xs"
        :class="scanError ? 'text-danger' : 'text-ok'"
      >
        {{ scanError || scanMessage }}
      </p>

      <FilterBar
        v-model="activeFilters"
        v-model:search-query="searchQuery"
        v-model:sort-value="currentSort"
        v-model:sort-direction="currentSortDirection"
        :filters="filterDefs"
        :sort-options="sortOptions"
        :sort-direction-options="sortDirectionOptions"
        :total-count="components.length"
        :filtered-count="hasActiveFilters ? filteredComponents.length : undefined"
        placeholder="Filter components... (e.g. ecosystem:npm severity:high)"
      />

      <div class="overflow-hidden rounded-2xl border border-surface-border-subtle">
        <div
          v-if="loading"
          class="px-4 py-10 text-sm text-gray-500"
        >
          Loading components...
        </div>
        <div
          v-else-if="filteredComponents.length === 0"
          class="px-4 py-10 text-sm text-gray-500"
        >
          No components match the current filters.
        </div>
        <div
          v-else
          class="overflow-x-auto"
        >
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.16em] text-gray-500">
              <tr>
                <th class="px-3 py-2 font-medium">
                  Sources
                </th>
                <th class="px-3 py-2 font-medium">
                  Ecosystem
                </th>
                <th class="px-3 py-2 font-medium">
                  Library
                </th>
                <th class="px-3 py-2 font-medium">
                  Version
                </th>
                <th class="px-3 py-2 font-medium">
                  License
                </th>
                <th class="px-3 py-2 font-medium">
                  Repositories
                </th>
                <th class="px-3 py-2 font-medium">
                  Vulns
                </th>
                <th class="px-3 py-2 font-medium">
                  Severity
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="component in filteredComponents"
                :key="component.id"
                class="cursor-pointer transition hover:bg-white/5"
                :class="component.vuln_count > 0 ? 'border-l-2 border-l-danger/70' : 'border-l-2 border-l-transparent'"
                @click="activeComponent = component"
              >
                <td class="px-3 py-2.5">
                  <div
                    v-if="component.sources?.length"
                    class="flex flex-wrap gap-1"
                  >
                    <span
                      v-for="source in component.sources"
                      :key="source"
                      class="rounded-full border border-surface-border px-2 py-0.5 font-mono text-[11px] text-gray-300"
                    >{{ source }}</span>
                  </div>
                  <span
                    v-else
                    class="text-gray-600"
                  >—</span>
                </td>
                <td class="px-3 py-2.5">
                  <span
                    class="eco-badge"
                    :class="`eco-${ecosystemKey(component.ecosystem)}`"
                  >{{ component.ecosystem || 'unknown' }}</span>
                </td>
                <td class="px-3 py-2.5">
                  <div class="font-medium text-gray-200">
                    {{ component.name }}
                  </div>
                  <div
                    class="truncate font-mono text-[11px] text-gray-500"
                    :title="component.purl"
                  >
                    {{ component.purl }}
                  </div>
                </td>
                <td class="px-3 py-2.5 font-mono text-xs text-gray-300">
                  {{ component.version }}
                </td>
                <td class="px-3 py-2.5">
                  <div
                    v-if="component.licenses?.length"
                    class="flex flex-wrap gap-1"
                  >
                    <span
                      v-for="licenseId in component.licenses.slice(0, 2)"
                      :key="licenseId"
                      class="rounded-full border border-surface-border px-2 py-0.5 font-mono text-[11px] text-gray-300"
                    >{{ licenseId }}</span>
                    <span
                      v-if="component.licenses.length > 2"
                      class="text-[11px] text-gray-500"
                      :title="component.licenses.join(', ')"
                    >+{{ component.licenses.length - 2 }}</span>
                  </div>
                  <!-- Absent metadata is a gate-relevant state, not a blank:
                       deny_unknown defaults to true. -->
                  <span
                    v-else
                    class="text-warn"
                    title="No license metadata — fails the gate when deny_unknown is on"
                  >unknown</span>
                </td>
                <td class="px-3 py-2.5">
                  <div class="flex flex-wrap gap-1">
                    <span
                      v-for="repoSlug in component.repos.slice(0, 3)"
                      :key="repoSlug"
                      class="rounded-full border border-surface-border px-2 py-0.5 text-[11px] text-gray-300"
                    >{{ repoSlug }}</span>
                    <span
                      v-if="component.repos.length > 3"
                      class="text-[11px] text-gray-500"
                      :title="component.repos.join(', ')"
                    >+{{ component.repos.length - 3 }}</span>
                  </div>
                </td>
                <td class="px-3 py-2.5">
                  <span
                    class="inline-flex min-w-[1.5rem] items-center justify-center rounded-full px-2 py-0.5 text-xs font-medium"
                    :class="component.vuln_count > 0 ? 'bg-danger/15 text-danger' : 'text-gray-500'"
                  >{{ isScannableEcosystem(component.ecosystem) ? component.vuln_count : '—' }}</span>
                </td>
                <td class="px-3 py-2.5">
                  <span
                    v-if="component.highest_severity"
                    class="rounded-full px-2 py-0.5 text-xs font-medium"
                    :class="`sev-${sevKey(component.highest_severity)}`"
                  >{{ component.highest_severity }}</span>
                  <span
                    v-else
                    class="text-gray-600"
                  >—</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <LibraryDetailModal
      v-if="activeComponent"
      :component="activeComponent"
      @close="activeComponent = null"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { RefreshCw } from 'lucide-vue-next'

import { api, type OrgComponent } from '@/api/client'
import EcosystemSunburst from '@/components/EcosystemSunburst.vue'
import FilterBar from '@/components/FilterBar.vue'
import LibraryDetailModal from '@/components/LibraryDetailModal.vue'
import { ecosystemKey, isScannableEcosystem } from '@/lib/purl'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const components = ref<OrgComponent[]>([])
const loading = ref(true)
const scanning = ref(false)
const scanError = ref('')
const scanMessage = ref('')
const activeComponent = ref<OrgComponent | null>(null)

const activeFilters = ref<Record<string, string>>({})
const searchQuery = ref('')
const currentSort = ref('vulns')
const currentSortDirection = ref('desc')

const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

const ecosystemOptions = computed(() => Array.from(new Set(components.value.map((c) => ecosystemKey(c.ecosystem)))).sort())
const repoOptions = computed(() => Array.from(new Set(components.value.flatMap((c) => c.repos))).sort())
// "unknown" is a real, selectable value here rather than an absence: it is the
// set a deny_unknown policy would flag.
const licenseOptions = computed(() =>
  Array.from(new Set(components.value.map((c) => (c.licenses?.length ? c.licenses : ['unknown'])).flat())).sort(),
)
const severityOptions = ['critical', 'high', 'medium', 'low', 'info']

const filterDefs = computed(() => [
  { key: 'ecosystem', label: 'Ecosystem', options: ecosystemOptions.value, multi: true },
  { key: 'repo', label: 'Repository', options: repoOptions.value, multi: true },
  { key: 'license', label: 'License', options: licenseOptions.value, multi: true },
  { key: 'severity', label: 'Severity', options: severityOptions, multi: true },
  { key: 'vulnerable', label: 'Vulnerable', options: ['yes', 'no'], multi: false },
])
const sortOptions = [
  { key: 'vulns', label: 'Vulns' },
  { key: 'name', label: 'Name' },
  { key: 'severity', label: 'Severity' },
]
const sortDirectionOptions = [
  { key: 'desc', label: '↓ Desc' },
  { key: 'asc', label: '↑ Asc' },
]

const hasActiveFilters = computed(() => Object.values(activeFilters.value).some(Boolean) || searchQuery.value.trim().length > 0)

const tiles = computed(() => {
  const vulnerable = components.value.filter((c) => c.vuln_count > 0).length
  const ecosystems = new Set(components.value.map((c) => ecosystemKey(c.ecosystem))).size
  const repos = repoOptions.value.length
  return [
    { label: 'Components', value: components.value.length, accent: '', valueClass: 'text-white' },
    { label: 'Vulnerable', value: vulnerable, accent: vulnerable > 0 ? 'border-l-2 border-l-danger/70' : '', valueClass: vulnerable > 0 ? 'text-danger' : 'text-ok' },
    { label: 'Ecosystems', value: ecosystems, accent: '', valueClass: 'text-white' },
    { label: 'Repositories', value: repos, accent: '', valueClass: 'text-white' },
  ]
})

const filteredComponents = computed(() => {
  const list = components.value.filter(matchesFilters)
  const direction = currentSortDirection.value === 'asc' ? 1 : -1
  return [...list].sort((a, b) => {
    let result = 0
    if (currentSort.value === 'name') {
      result = a.name.localeCompare(b.name)
    } else if (currentSort.value === 'severity') {
      result = (SEVERITY_RANK[sevKey(a.highest_severity ?? '')] ?? 0) - (SEVERITY_RANK[sevKey(b.highest_severity ?? '')] ?? 0)
    } else {
      result = a.vuln_count - b.vuln_count
    }
    if (result === 0) {
      return a.name.localeCompare(b.name)
    }
    return result * direction
  })
})

watch(
  [provider, slug],
  async () => {
    if (!provider.value || !slug.value) {
      components.value = []
      return
    }
    loading.value = true
    try {
      const res = await api.listOrgComponents(provider.value, slug.value)
      components.value = res.data
    } catch {
      components.value = []
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

function matchesFilters(component: OrgComponent): boolean {
  const ecoFilter = splitFilter(activeFilters.value.ecosystem)
  if (ecoFilter.length && !ecoFilter.includes(ecosystemKey(component.ecosystem))) {
    return false
  }
  const severityFilter = splitFilter(activeFilters.value.severity)
  if (severityFilter.length && !severityFilter.includes(sevKey(component.highest_severity ?? ''))) {
    return false
  }
  const repoFilter = splitFilter(activeFilters.value.repo)
  if (repoFilter.length && !repoFilter.some((repoSlug) => component.repos.includes(repoSlug))) {
    return false
  }
  const licenseFilter = splitFilter(activeFilters.value.license)
  if (licenseFilter.length) {
    const componentLicenses = component.licenses?.length ? component.licenses : ['unknown']
    if (!licenseFilter.some((licenseId) => componentLicenses.includes(licenseId))) {
      return false
    }
  }
  const vulnerable = activeFilters.value.vulnerable
  if (vulnerable === 'yes' && component.vuln_count === 0) {
    return false
  }
  if (vulnerable === 'no' && component.vuln_count > 0) {
    return false
  }
  const query = searchQuery.value.trim().toLowerCase()
  if (query) {
    const haystack = [component.name, component.version, component.purl, ...component.repos, ...(component.licenses ?? [])]
    if (!haystack.some((value) => value.toLowerCase().includes(query))) {
      return false
    }
  }
  return true
}

async function runOrgComponentScan() {
  if (!provider.value || !slug.value || scanning.value) return
  scanning.value = true
  scanError.value = ''
  scanMessage.value = ''
  try {
    const response = await api.triggerOrgComponentScan(provider.value, slug.value)
    const res = await api.listOrgComponents(provider.value, slug.value)
    components.value = res.data
    const failed = response.data.failed?.length ? ` (${response.data.failed.length} repos failed)` : ''
    scanMessage.value = `Scanned ${response.data.scans.length} repositories with ${response.data.providers.join(', ')}${failed}.`
  } catch (error) {
    scanError.value = error instanceof Error ? error.message : 'Failed to trigger component scan'
  } finally {
    scanning.value = false
  }
}

function applyEcosystem(ecosystem: string) {
  activeFilters.value = { ...activeFilters.value, ecosystem: ecosystemKey(ecosystem) }
}

function splitFilter(value: string | undefined): string[] {
  return (value ?? '').split(',').map((item) => item.trim()).filter(Boolean)
}

function sevKey(severity: string): string {
  const value = (severity || '').toLowerCase().replace(/[. ]/g, '')
  if (value === 'critical' || value === 'veryhigh') return 'critical'
  if (value === 'high') return 'high'
  if (value === 'medium' || value === 'moderate') return 'medium'
  if (value === 'info' || value === 'informational' || value === 'none') return 'info'
  if (!value) return ''
  return 'low'
}
</script>

<template>
  <div class="space-y-5">
    <!-- Summary tiles -->
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
        <div
          v-if="tile.hint"
          class="mt-0.5 text-[11px] text-gray-500"
        >
          {{ tile.hint }}
        </div>
      </div>
    </div>

    <!-- Dependency visualization -->
    <section class="overflow-hidden rounded-2xl border border-surface-border-subtle bg-surface-raised/40">
      <div class="flex items-center justify-between border-b border-surface-border-subtle px-4 py-3">
        <h2 class="text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-400">
          Dependency Visualization
        </h2>
        <div class="inline-flex overflow-hidden rounded-lg border border-surface-border text-xs">
          <button
            v-for="mode in ['tree', 'graph']"
            :key="mode"
            type="button"
            class="px-3 py-1 font-medium capitalize transition"
            :class="viewMode === mode ? 'bg-accent/15 text-accent' : 'text-gray-400 hover:text-gray-200'"
            @click="viewMode = mode as ViewMode"
          >
            {{ mode }}
          </button>
        </div>
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
          No components found for this {{ selectedSnapshot ? 'snapshot' : 'ref' }}.
        </div>

        <EcosystemSunburst
          v-else-if="viewMode === 'tree'"
          :components="components"
          @select="applyEcosystem"
        />

        <div
          v-else
          class="space-y-3"
        >
          <div class="rounded-xl border border-dashed border-surface-border bg-surface-overlay/30 px-5 py-10 text-center">
            <p class="text-sm text-gray-400">
              The interactive dependency graph needs the SBOM dependency relationships
              (nodes + edges) from the backend.
            </p>
            <p class="mt-1 text-[11px] text-gray-600">
              Tracked in <span class="font-mono">TODO-BACKEND-deps-nodata.md</span> §2. Use the
              <button
                type="button"
                class="text-accent hover:underline"
                @click="viewMode = 'tree'"
              >
                tree view
              </button>
              meanwhile.
            </p>
          </div>
        </div>
      </div>
    </section>

    <!-- Components -->
    <section class="space-y-3">
      <div class="flex items-center justify-between">
        <h2 class="text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-400">
          Components
        </h2>
        <span class="text-xs text-gray-500">{{ components.length }} total</span>
      </div>

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
        placeholder="Filter components... (e.g. ecosystem:npm severity:high nuxt)"
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
                  Fixed
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
                @click="openComponent(component)"
              >
                <td class="px-3 py-2.5">
                  <div class="flex flex-wrap gap-1">
                    <span
                      v-for="source in (component.sources ?? [])"
                      :key="source"
                      class="source-badge"
                      :class="`source-${sourceKey(source)}`"
                    >{{ source }}</span>
                    <span
                      v-if="!(component.sources ?? []).length"
                      class="text-gray-600"
                    >—</span>
                  </div>
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
                <td class="px-3 py-2.5 font-mono text-xs">
                  <span :class="component.fixed_versions?.length ? 'text-ok' : 'text-gray-600'">
                    {{ component.fixed_versions?.join(', ') || '—' }}
                  </span>
                </td>
                <td class="px-3 py-2.5">
                  <span
                    class="inline-flex min-w-[1.5rem] items-center justify-center rounded-full px-2 py-0.5 text-xs font-medium"
                    :class="component.vuln_count > 0 ? 'bg-danger/15 text-danger' : 'text-gray-500'"
                  >{{ component.vuln_count }}</span>
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

import { api, type ComponentWithVulns } from '@/api/client'
import EcosystemSunburst from '@/components/EcosystemSunburst.vue'
import FilterBar from '@/components/FilterBar.vue'
import LibraryDetailModal from '@/components/LibraryDetailModal.vue'
import { ecosystemKey, sourceKey } from '@/lib/purl'

type ViewMode = 'tree' | 'graph'

const route = useRoute()

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)
const selectedRef = computed(() => typeof route.query.ref === 'string' ? route.query.ref : undefined)
const selectedSnapshot = computed(() => typeof route.query.snapshot === 'string' ? route.query.snapshot : undefined)

const components = ref<ComponentWithVulns[]>([])
const loading = ref(true)
const viewMode = ref<ViewMode>('tree')
const activeComponent = ref<ComponentWithVulns | null>(null)

const activeFilters = ref<Record<string, string>>({})
const searchQuery = ref('')
const currentSort = ref('vulns')
const currentSortDirection = ref('desc')

const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

const ecosystemOptions = computed(() => Array.from(new Set(components.value.map((component) => ecosystemKey(component.ecosystem)))).sort())
const sourceOptions = computed(() => Array.from(new Set(components.value.flatMap((component) => component.sources ?? []))).sort())
const severityOptions = ['critical', 'high', 'medium', 'low', 'info']

const filterDefs = computed(() => [
  { key: 'ecosystem', label: 'Ecosystem', options: ecosystemOptions.value, multi: true },
  { key: 'source', label: 'Sources', options: sourceOptions.value, multi: true },
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
  const vulnerable = components.value.filter((component) => component.vuln_count > 0).length
  const ecosystems = new Set(components.value.map((component) => ecosystemKey(component.ecosystem))).size
  const sourceCount = sourceOptions.value.length

  return [
    { label: 'Components', value: components.value.length, hint: '', accent: '', valueClass: 'text-white' },
    { label: 'Vulnerable', value: vulnerable, hint: '', accent: vulnerable > 0 ? 'border-l-2 border-l-danger/70' : '', valueClass: vulnerable > 0 ? 'text-danger' : 'text-ok' },
    { label: 'Ecosystems', value: ecosystems, hint: '', accent: '', valueClass: 'text-white' },
    { label: 'Sources', value: sourceCount || '—', hint: sourceCount ? '' : 'backend TODO', accent: '', valueClass: sourceCount ? 'text-white' : 'text-gray-500' },
  ]
})

function matchesFilters(component: ComponentWithVulns): boolean {
  const ecoFilter = splitFilter(activeFilters.value.ecosystem)
  if (ecoFilter.length && !ecoFilter.includes(ecosystemKey(component.ecosystem))) {
    return false
  }

  const severityFilter = splitFilter(activeFilters.value.severity)
  if (severityFilter.length && !severityFilter.includes(sevKey(component.highest_severity ?? ''))) {
    return false
  }

  const sourceFilter = splitFilter(activeFilters.value.source)
  if (sourceFilter.length) {
    const componentSources = (component.sources ?? []).map((source) => source.toLowerCase())
    if (!sourceFilter.some((source) => componentSources.includes(source.toLowerCase()))) {
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
    const haystack = [
      component.name,
      component.version,
      component.purl,
      ...(component.advisories?.map((advisory) => `${advisory.canonical_id} ${advisory.title}`) ?? []),
    ]
    if (!haystack.some((value) => value.toLowerCase().includes(query))) {
      return false
    }
  }

  return true
}

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
      result = a.name.localeCompare(b.name)
      return result
    }
    return result * direction
  })
})

watch(
  [provider, slug, repoSlug, selectedRef, selectedSnapshot],
  async () => {
    if (!provider.value || !slug.value || !repoSlug.value) {
      components.value = []
      return
    }

    loading.value = true
    try {
      const res = await api.listRefComponents(provider.value, slug.value, repoSlug.value, {
        ref: selectedRef.value,
        snapshot: selectedSnapshot.value,
      })
      components.value = res.data
    } catch {
      components.value = []
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

function openComponent(component: ComponentWithVulns) {
  activeComponent.value = component
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

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
          <DependencyGraph
            v-if="graph && graph.nodes.length > 0 && graphHasDependencyEdges"
            :graph="graph"
            :focused-ref="focusedNodeRef"
            @select="selectGraphNode"
          />
          <div
            v-else-if="graph && graph.nodes.length > 0"
            class="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/[0.06] px-4 py-3 text-sm text-amber-200"
          >
            <TriangleAlert class="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
            <div>
              <p class="font-medium">Dependency graph unavailable for this SBOM.</p>
              <p class="mt-0.5 text-xs text-amber-300/70">
                SPDX SBOMs don't record dependency relationships, so the graph can't be drawn. Upload a CycloneDX SBOM to see the full dependency graph - the components are still listed below.
              </p>
            </div>
          </div>
          <div
            v-else
            class="rounded-xl border border-dashed border-surface-border bg-surface-overlay/30 px-5 py-10 text-center"
          >
            <p class="text-sm text-gray-400">
              Dependency graph unavailable for this {{ selectedSnapshot ? 'snapshot' : 'ref' }}.
            </p>
            <p class="mt-1 text-[11px] text-gray-600">
              Component details still work; usage chains appear when graph data loads successfully.
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
        <div class="flex items-center gap-3">
          <span class="text-xs text-gray-500">{{ components.length }} total</span>
          <button
            type="button"
            class="inline-flex items-center gap-1.5 rounded-lg border border-surface-border bg-surface-overlay/40 px-2.5 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/40 hover:text-accent disabled:cursor-not-allowed disabled:opacity-60"
            :disabled="scanning || scanUnavailable"
            :title="scanUnavailable ? scanError : 'Scan current snapshot components against enabled advisory providers'"
            @click="runComponentScan"
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
                  <div class="flex items-start justify-between gap-2">
                    <div class="min-w-0">
                      <div class="font-medium text-gray-200">
                        {{ component.name }}
                      </div>
                      <div
                        class="truncate font-mono text-[11px] text-gray-500"
                        :title="component.purl"
                      >
                        {{ component.purl }}
                      </div>
                    </div>
                    <button
                      type="button"
                      class="rounded-md p-1 text-gray-500 transition hover:bg-white/5 hover:text-accent"
                      :aria-label="`Locate ${component.name} in graph`"
                      :title="`Locate ${component.name} in graph`"
                      @click.stop="locateComponent(component)"
                    >
                      <Workflow class="h-4 w-4" />
                    </button>
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
                    :class="component.vuln_count > 0 ? 'vuln-count' : 'text-gray-500'"
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
import { RefreshCw, TriangleAlert, Workflow } from 'lucide-vue-next'
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import { api, type ComponentGraph, type ComponentGraphNode, type ComponentWithVulns } from '@/api/client'
import DependencyGraph from '@/components/DependencyGraph.vue'
import EcosystemSunburst from '@/components/EcosystemSunburst.vue'
import FilterBar from '@/components/FilterBar.vue'
import LibraryDetailModal from '@/components/LibraryDetailModal.vue'
import { ecosystemKey, isScannableEcosystem, parsePurl, sourceKey } from '@/lib/purl'

type ViewMode = 'tree' | 'graph'

const route = useRoute()

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)
const selectedRef = computed(() => typeof route.query.ref === 'string' ? route.query.ref : undefined)
const selectedSnapshot = computed(() => typeof route.query.snapshot === 'string' ? route.query.snapshot : undefined)

const components = ref<ComponentWithVulns[]>([])
const graph = ref<ComponentGraph | null>(null)
const graphHasDependencyEdges = computed(() =>
  Boolean(graph.value?.edges?.some((edge) => (edge.depends_on?.length ?? 0) > 0)),
)
const loading = ref(true)
const scanning = ref(false)
const scanError = ref('')
const scanMessage = ref('')
const viewMode = ref<ViewMode>('tree')
const activeComponent = ref<ComponentWithVulns | null>(null)
const focusedNodeRef = ref<string | null>(null)

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
const scanUnavailable = computed(() => {
  const message = scanError.value.toLowerCase()
  return message.includes('advisory scanning is not enabled') || message.includes('no advisory providers are configured')
})

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
    const componentSources = new Set((component.sources ?? []).map((source) => source.toLowerCase()))
    if (!sourceFilter.some((source) => componentSources.has(source.toLowerCase()))) {
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

async function loadComponents(options?: { resetSelection?: boolean; clearScanStatus?: boolean }) {
  const resetSelection = options?.resetSelection ?? true
  const clearScanStatus = options?.clearScanStatus ?? true

  if (!provider.value || !slug.value || !repoSlug.value) {
    components.value = []
    graph.value = null
    if (clearScanStatus) {
      scanError.value = ''
      scanMessage.value = ''
    }
    return
  }

  loading.value = true
  if (resetSelection) {
    activeComponent.value = null
    focusedNodeRef.value = null
  }
  if (clearScanStatus) {
    scanError.value = ''
    scanMessage.value = ''
  }

  try {
    const params = {
      ref: selectedRef.value,
      snapshot: selectedSnapshot.value,
    }
    const [componentsRes, graphRes] = await Promise.allSettled([
      api.listRefComponents(provider.value, slug.value, repoSlug.value, params),
      api.getComponentGraph(provider.value, slug.value, repoSlug.value, params),
    ])

    components.value = componentsRes.status === 'fulfilled' ? componentsRes.value.data : []
    graph.value = graphRes.status === 'fulfilled' ? graphRes.value.data : null
  } catch {
    components.value = []
    graph.value = null
  } finally {
    loading.value = false
  }
}

async function runComponentScan() {
  if (!provider.value || !slug.value || !repoSlug.value || scanning.value || scanUnavailable.value) {
    return
  }

  scanning.value = true
  scanError.value = ''
  scanMessage.value = ''

  try {
    const response = await api.triggerComponentScan(provider.value, slug.value, repoSlug.value, {
      ref: selectedRef.value,
      snapshot: selectedSnapshot.value,
    })
    await loadComponents({ resetSelection: false, clearScanStatus: false })

    const providers = response.data.providers.join(', ')
    scanMessage.value = providers ? `Component scan completed with ${providers}.` : 'Component scan completed.'
  } catch (error) {
    scanError.value = error instanceof Error ? error.message : 'Failed to trigger component scan'
  } finally {
    scanning.value = false
  }
}

watch(
  [provider, slug, repoSlug, selectedRef, selectedSnapshot],
  async () => {
    await loadComponents()
  },
  { immediate: true },
)

function openComponent(component: ComponentWithVulns) {
  activeComponent.value = {
    ...component,
    usage_paths: computeUsagePaths(component.purl),
  }
  focusedNodeRef.value = component.purl
}

function locateComponent(component: ComponentWithVulns) {
  viewMode.value = 'graph'
  focusedNodeRef.value = component.purl
}

function selectGraphNode(purl: string) {
  focusedNodeRef.value = purl
  const component = components.value.find((entry) => entry.purl === purl)
  if (component) {
    openComponent(component)
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

function computeUsagePaths(targetPurl: string): string[][] {
  const currentGraph = graph.value
  if (!currentGraph?.root_ref || !targetPurl) {
    return []
  }

  const nodesByRef = new Map(currentGraph.nodes.map((node) => [node.ref, node]))
  if (!nodesByRef.has(currentGraph.root_ref) || !nodesByRef.has(targetPurl)) {
    return []
  }

  const adjacency = new Map<string, string[]>()
  for (const edge of currentGraph.edges) {
    adjacency.set(edge.ref, edge.depends_on.filter((child) => nodesByRef.has(child)))
  }

  const MAX_PATHS = 12
  const MAX_DEPTH = 14
  const MAX_STEPS = 5000
  const paths: string[][] = []
  const currentPath: string[] = []
  const visited = new Set<string>()
  let steps = 0

  const consumeStep = (): boolean => {
    steps += 1
    return steps <= MAX_STEPS
  }

  const walk = (currentRef: string, depth: number) => {
    if (paths.length >= MAX_PATHS || depth > MAX_DEPTH || visited.has(currentRef)) {
      return
    }
    if (!consumeStep()) {
      return
    }

    visited.add(currentRef)
    currentPath.push(currentRef)

    if (currentRef === targetPurl) {
      paths.push(currentPath.map((ref) => nodeDisplayLabel(nodesByRef.get(ref))))
    } else {
      for (const childRef of adjacency.get(currentRef) ?? []) {
        if (paths.length >= MAX_PATHS) {
          break
        }
        if (!consumeStep()) {
          break
        }
        walk(childRef, depth + 1)
      }
    }

    currentPath.pop()
    visited.delete(currentRef)
  }

  walk(currentGraph.root_ref, 0)
  return paths
}

function nodeDisplayLabel(node: ComponentGraphNode | undefined): string {
  if (!node) {
    return 'unknown'
  }
  return node.name || shortPurl(node.ref)
}

function shortPurl(purl: string): string {
  const parsed = parsePurl(purl)
  if (!parsed) {
    return purl.length > 36 ? `${purl.slice(0, 33)}...` : purl
  }
  return parsed.namespace ? `${parsed.namespace}/${parsed.name}` : parsed.name || purl
}
</script>

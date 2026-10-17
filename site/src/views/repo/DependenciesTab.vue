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
          <!-- A ref without inventory asks for one on first read (ADR-045
               §4.1.1); the state here says whether it is on its way. -->
          <template v-if="extractionPending">
            <RefreshCw class="mx-auto mb-2 h-4 w-4 animate-spin text-accent" />
            Extracting dependencies from the repository{{ extraction?.job?.status === 'processing' ? '…' : ' (queued)…' }}
          </template>
          <template v-else-if="extraction?.job?.status === 'failed' && extraction.job.last_error">
            <p class="text-warn">
              Dependency extraction failed.
            </p>
            <p class="mt-1 font-mono text-[11px] text-gray-500">
              {{ extraction.job.last_error }}
            </p>
          </template>
          <template v-else-if="extraction?.run && extraction.run.component_count === 0">
            No lockfile or manifest recognised at this commit.
          </template>
          <template v-else>
            No components found for this {{ selectedSnapshot ? 'snapshot' : 'ref' }}.
          </template>
          <div
            v-if="extraction?.enabled && !selectedSnapshot && !extractionPending"
            class="mt-3"
          >
            <button
              type="button"
              class="rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/50 hover:text-white disabled:opacity-50"
              :disabled="extracting"
              @click="requestExtraction"
            >
              {{ extracting ? 'Requesting…' : 'Extract dependencies now' }}
            </button>
          </div>
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
              <p class="font-medium">
                Dependency graph unavailable for this SBOM.
              </p>
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

      <p
        v-if="components.length > 0 && shippedCount !== components.length"
        class="mb-2 text-xs text-gray-500"
      >
        <span class="text-gray-300">{{ shippedCount }}</span> shipped · {{ components.length }} total
      </p>

      <!-- Declared-scope suggestions (ADR-045 §6): dev and test scopes are
           suggestions, never automatic. The entries belong in .hibou.yaml,
           reviewed in a pull request, so the action copies them. -->
      <div
        v-if="shipping && scopeSuggestions.length > 0"
        class="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-3 py-2 text-xs text-gray-400"
      >
        <span>
          <span class="text-gray-200">{{ scopeSuggestions.length }}</span> shipped components are declared dev or test
          ({{ suggestionScopes.join(', ') }}): not shipped? Add them to
          <span class="font-mono">dependencies.not_shipped</span> in <span class="font-mono">.hibou.yaml</span>.
        </span>
        <button
          type="button"
          class="rounded-md border border-surface-border px-2 py-1 text-gray-300 transition hover:border-accent/50 hover:text-white"
          title="Copy the .hibou.yaml entries for these packages"
          @click="copyScopeSuggestions"
        >
          Copy {{ scopeSuggestions.length }} {{ scopeSuggestions.length === 1 ? 'entry' : 'entries' }}
        </button>
      </div>

      <div
        v-if="shipping?.undeclared_modules?.length"
        class="mb-3 rounded-xl border border-warn/30 bg-surface-overlay/40 px-3 py-2 text-xs text-gray-400"
        title="An SBOM was uploaded, but .hibou.yaml does not say what it covers (dependencies.sbom_covers)"
      >
        <span class="text-gray-200">{{ shipping.undeclared_modules.map((m) => `${m}/`).join(', ') }}</span>
        {{ shipping.undeclared_modules.length === 1 ? 'is' : 'are' }} not in the uploaded SBOM: shipped or not? Declare
        <span class="font-mono">dependencies.sbom_covers</span> in <span class="font-mono">.hibou.yaml</span>, or list the modules as not shipped.
      </div>

      <!-- Not-shipped lists (ADR-045 §6): every entry with where it comes
           from, read-only. Repository entries are edited in .hibou.yaml,
           organization entries in the org settings. Entries recorded here
           before that can still be removed. -->
      <details
        v-if="shipping"
        class="mb-3 rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-3 py-2 text-xs text-gray-400"
      >
        <summary class="cursor-pointer select-none">
          <span class="uppercase tracking-[0.16em] text-gray-500">Not shipped</span>
          <span class="ml-2">{{ shipping.entries.length }} {{ shipping.entries.length === 1 ? 'entry' : 'entries' }}</span>
          <span
            v-if="shipping.uploaded_sbom"
            class="ml-2 text-gray-500"
          >· an uploaded SBOM decides what ships{{ shipping.sbom_covers?.length ? ` for ${shipping.sbom_covers.join(', ')}` : '' }}</span>
        </summary>
        <ul class="mt-2 divide-y divide-surface-border-subtle">
          <li
            v-for="entry in shipping.entries"
            :key="`${entry.source}:${entry.pattern}`"
            class="flex flex-wrap items-center justify-between gap-2 py-1.5"
            :class="entry.overridden ? 'line-through opacity-60' : ''"
            :title="entry.overridden ? 'Cancelled by dependencies.shipped in .hibou.yaml' : entry.reason || ''"
          >
            <span class="flex flex-wrap items-center gap-2">
              <span class="font-mono text-gray-300">{{ entry.pattern }}</span>
              <span class="rounded border border-surface-border px-1 py-px text-[10px] uppercase tracking-wide text-gray-500">{{ entry.source }}</span>
              <span
                v-if="entry.reason && entry.source !== 'default'"
                class="text-gray-500"
              >{{ entry.reason }}</span>
            </span>
            <button
              v-if="shipping.can_edit && entry.source === 'repository' && entry.id"
              type="button"
              class="text-gray-500 transition hover:text-danger"
              title="Remove this entry, recorded from the UI: new entries go in .hibou.yaml"
              @click="removeNotShipped(entry.id)"
            >
              remove
            </button>
          </li>
        </ul>
        <p class="mt-2 text-gray-500">
          Edit the repository list in <span class="font-mono text-gray-300">.hibou.yaml</span> under
          <span class="font-mono text-gray-300">dependencies.not_shipped</span>, reviewed like any change;
          organization entries are in the organization settings.
        </p>
        <p
          v-if="shippingError"
          class="mt-1 text-danger"
        >
          {{ shippingError }}
        </p>
      </details>

      <p
        v-if="extraction?.run && extraction.current_extractor_version && extraction.run.extractor_version !== extraction.current_extractor_version"
        class="mb-2 text-xs text-gray-500"
        title="A newer extractor may read more formats; the upgrade pass re-extracts eager branches and releases"
      >
        Extracted with <span class="font-mono">{{ extraction.run.extractor_version }}</span> · current <span class="font-mono">{{ extraction.current_extractor_version }}</span>
      </p>

      <!-- Install-time cooldown (ADR-048 §3.1): the gate holds a merge, only
           the package manager's own setting keeps a fresh version off a
           build. One entry per module and tool, from the last extraction. -->
      <div
        v-if="installConfigRows.length > 0"
        class="mb-3 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-3 py-2 text-xs text-gray-400"
      >
        <span class="uppercase tracking-[0.16em] text-gray-500">Install-time cooldown</span>
        <span
          v-for="row in installConfigRows"
          :key="row.key"
          class="inline-flex items-center gap-1"
          :title="row.title"
        >
          <ShieldCheck
            v-if="row.present"
            class="signal-icon text-ok"
          />
          <ShieldOff
            v-else
            class="signal-icon signal-cooldown"
          />
          <span class="font-mono">{{ row.label }}</span>
        </span>
      </div>

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
                      <!-- Provenance (ADR-045 §5): relationship and declared
                           scopes, with the module in a monorepo. Nothing is
                           shown when no inventory source said. -->
                      <div
                        v-if="provenanceLine(component)"
                        class="text-[11px] text-gray-500"
                        :title="provenanceTitle(component)"
                      >
                        {{ provenanceLine(component) }}
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
                <td class="px-3 py-2.5 text-xs text-gray-300">
                  <span class="inline-flex items-center gap-1.5 whitespace-nowrap">
                    <span class="font-mono">{{ component.version }}</span>
                    <!-- deps.dev signals (ADR-048): attributes of the version,
                         not vulnerabilities. Icons only: the table is already
                         wide. No icon means not evaluated. -->
                    <Clock
                      v-if="component.signals?.in_cooldown"
                      class="signal-icon signal-cooldown"
                      :title="`In cooldown: published ${relativeDate(component.signals.published_at)}, deps.dev recommends waiting until ${shortDate(component.signals.cooldown_until)}`"
                    />
                    <EyeOff
                      v-if="component.signals?.unpublished"
                      class="signal-icon signal-unpublished"
                      title="Unpublished: this version is no longer on the public registry"
                    />
                    <Archive
                      v-if="component.signals?.deprecated"
                      class="signal-icon signal-deprecated"
                      :title="`Deprecated: ${component.signals.deprecated_reason || 'deprecated on the registry'}`"
                    />
                    <TriangleAlert
                      v-if="component.signals?.low_usage"
                      class="signal-icon signal-low-usage"
                      :title="component.signals.alternatives?.length ? `Low usage: did you mean ${component.signals.alternatives.join(', ')}?` : 'Low usage: verify this is the package you meant'"
                    />
                  </span>
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
                    class="text-warn text-[11px]"
                    title="No license metadata — fails the gate when deny_unknown is on"
                  >unknown</span>
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
                  <span class="inline-flex items-center gap-1.5">
                    <MalwareIcon
                      v-if="isMalwareComponent(component)"
                      size="sm"
                    />
                    <span
                      v-if="component.highest_severity"
                      class="rounded-full px-2 py-0.5 text-xs font-medium"
                      :class="`sev-${sevKey(component.highest_severity)}`"
                    >{{ component.highest_severity }}</span>
                    <span
                      v-else
                      class="text-gray-600"
                    >—</span>
                  </span>
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
      :can-mark-not-shipped="Boolean(shipping)"
      @close="closeComponent"
      @open-finding="openFinding"
      @mark-not-shipped="markNotShipped"
    />
  </div>
</template>

<script setup lang="ts">
import { Archive, Clock, EyeOff, RefreshCw, ShieldCheck, ShieldOff, TriangleAlert, Workflow } from 'lucide-vue-next'
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, type ComponentGraph, type ComponentGraphNode, type ComponentWithVulns, type DepExtractionStatus, type ShippingInfo } from '@/api/client'
import { isMalwareComponent } from '@/lib/findingDisplay'
import DependencyGraph from '@/components/DependencyGraph.vue'
import MalwareIcon from '@/components/finding/MalwareIcon.vue'
import EcosystemSunburst from '@/components/EcosystemSunburst.vue'
import FilterBar from '@/components/FilterBar.vue'
import LibraryDetailModal from '@/components/LibraryDetailModal.vue'
import { useToast } from '@/composables/useToast'
import { ecosystemKey, isScannableEcosystem, parsePurl, sourceKey } from '@/lib/purl'

type ViewMode = 'tree' | 'graph'

const route = useRoute()
const router = useRouter()

const { pushToast } = useToast()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)
const selectedRef = computed(() => typeof route.query.ref === 'string' ? route.query.ref : undefined)
const selectedSnapshot = computed(() => typeof route.query.snapshot === 'string' ? route.query.snapshot : undefined)

const components = ref<ComponentWithVulns[]>([])
// Built-in extraction state for an empty ref (ADR-045 §4.1.1), polled while
// a job is queued or running so the table fills in on its own.
const extraction = ref<DepExtractionStatus | null>(null)
const extracting = ref(false)
const extractionPending = computed(() => extraction.value?.job?.status === 'pending' || extraction.value?.job?.status === 'processing')
let extractionTimer: ReturnType<typeof setTimeout> | null = null

function humanWindow(seconds?: number): string {
  if (!seconds || seconds <= 0) return ''
  if (seconds % 86400 === 0) return `${seconds / 86400}d`
  if (seconds % 3600 === 0) return `${seconds / 3600}h`
  return `${Math.round(seconds / 60)}min`
}

/** One row per module and package manager: present with its window, or missing. */
const installConfigRows = computed(() => {
  const run = extraction.value?.run
  if (!run) return []
  const rows: Array<{ key: string; label: string; title: string; present: boolean }> = []
  for (const module of run.modules ?? []) {
    for (const setting of module.install_config ?? []) {
      const where = module.path === '.' || module.path === '' ? '' : `${module.path}/ `
      const window = humanWindow(setting.window_seconds)
      rows.push({
        key: `${module.path}:${setting.tool}`,
        present: setting.present,
        label: `${where}${setting.tool} ${setting.present ? window || 'set' : 'missing'}`,
        title: setting.present
          ? `${setting.setting} = ${setting.value ?? ''} in ${setting.path}${setting.note ? ` (${setting.note})` : ''}`
          : `No ${setting.setting} in ${setting.path}: ${setting.tool} installs a fresh version the moment it is published${setting.note ? ` (${setting.note})` : ''}`,
      })
    }
  }
  for (const updater of run.updaters ?? []) {
    const window = humanWindow(updater.window_seconds)
    rows.push({
      key: `updater:${updater.tool}`,
      present: updater.present,
      label: `${updater.tool} ${updater.present ? window || 'set' : 'no cooldown'}`,
      title: updater.present ? `${updater.tool} waits ${window} before proposing a version (${updater.path})` : `${updater.tool} proposes versions as soon as they are published (${updater.path})`,
    })
  }
  return rows
})

async function refreshExtraction() {
  if (!provider.value || !slug.value || !repoSlug.value || selectedSnapshot.value) return
  try {
    const response = await api.getDependencyExtraction(provider.value, slug.value, repoSlug.value, selectedRef.value || undefined)
    extraction.value = response.data
  } catch {
    extraction.value = null
  }
  if (extractionTimer) clearTimeout(extractionTimer)
  if (extractionPending.value) {
    extractionTimer = setTimeout(async () => {
      const wasPending = extractionPending.value
      await refreshExtraction()
      if (wasPending && !extractionPending.value) {
        await loadComponents({ resetSelection: false, clearScanStatus: false })
      }
    }, 4000)
  }
}

async function requestExtraction() {
  if (!provider.value || !slug.value || !repoSlug.value || extracting.value) return
  extracting.value = true
  try {
    await api.triggerDependencyExtraction(provider.value, slug.value, repoSlug.value, selectedRef.value || undefined)
    await refreshExtraction()
  } catch (error) {
    scanError.value = error instanceof Error ? error.message : 'Failed to request dependency extraction'
  } finally {
    extracting.value = false
  }
}
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

const SEVERITY_RANK: Record<string, number> = { critical: 6, high: 5, medium: 4, unknown: 3, low: 2, info: 1 }

const ecosystemOptions = computed(() => Array.from(new Set(components.value.map((component) => ecosystemKey(component.ecosystem)))).sort())
const sourceOptions = computed(() => Array.from(new Set(components.value.flatMap((component) => component.sources ?? []))).sort())
const severityOptions = ['critical', 'high', 'medium', 'unknown', 'low', 'info']

const signalOptions = ['cooldown', 'deprecated', 'low-usage', 'unpublished', 'none']
const relationshipOptions = ['direct', 'indirect', 'unknown']

/** "direct · dev · in web": what the inventory sources said about this component. */
function provenanceLine(component: ComponentWithVulns): string {
  const parts: string[] = []
  if (component.relationship) parts.push(component.relationship)
  if (component.scopes?.length) parts.push(component.scopes.join(', '))
  if (component.modules?.length && !(component.modules.length === 1 && component.modules[0] === '.')) {
    parts.push(`in ${component.modules.join(', ')}`)
  }
  if (component.registry === 'private') parts.push('private registry')
  if (component.layer !== undefined) parts.push(component.base_image ? `base image layer ${component.layer}` : `layer ${component.layer}`)
  if (component.shipped === false) parts.push('not shipped')
  return parts.join(' · ')
}

/** "34 shipped · 54 total": the counts stay side by side (ADR-045 §6). */
const shippedCount = computed(() => components.value.filter((component) => component.shipped !== false).length)

// The not-shipped lists and the SBOM facts behind the attribute.
const shipping = ref<ShippingInfo | null>(null)
const shippingError = ref('')

async function refreshShipping() {
  if (!provider.value || !slug.value || !repoSlug.value) return
  try {
    const response = await api.getDependencyShipping(provider.value, slug.value, repoSlug.value, {
      ref: selectedRef.value || undefined,
      snapshot: selectedSnapshot.value || undefined,
    })
    shipping.value = response.data
  } catch {
    shipping.value = null
  }
}

/** Shipped components whose declared scope says dev or test (ADR-045 §6). */
const DEV_SCOPES = new Set(['dev', 'devdependencies', 'dev-dependencies', 'development', 'test', 'build-dependencies', 'docs', 'lint'])
const scopeSuggestions = computed(() => components.value.filter((component) => component.shipped !== false && (component.scopes ?? []).some((scope) => DEV_SCOPES.has(scope.toLowerCase()))))
const suggestionScopes = computed(() => Array.from(new Set(scopeSuggestions.value.flatMap((component) => (component.scopes ?? []).filter((scope) => DEV_SCOPES.has(scope.toLowerCase()))))))

/** The purl without its version: a not-shipped entry covers every version of the package. */
function purlIdentity(purl: string): string {
  const base = purl.split('?')[0].split('#')[0]
  const at = base.lastIndexOf('@')
  return at > base.indexOf('/') ? base.slice(0, at) : base
}

/** The .hibou.yaml lines that record entries in the repository's
 * not-shipped list, ready to paste under `dependencies:`. */
function notShippedSnippet(entries: Array<{ pattern: string; reason: string }>): string {
  const lines = ['  not_shipped:']
  for (const entry of entries) {
    lines.push(`    - "${entry.pattern.replace(/"/g, '\\"')}"  # ${entry.reason}`)
  }
  return lines.join('\n')
}

async function copyNotShipped(entries: Array<{ pattern: string; reason: string }>, title: string) {
  try {
    await navigator.clipboard.writeText(notShippedSnippet(entries))
    pushToast({ title, description: 'Paste under dependencies: in .hibou.yaml and open a pull request.', tone: 'success' })
  } catch (error) {
    pushToast({ title: 'Could not copy', description: error instanceof Error ? error.message : undefined, tone: 'error' })
  }
}

function markNotShipped(component: ComponentWithVulns) {
  void copyNotShipped([{ pattern: purlIdentity(component.purl), reason: `${component.name}: not shipped` }], '.hibou.yaml entry copied')
}

function copyScopeSuggestions() {
  const seen = new Set<string>()
  const entries: Array<{ pattern: string; reason: string }> = []
  for (const component of scopeSuggestions.value) {
    const pattern = purlIdentity(component.purl)
    if (seen.has(pattern)) continue
    seen.add(pattern)
    const scope = (component.scopes ?? []).find((value) => DEV_SCOPES.has(value.toLowerCase())) ?? 'dev'
    entries.push({ pattern, reason: `declared ${scope}` })
  }
  void copyNotShipped(entries, `${entries.length} .hibou.yaml ${entries.length === 1 ? 'entry' : 'entries'} copied`)
}

async function removeNotShipped(entryID: string) {
  try {
    await api.deleteNotShippedEntry(provider.value, slug.value, repoSlug.value, entryID)
    await Promise.all([refreshShipping(), loadComponents()])
  } catch (error) {
    shippingError.value = error instanceof Error ? error.message : 'Could not remove the entry'
  }
}

function provenanceTitle(component: ComponentWithVulns): string {
  const lines: string[] = []
  if (component.relationship === 'indirect') lines.push('Indirect: resolved by this repository\'s own build from its lockfile. A library used by other projects has its clients resolve their own versions.')
  if (component.relationship === 'unknown') lines.push('Unknown: no inventory source could tell whether this is a direct dependency.')
  if (component.resolution === 'declared') lines.push('Declared only: the version comes from a manifest, not a lockfile.')
  if (component.inventory_sources?.length) lines.push(`Reported by ${component.inventory_sources.join(', ')}`)
  if (component.layer !== undefined) {
    lines.push(component.base_image
      ? `Introduced by image layer ${component.layer}, part of the base image: a base image update fixes it, not an application change.`
      : `Introduced by image layer ${component.layer}, one of the application's own layers.`)
  }
  if (component.shipped === false) lines.push(`Not shipped: ${component.shipped_reason || 'does not reach clients'}. Listed, never hidden.`)
  return lines.join('\n')
}

const filterDefs = computed(() => [
  { key: 'ecosystem', label: 'Ecosystem', options: ecosystemOptions.value, multi: true },
  { key: 'source', label: 'Sources', options: sourceOptions.value, multi: true },
  { key: 'severity', label: 'Severity', options: severityOptions, multi: true },
  { key: 'vulnerable', label: 'Vulnerable', options: ['yes', 'no'], multi: false },
  { key: 'signal', label: 'Signal', options: signalOptions, multi: true },
  { key: 'relationship', label: 'Relationship', options: relationshipOptions, multi: true },
  { key: 'shipped', label: 'Shipped', options: ['yes', 'no'], multi: false },
])

/** The signal keys a component carries; 'none' only when it was evaluated and carries nothing. */
function componentSignalKeys(component: ComponentWithVulns): string[] {
  const signals = component.signals
  if (!signals) return []
  const keys: string[] = []
  if (signals.in_cooldown) keys.push('cooldown')
  if (signals.deprecated) keys.push('deprecated')
  if (signals.low_usage) keys.push('low-usage')
  if (signals.unpublished) keys.push('unpublished')
  return keys.length ? keys : ['none']
}

function shortDate(value?: string): string {
  if (!value) return '?'
  return new Date(value).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

function relativeDate(value?: string): string {
  if (!value) return 'at an unknown date'
  const days = Math.floor((Date.now() - new Date(value).getTime()) / 86_400_000)
  if (days < 1) return 'today'
  if (days === 1) return 'yesterday'
  return `${days} days ago`
}
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

  const direct = components.value.filter((component) => component.relationship === 'direct').length
  const indirect = components.value.filter((component) => component.relationship === 'indirect').length
  const unknown = components.value.length - direct - indirect
  const relationshipHint = components.value.length > 0 && (direct > 0 || indirect > 0) ? `${direct} direct · ${indirect} indirect · ${unknown} unknown` : ''

  return [
    { label: 'Components', value: components.value.length, hint: relationshipHint, accent: '', valueClass: 'text-white' },
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

  const relationshipFilter = splitFilter(activeFilters.value.relationship)
  if (relationshipFilter.length && !relationshipFilter.includes(component.relationship ?? '')) {
    return false
  }

  const shippedFilter = activeFilters.value.shipped
  if (shippedFilter === 'yes' && component.shipped === false) return false
  if (shippedFilter === 'no' && component.shipped !== false) return false

  const signalFilter = splitFilter(activeFilters.value.signal)
  if (signalFilter.length) {
    const keys = new Set(componentSignalKeys(component))
    if (!signalFilter.some((signal) => keys.has(signal))) {
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
      ...(component.licenses ?? []),
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
    // Malicious packages first, whatever the sort and direction.
    const malware = Number(isMalwareComponent(b)) - Number(isMalwareComponent(a))
    if (malware !== 0) return malware
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
    openComponentFromRoute()
    // The extraction state carries the install-time cooldown settings, so it
    // is read for populated refs too, not only to show an empty ref's progress.
    void refreshExtraction()
    void refreshShipping()
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

// The component modal is deep-linkable (?component=<purl>) so the findings
// view, PR comments and search can land on it open.
function openComponent(component: ComponentWithVulns) {
  activeComponent.value = {
    ...component,
    // The server walks the full graph, including the modules of a built-in
    // extraction; the client graph is the fallback for older servers.
    usage_paths: component.usage_paths?.length ? component.usage_paths : computeUsagePaths(component.purl),
  }
  focusedNodeRef.value = component.purl
  if (route.query.component !== component.purl) {
    void router.replace({ query: { ...route.query, component: component.purl } })
  }
}

function closeComponent() {
  activeComponent.value = null
  if (route.query.component !== undefined) {
    const next = { ...route.query }
    delete next.component
    void router.replace({ query: next })
  }
}

/** A row in the component modal: the same finding, in the findings view.
 * With a fingerprint the drawer opens on it; without one the advisory id is
 * the search, which lists it. */
function openFinding(target: { fingerprint?: string; advisoryId: string }) {
  void router.push({
    name: 'repo-vulnerabilities',
    params: { provider: provider.value, slug: slug.value, repoSlug: repoSlug.value },
    query: {
      ...(target.fingerprint ? { finding: target.fingerprint } : { search: target.advisoryId }),
      ...(selectedRef.value ? { ref: selectedRef.value } : {}),
      ...(selectedSnapshot.value ? { snapshot: selectedSnapshot.value } : {}),
    },
  })
}

/** Open the component the URL names once the list is loaded. */
function openComponentFromRoute() {
  const purl = typeof route.query.component === 'string' ? route.query.component : ''
  if (!purl || activeComponent.value?.purl === purl) return
  const match = components.value.find((component) => component.purl === purl)
  if (match) openComponent(match)
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
  if (value === 'unknown') return 'unknown'
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

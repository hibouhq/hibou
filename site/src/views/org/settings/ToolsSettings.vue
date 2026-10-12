<template>
  <div class="space-y-4">
    <div class="border-b border-surface-border pb-2">
      <h2 class="text-base font-semibold text-white">
        Tools
      </h2>
    </div>

    <p class="text-sm text-gray-500">
      Every scanner, advisory source and report format seen across the organization, with the health of its latest runs.
      A partial or failed run leaves the findings it did not cover open as <em>not re-checked</em> instead of fixed.
    </p>

    <div
      v-if="loading"
      class="text-sm text-gray-500"
    >
      Loading tools…
    </div>
    <div
      v-else-if="loadFailed"
      class="text-sm text-gray-500"
    >
      The tool catalog could not be loaded.
    </div>
    <div
      v-else-if="groups.length === 0"
      class="text-sm text-gray-500"
    >
      No tools seen yet. Upload a SARIF, SBOM or coverage report to populate the catalog.
    </div>

    <section
      v-for="group in groups"
      v-else
      :key="group.category"
      class="space-y-2"
    >
      <h3 class="text-xs font-semibold uppercase tracking-wide text-gray-500">
        {{ group.label }}
      </h3>
      <ul class="divide-y divide-surface-border-subtle rounded-lg border border-surface-border">
        <li
          v-for="tool in group.tools"
          :key="tool.name"
          class="flex items-start gap-3 px-4 py-3"
        >
          <span
            class="mt-1.5 h-2 w-2 shrink-0 rounded-full"
            :class="statusDot(tool.status)"
            :title="tool.status"
          />
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2 text-sm text-gray-100">
              <span class="truncate font-mono">{{ tool.name }}</span>
              <span class="rounded-full bg-surface-overlay px-1.5 text-[10px] capitalize text-gray-400">{{ tool.status }}</span>
            </div>
            <div class="mt-0.5 text-xs text-gray-500">
              <span v-if="tool.last_seen_at && !tool.last_seen_at.startsWith('0001')">last {{ relativeTime(tool.last_seen_at) }}</span>
              <span v-else>never seen</span>
              · {{ tool.repo_count }} {{ tool.repo_count === 1 ? 'repo' : 'repos' }}
              · {{ tool.data_points }} {{ dataPointsLabel(tool) }}
            </div>
            <p
              v-if="tool.warning"
              class="mt-1 text-xs text-amber-300"
            >
              {{ tool.warning }}
            </p>
            <p
              v-if="tool.last_error"
              class="mt-1 truncate text-xs text-gray-500"
              :title="tool.last_error"
            >
              Last error: {{ tool.last_error }}
            </p>
            <div
              v-if="tool.resolution_policy"
              class="mt-2 flex flex-wrap items-center gap-2 text-xs text-gray-400"
            >
              <span title="How findings this scanner stops reporting are resolved">Resolution</span>
              <select
                :value="tool.resolution_policy"
                :disabled="!isOrgAdmin || savingTool === tool.name"
                class="rounded-md border border-surface-border bg-surface-overlay px-2 py-1 text-xs text-gray-200 disabled:opacity-60"
                :aria-label="`Resolution policy for ${tool.name}`"
                @change="savePolicy(tool, ($event.target as HTMLSelectElement).value as ProducerPolicyKind, tool.policy_threshold ?? 3)"
              >
                <option value="coverage">
                  Coverage — re-checked and the code changed
                </option>
                <option value="consecutive-absence">
                  Consecutive absence — N scans without it
                </option>
                <option value="explicit">
                  Explicit — only a decision resolves
                </option>
                <option value="retired">
                  Retired — removed from CI on purpose
                </option>
              </select>
              <label
                v-if="tool.resolution_policy !== 'explicit' && tool.resolution_policy !== 'retired'"
                class="inline-flex items-center gap-1"
                :title="tool.resolution_policy === 'coverage' ? 'Unchanged covered scans before an unconfirmed finding is no longer reported' : 'Covered scans without the finding before it is resolved'"
              >
                N
                <input
                  type="number"
                  min="1"
                  max="100"
                  :value="tool.policy_threshold ?? 3"
                  :disabled="!isOrgAdmin || savingTool === tool.name"
                  class="w-14 rounded-md border border-surface-border bg-surface-overlay px-2 py-1 text-xs text-gray-200 disabled:opacity-60"
                  @change="savePolicy(tool, tool.resolution_policy!, Number(($event.target as HTMLInputElement).value))"
                >
              </label>
            </div>
          </div>
        </li>
      </ul>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { api, type ProducerPolicyKind, type ToolCatalogEntry } from '@/api/client'
import { useOrgRole } from '@/composables/useOrgRole'
import { useToast } from '@/composables/useToast'
import { relativeTime } from '@/lib/datetime'

const route = useRoute()
const provider = route.params.provider as string
const slug = route.params.slug as string

const { isOrgAdmin } = useOrgRole()
const { pushToast } = useToast()

const tools = ref<ToolCatalogEntry[]>([])
const loading = ref(true)
const loadFailed = ref(false)
const savingTool = ref('')

async function savePolicy(tool: ToolCatalogEntry, policy: ProducerPolicyKind, threshold: number) {
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > 100) {
    pushToast({ tone: 'error', title: 'N must be between 1 and 100' })
    return
  }
  savingTool.value = tool.name
  try {
    const response = await api.setProducerPolicy(provider, slug, { producer: tool.name, policy, threshold })
    tool.resolution_policy = response.data.policy
    tool.policy_threshold = response.data.threshold
    pushToast({ tone: 'success', title: `Resolution policy for ${tool.name} saved` })
  } catch {
    pushToast({ tone: 'error', title: `Could not save the policy for ${tool.name}` })
  } finally {
    savingTool.value = ''
  }
}

const categoryLabels: Record<ToolCatalogEntry['category'], string> = {
  sast: 'Code scanners',
  secret_scanning: 'Secret scanning',
  advisory_provider: 'Advisory sources',
  sbom_generator: 'SBOM ecosystems',
  vex_source: 'VEX sources',
  coverage: 'Coverage formats',
}

const groups = computed(() => {
  const order = Object.keys(categoryLabels) as ToolCatalogEntry['category'][]
  return order
    .map(category => ({
      category,
      label: categoryLabels[category],
      tools: tools.value.filter(tool => tool.category === category),
    }))
    .filter(group => group.tools.length > 0)
})

onMounted(async () => {
  try {
    const response = await api.getToolCatalog(provider, slug)
    tools.value = response.data?.tools ?? []
  } catch {
    loadFailed.value = true
  } finally {
    loading.value = false
  }
})

function statusDot(status: ToolCatalogEntry['status']) {
  switch (status) {
    case 'healthy':
      return 'bg-emerald-400'
    case 'degraded':
      return 'bg-warning'
    case 'unhealthy':
      return 'bg-danger'
    default:
      return 'bg-gray-500'
  }
}

function dataPointsLabel(tool: ToolCatalogEntry) {
  if (tool.last_outcome) {
    return tool.data_points === 1 ? 'run' : 'runs'
  }
  switch (tool.category) {
    case 'advisory_provider':
      return 'advisories'
    case 'sbom_generator':
      return 'components'
    case 'vex_source':
      return 'statements'
    case 'coverage':
      return 'reports'
    default:
      return 'findings'
  }
}
</script>

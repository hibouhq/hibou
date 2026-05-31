<template>
  <section class="space-y-6 rounded-3xl border border-surface-border bg-surface-raised p-6">
    <div class="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
      <div>
        <p class="text-xs uppercase tracking-[0.2em] text-gray-500">
          Ref comparison
        </p>
        <h1 class="mt-2 text-3xl font-semibold tracking-tight text-white">
          Compare: {{ baseLabel }} → {{ headLabel }}
        </h1>
        <p class="mt-2 text-sm text-gray-400">
          Compare vulnerabilities and SBOM component changes across any two scanned refs.
        </p>
      </div>
    </div>

    <div class="grid gap-4 lg:grid-cols-2">
      <label class="space-y-2 text-sm text-gray-300">
        <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Base ref</span>
        <select
          v-model="baseRef"
          class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100"
        >
          <option
            v-for="refItem in refs"
            :key="`base-${refItem.id}`"
            :value="refItem.name"
          >
            {{ formatRefOption(refItem) }}
          </option>
        </select>
      </label>

      <label class="space-y-2 text-sm text-gray-300">
        <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Head ref</span>
        <select
          v-model="headRef"
          class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100"
        >
          <option
            v-for="refItem in refs"
            :key="`head-${refItem.id}`"
            :value="refItem.name"
          >
            {{ formatRefOption(refItem) }}
          </option>
        </select>
      </label>
    </div>

    <div
      v-if="comparison"
      class="grid gap-3 md:grid-cols-2 xl:grid-cols-3"
    >
      <article
        v-for="card in summaryCards"
        :key="card.label"
        class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/80 p-4"
      >
        <p class="text-xs uppercase tracking-[0.18em] text-gray-500">
          {{ card.label }}
        </p>
        <p class="mt-3 text-3xl font-semibold text-white">
          {{ card.value }}
        </p>
      </article>
    </div>

    <div
      v-if="comparison"
      class="grid gap-4 lg:grid-cols-2"
    >
      <div class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/70 p-4">
        <p class="text-xs uppercase tracking-[0.18em] text-gray-500">
          Base snapshot
        </p>
        <p class="mt-2 text-lg font-medium text-white">
          {{ comparison.base.ref_name }}
        </p>
        <p class="mt-1 text-sm text-gray-400">
          <a
            v-if="commitUrl(comparison.base.commit_sha)"
            :href="commitUrl(comparison.base.commit_sha) || undefined"
            target="_blank"
            rel="noopener"
            class="font-mono hover:text-accent hover:underline"
          >{{ comparison.base.commit_sha.slice(0, 12) }}</a>
          <span
            v-else
            class="font-mono"
          >{{ comparison.base.commit_sha.slice(0, 12) }}</span>
          · {{ formatDateTime(comparison.base.date) }}
        </p>
      </div>

      <div class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/70 p-4">
        <p class="text-xs uppercase tracking-[0.18em] text-gray-500">
          Head snapshot
        </p>
        <p class="mt-2 text-lg font-medium text-white">
          {{ comparison.head.ref_name }}
        </p>
        <p class="mt-1 text-sm text-gray-400">
          <a
            v-if="commitUrl(comparison.head.commit_sha)"
            :href="commitUrl(comparison.head.commit_sha) || undefined"
            target="_blank"
            rel="noopener"
            class="font-mono hover:text-accent hover:underline"
          >{{ comparison.head.commit_sha.slice(0, 12) }}</a>
          <span
            v-else
            class="font-mono"
          >{{ comparison.head.commit_sha.slice(0, 12) }}</span>
          · {{ formatDateTime(comparison.head.date) }}
        </p>
      </div>
    </div>

    <div
      v-if="loading"
      class="rounded-2xl border border-dashed border-surface-border-subtle px-4 py-10 text-sm text-gray-500"
    >
      Running comparison...
    </div>

    <div
      v-else-if="error"
      class="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-5 text-sm text-danger"
    >
      {{ error }}
    </div>

    <template v-else-if="comparison">
      <details
        open
        class="overflow-hidden rounded-2xl border border-surface-border-subtle"
      >
        <summary class="cursor-pointer bg-surface-overlay px-4 py-3 text-sm font-medium text-white">
          Vulnerability Delta
        </summary>

        <div
          v-if="vulnRows.length === 0"
          class="px-4 py-8 text-sm text-gray-500"
        >
          No vulnerability changes between these refs.
        </div>

        <div
          v-else
          class="overflow-x-auto"
        >
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay/60 text-left text-xs uppercase tracking-[0.18em] text-gray-500">
              <tr>
                <th class="px-4 py-3 font-medium">
                  Change
                </th>
                <th class="px-4 py-3 font-medium">
                  Severity
                </th>
                <th class="px-4 py-3 font-medium">
                  Type
                </th>
                <th class="px-4 py-3 font-medium">
                  Identifier
                </th>
                <th class="px-4 py-3 font-medium">
                  Title
                </th>
                <th class="px-4 py-3 font-medium">
                  Location
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="vuln in vulnRows"
                :key="`${vuln.change}-${vuln.advisory_id}-${vuln.component_name}`"
                class="transition hover:bg-white/5"
              >
                <td class="px-4 py-4">
                  <span :class="changeBadgeClass(vuln.change)">
                    {{ vuln.change }}
                  </span>
                </td>
                <td class="px-4 py-4">
                  <span :class="severityBadgeClass(vuln.severity)">
                    {{ vuln.severity }}
                  </span>
                </td>
                <td class="px-4 py-4 text-gray-300">
                  {{ vuln.type }}
                </td>
                <td class="px-4 py-4 font-mono text-xs text-accent">
                  {{ vuln.primary_identifier?.value || vuln.scanner_name || 'n/a' }}
                </td>
                <td class="px-4 py-4 text-gray-300">
                  {{ vuln.title }}
                </td>
                <td class="px-4 py-4 text-gray-400">
                  {{ vulnerabilityLocation(vuln) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </details>

      <details
        open
        class="overflow-hidden rounded-2xl border border-surface-border-subtle"
      >
        <summary class="cursor-pointer bg-surface-overlay px-4 py-3 text-sm font-medium text-white">
          Component Changes
        </summary>

        <div
          v-if="componentRows.length === 0"
          class="px-4 py-8 text-sm text-gray-500"
        >
          No component additions or removals between these refs.
        </div>

        <div
          v-else
          class="overflow-x-auto"
        >
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay/60 text-left text-xs uppercase tracking-[0.18em] text-gray-500">
              <tr>
                <th class="px-4 py-3 font-medium">
                  Change
                </th>
                <th class="px-4 py-3 font-medium">
                  Package
                </th>
                <th class="px-4 py-3 font-medium">
                  Version
                </th>
                <th class="px-4 py-3 font-medium">
                  Ecosystem
                </th>
                <th class="px-4 py-3 font-medium">
                  Vulns
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="component in componentRows"
                :key="`${component.change}-${component.purl || `${component.name}-${component.version}`}`"
                class="transition hover:bg-white/5"
              >
                <td class="px-4 py-4">
                  <span :class="changeBadgeClass(component.change)">
                    {{ component.change }}
                  </span>
                </td>
                <td class="px-4 py-4 text-gray-200">
                  <div class="font-medium">
                    {{ component.name }}
                  </div>
                  <div class="text-xs text-gray-500">
                    {{ component.purl }}
                  </div>
                </td>
                <td class="px-4 py-4 text-gray-300">
                  {{ component.version }}
                </td>
                <td class="px-4 py-4">
                  <span class="rounded-full border border-surface-border px-2.5 py-1 text-xs uppercase tracking-[0.14em] text-gray-300">
                    {{ component.ecosystem }}
                  </span>
                </td>
                <td class="px-4 py-4 text-gray-300">
                  {{ component.vuln_count }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </details>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, forgeCommitUrl, type CompareResult, type ComponentEntry, type EnhancedRef, type Repository, type Vulnerability } from '@/api/client'
import { useOrgStore } from '@/stores/org'

type VulnRow = Vulnerability & { change: 'new' | 'resolved' }
type ComponentRow = ComponentEntry & { change: 'added' | 'removed' }

const route = useRoute()
const router = useRouter()
const orgStore = useOrgStore()

const repo = ref<Repository | null>(null)
const refs = ref<EnhancedRef[]>([])
const comparison = ref<CompareResult | null>(null)
const loading = ref(false)
const loadingRefs = ref(true)
const error = ref('')
const baseRef = ref('')
const headRef = ref('')
const forgeUrl = computed(() => orgStore.currentOrg?.forge_url ?? '')
const repoProviderID = computed(() => repo.value?.provider_id ?? '')

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const baseLabel = computed(() => baseRef.value || 'Base')
const headLabel = computed(() => headRef.value || 'Head')

const summaryCards = computed(() => {
  if (!comparison.value) {
    return []
  }

  return [
    { label: 'New vulnerabilities', value: comparison.value.delta.new_vulnerabilities.length },
    { label: 'Resolved vulnerabilities', value: comparison.value.delta.resolved_vulnerabilities.length },
    { label: 'Added components', value: comparison.value.component_diff.added.length },
    { label: 'Removed components', value: comparison.value.component_diff.removed.length },
  ]
})

const vulnRows = computed<VulnRow[]>(() => {
  if (!comparison.value) {
    return []
  }

  return [
    ...comparison.value.delta.new_vulnerabilities.map((vuln) => ({ ...vuln, change: 'new' as const })),
    ...comparison.value.delta.resolved_vulnerabilities.map((vuln) => ({ ...vuln, change: 'resolved' as const })),
  ]
})

const componentRows = computed<ComponentRow[]>(() => {
  if (!comparison.value) {
    return []
  }

  return [
    ...comparison.value.component_diff.added.map((component) => ({ ...component, change: 'added' as const })),
    ...comparison.value.component_diff.removed.map((component) => ({ ...component, change: 'removed' as const })),
  ]
})

watch(
  () => [route.params.provider, route.params.slug, route.params.repoSlug],
  () => {
    void loadRefs()
  },
  { immediate: true },
)

watch(
  () => [route.query.base, route.query.head],
  () => {
    baseRef.value = typeof route.query.base === 'string' ? route.query.base : ''
    headRef.value = typeof route.query.head === 'string' ? route.query.head : ''
    void loadComparison()
  },
  { immediate: true },
)

watch([baseRef, headRef], ([base, head]) => {
  const nextBase = typeof route.query.base === 'string' ? route.query.base : ''
  const nextHead = typeof route.query.head === 'string' ? route.query.head : ''
  if (!base || !head || (base === nextBase && head === nextHead)) {
    return
  }

  void router.replace({ query: { ...route.query, base, head } })
})

async function loadRefs() {
  loadingRefs.value = true

  try {
    const [repoRes, refsRes] = await Promise.all([
      api.getRepo(provider.value, slug.value, repoSlug.value),
      api.listRefsEnhanced(provider.value, slug.value, repoSlug.value),
    ])

    repo.value = repoRes.data
    refs.value = refsRes.data
    ensureSelections()
  } catch {
    repo.value = null
    refs.value = []
    error.value = 'Failed to load refs for comparison.'
  } finally {
    loadingRefs.value = false

    if (typeof route.query.base === 'string' && typeof route.query.head === 'string') {
      void loadComparison()
    }
  }
}

function ensureSelections() {
  if (refs.value.length === 0 || !repo.value) {
    return
  }

  const routeBase = typeof route.query.base === 'string' ? route.query.base : ''
  const routeHead = typeof route.query.head === 'string' ? route.query.head : ''
  const defaultBase = refs.value.find((refItem) => refItem.name === repo.value?.default_branch)?.name || refs.value[0]?.name || ''
  const defaultHead = refs.value.find((refItem) => refItem.name !== defaultBase)?.name || defaultBase

  baseRef.value = routeBase || defaultBase
  headRef.value = routeHead || defaultHead

  if (!routeBase || !routeHead) {
    void router.replace({
      query: {
        ...route.query,
        base: baseRef.value,
        head: headRef.value,
      },
    })
  }
}

async function loadComparison() {
  if (loadingRefs.value || !baseRef.value || !headRef.value) {
    return
  }

  loading.value = true
  error.value = ''

  try {
    const response = await api.compareRefs(
      provider.value,
      slug.value,
      repoSlug.value,
      baseRef.value,
      headRef.value,
    )
    comparison.value = response.data
  } catch (err) {
    comparison.value = null
    error.value = err instanceof Error ? err.message : 'Failed to compare refs.'
  } finally {
    loading.value = false
  }
}

function formatRefOption(refItem: EnhancedRef) {
  if (refItem.ref_type === 'pull_request') {
    return `${refItem.pr_title || refItem.name} (${refItem.pr_source_branch || 'source'} → ${refItem.merge_target_ref_name || 'target'})`
  }
  return refItem.name
}

function commitUrl(sha: string): string | null {
  return forgeCommitUrl(forgeUrl.value, repoProviderID.value, sha)
}

function severityBadgeClass(severity: string) {
  return `sev-${severity.toLowerCase()} rounded-full px-2.5 py-1 text-xs font-medium`
}

function changeBadgeClass(change: string) {
  if (change === 'new' || change === 'added') {
    return 'rounded-full bg-emerald-500/15 px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em] text-emerald-300'
  }

  return 'rounded-full bg-danger/15 px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em] text-danger'
}

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

function vulnerabilityLocation(vuln: Vulnerability) {
  if (vuln.file_path) {
    return vuln.start_line ? `${vuln.file_path}:${vuln.start_line}` : vuln.file_path
  }

  if (vuln.component_name) {
    return vuln.component_version ? `${vuln.component_name}@${vuln.component_version}` : vuln.component_name
  }

  return 'n/a'
}
</script>

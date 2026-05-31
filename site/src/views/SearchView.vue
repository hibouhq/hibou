<template>
  <section class="space-y-6">
    <div class="rounded-3xl border border-surface-border bg-surface-raised p-6 shadow-[0_24px_80px_-48px_rgba(0,0,0,0.9)]">
      <div class="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div class="min-w-0 flex-1">
          <h1 class="text-3xl font-semibold tracking-tight text-white">
            Search
          </h1>
          <p class="mt-2 text-sm text-gray-400">
            Search across vulnerabilities, components, and clients in this organization.
          </p>
        </div>

        <label class="flex w-full max-w-2xl items-center gap-3 rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-300">
          <input
            v-model="searchInput"
            type="search"
            placeholder="Search for CVEs, package names, rules, or clients"
            class="w-full bg-transparent text-sm text-gray-100 placeholder:text-gray-500 focus:outline-none"
            @keydown.enter.prevent="applySearch()"
          >
        </label>
      </div>

      <div class="mt-6 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div class="flex flex-wrap gap-2">
          <button
            v-for="tab in typeTabs"
            :key="tab.value"
            class="rounded-full px-3 py-1.5 text-xs font-medium uppercase tracking-[0.18em] transition"
            :class="selectedType === tab.value ? 'bg-accent-muted text-accent' : 'text-gray-500 hover:text-gray-200'"
            type="button"
            @click="setType(tab.value)"
          >
            {{ tab.label }}
          </button>
        </div>

        <label
          v-if="showSeverityFilter"
          class="space-y-2 text-sm text-gray-300"
        >
          <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Severity</span>
          <select
            v-model="selectedSeverity"
            class="rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100"
            @change="applySearch(1)"
          >
            <option value="">All severities</option>
            <option
              v-for="option in severityOptions"
              :key="option"
              :value="option"
            >{{ option }}</option>
          </select>
        </label>
      </div>
    </div>

    <section class="overflow-hidden rounded-3xl border border-surface-border bg-surface-raised">
      <div
        v-if="loading"
        class="px-6 py-10 text-sm text-gray-500"
      >
        Searching...
      </div>

      <div
        v-else-if="error"
        class="px-6 py-6"
      >
        <div class="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200">
          {{ error }}
        </div>
      </div>

      <div
        v-else-if="!results.length"
        class="px-6 py-10 text-sm text-gray-500"
      >
        No results for '{{ searchInput.trim() || 'your query' }}'.
      </div>

      <template v-else>
        <div class="divide-y divide-surface-border-subtle">
          <article
            v-for="result in results"
            :key="`${result.type}-${result.id}`"
            class="px-6 py-4 transition hover:bg-white/5"
          >
            <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div class="min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="rounded-full border border-surface-border px-2.5 py-1 text-[10px] font-medium uppercase tracking-[0.16em] text-gray-300">
                    {{ result.type }}
                  </span>
                  <span
                    v-if="result.severity"
                    :class="['rounded-full px-2.5 py-1 text-[10px] font-medium uppercase tracking-[0.16em]', severityClass(result.severity)]"
                  >
                    {{ result.severity }}
                  </span>
                </div>

                <component
                  :is="clientLink(result) ? RouterLink : 'div'"
                  :to="clientLink(result) || undefined"
                  class="mt-3 block text-lg font-medium text-white"
                >
                  {{ result.title }}
                </component>
                <p class="mt-1 text-sm text-gray-400">
                  {{ result.subtitle }}
                </p>
              </div>

              <pre
                v-if="result.metadata"
                class="overflow-x-auto rounded-2xl border border-surface-border bg-surface-overlay px-3 py-2 text-[11px] text-gray-500"
              >{{ JSON.stringify(result.metadata, null, 2) }}</pre>
            </div>
          </article>
        </div>

        <div class="flex items-center justify-between border-t border-surface-border-subtle px-6 py-4 text-sm text-gray-400">
          <div>Page {{ pagination.page }} of {{ totalPages }}</div>
          <div class="flex items-center gap-3">
            <button
              class="rounded-xl border border-surface-border px-3 py-2 transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
              type="button"
              :disabled="pagination.page <= 1"
              @click="applySearch(pagination.page - 1)"
            >
              Previous
            </button>
            <button
              class="rounded-xl border border-surface-border px-3 py-2 transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
              type="button"
              :disabled="pagination.page >= totalPages"
              @click="applySearch(pagination.page + 1)"
            >
              Next
            </button>
          </div>
        </div>
      </template>
    </section>
  </section>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'

import { api, type SearchResult } from '@/api/client'

const route = useRoute()
const router = useRouter()

const results = ref<SearchResult[]>([])
const loading = ref(true)
const error = ref('')
const searchInput = ref('')
const selectedType = ref('')
const selectedSeverity = ref('')
const pagination = ref({ page: 1, per_page: 20, total: 0 })
let debounceHandle: number | undefined

const typeTabs = [
  { label: 'All', value: '' },
  { label: 'Vulnerabilities', value: 'vulnerability' },
  { label: 'Components', value: 'component' },
  { label: 'Clients', value: 'client' },
]
const severityOptions = ['critical', 'high', 'medium', 'low', 'info']
const showSeverityFilter = computed(() => selectedType.value === 'vulnerability')
const totalPages = computed(() => Math.max(1, Math.ceil(pagination.value.total / pagination.value.per_page)))

watch(
  () => route.query,
  () => {
    searchInput.value = typeof route.query.q === 'string' ? route.query.q : ''
    selectedType.value = typeof route.query.type === 'string' ? route.query.type : ''
    selectedSeverity.value = typeof route.query.severity === 'string' ? route.query.severity : ''
    const page = Number(typeof route.query.page === 'string' ? route.query.page : '1')
    pagination.value.page = Number.isFinite(page) && page > 0 ? page : 1
    void loadResults()
  },
  { immediate: true },
)

watch(searchInput, (value, previousValue) => {
  if (value === previousValue) {
    return
  }
  if (debounceHandle) {
    window.clearTimeout(debounceHandle)
  }
  if (value.trim().length < 2 && value.trim().length > 0) {
    return
  }
  debounceHandle = window.setTimeout(() => {
    void applySearch(1)
  }, 300)
})

async function loadResults() {
  const query = searchInput.value.trim()
  if (!query) {
    results.value = []
    pagination.value = { ...pagination.value, total: 0 }
    error.value = ''
    loading.value = false
    return
  }

  loading.value = true
  error.value = ''
  try {
    const response = await api.search(route.params.provider as string, route.params.slug as string, {
      q: query,
      type: selectedType.value || undefined,
      severity: showSeverityFilter.value ? selectedSeverity.value || undefined : undefined,
      page: pagination.value.page,
      per_page: pagination.value.per_page,
    })
    results.value = response.data.results
    pagination.value = response.data.pagination
  } catch (loadError) {
    results.value = []
    pagination.value = { ...pagination.value, total: 0 }
    error.value = loadError instanceof Error ? loadError.message : 'Search failed'
  } finally {
    loading.value = false
  }
}

function setType(type: string) {
  selectedType.value = type
  if (!showSeverityFilter.value) {
    selectedSeverity.value = ''
  }
  void applySearch(1)
}

function applySearch(page = 1) {
  const query: Record<string, string> = {}
  const trimmed = searchInput.value.trim()
  if (trimmed) {
    query.q = trimmed
  }
  if (selectedType.value) {
    query.type = selectedType.value
  }
  if (showSeverityFilter.value && selectedSeverity.value) {
    query.severity = selectedSeverity.value
  }
  if (page > 1) {
    query.page = String(page)
  }

  return router.replace({ query })
}

function severityClass(level: string) {
  return `sev-${level.toLowerCase()}`
}

function clientLink(result: SearchResult) {
  if (result.type !== 'client') {
    return null
  }
  const clientSlug = typeof result.metadata?.slug === 'string' ? result.metadata.slug : ''
  if (!clientSlug) {
    return null
  }
  return {
    name: 'client-detail',
    params: { ...route.params, clientSlug },
  }
}
</script>

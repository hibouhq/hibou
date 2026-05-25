<template>
  <div class="space-y-5">
    <div class="flex flex-wrap items-end gap-2">
      <label class="space-y-2 text-sm text-gray-300">
        <span class="block text-[11px] uppercase tracking-[0.12em] text-gray-500">Severity</span>
        <select
          v-model="severityFilter"
          class="w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-100"
        >
          <option value="">All severities</option>
          <option
            v-for="option in severityOptions"
            :key="option"
            :value="option"
          >{{ option }}</option>
        </select>
      </label>

      <label class="space-y-2 text-sm text-gray-300">
        <span class="block text-[11px] uppercase tracking-[0.12em] text-gray-500">Tool</span>
        <select
          v-model="toolFilter"
          class="w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-100"
        >
          <option value="">All tools</option>
          <option
            v-for="option in toolOptions"
            :key="option"
            :value="option"
          >{{ option }}</option>
        </select>
      </label>

      <label class="space-y-2 text-sm text-gray-300">
        <span class="block text-[11px] uppercase tracking-[0.12em] text-gray-500">Status</span>
        <select
          v-model="statusFilter"
          class="w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-100"
        >
          <option value="">All statuses</option>
          <option
            v-for="option in statusOptions"
            :key="option"
            :value="option"
          >{{ option }}</option>
        </select>
      </label>

      <button
        class="text-xs text-gray-400 transition hover:text-white"
        type="button"
        @click="resetFilters"
      >
        Reset
      </button>
    </div>

    <div class="overflow-hidden rounded-2xl border border-surface-border-subtle">
      <div
        v-if="loading"
        class="px-4 py-10 text-sm text-gray-500"
      >
        Loading findings...
      </div>

      <div
        v-else-if="findings.length === 0"
        class="px-4 py-10 text-sm text-gray-500"
      >
        No findings for this ref.
      </div>

      <template v-else>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.18em] text-gray-500">
              <tr>
                <th class="px-3 py-2 font-medium">
                  Severity
                </th>
                <th class="px-3 py-2 font-medium">
                  Tool
                </th>
                <th class="px-3 py-2 font-medium">
                  Rule ID
                </th>
                <th class="px-3 py-2 font-medium">
                  File
                </th>
                <th class="px-3 py-2 font-medium">
                  Status
                </th>
                <th class="px-3 py-2 font-medium">
                  Message
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="finding in findings"
                :key="finding.id"
                class="transition hover:bg-white/5"
              >
                <td class="px-3 py-2.5">
                  <span :class="['rounded-full px-2.5 py-1 text-xs font-medium', severityClass(finding.severity)]">
                    {{ finding.severity }}
                  </span>
                </td>
                <td class="px-3 py-2.5 text-gray-300">
                  {{ finding.tool }}
                </td>
                <td class="px-3 py-2.5 font-mono text-xs text-accent">
                  {{ finding.rule_id }}
                </td>
                <td class="px-3 py-2.5 text-gray-400">
                  {{ formatLocation(finding) }}
                </td>
                <td class="px-3 py-2.5 text-gray-300">
                  {{ finding.status }}
                </td>
                <td class="px-3 py-2.5 text-gray-300">
                  {{ finding.message }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="flex items-center justify-between border-t border-surface-border-subtle px-3 py-2.5 text-sm text-gray-400">
          <div>Page {{ pagination.page }} of {{ totalPages }}</div>
          <div class="flex items-center gap-3">
            <button
              class="rounded-lg border border-surface-border px-2.5 py-1 text-xs transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
              type="button"
              :disabled="pagination.page <= 1"
              @click="changePage(pagination.page - 1)"
            >
              Previous
            </button>
            <button
              class="rounded-lg border border-surface-border px-2.5 py-1 text-xs transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
              type="button"
              :disabled="pagination.page >= totalPages"
              @click="changePage(pagination.page + 1)"
            >
              Next
            </button>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import { api, type Finding } from '@/api/client'

const route = useRoute()

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const findings = ref<Finding[]>([])
const loading = ref(true)
const severityFilter = ref('')
const toolFilter = ref('')
const statusFilter = ref('')
const pagination = ref({ page: 1, per_page: 50, total: 0 })

const severityOptions = ['critical', 'high', 'medium', 'low', 'info']
const toolOptions = computed(() => Array.from(new Set(findings.value.map((finding) => finding.tool))).sort())
const statusOptions = computed(() => Array.from(new Set(findings.value.map((finding) => finding.status))).sort())
const totalPages = computed(() => Math.max(1, Math.ceil(pagination.value.total / pagination.value.per_page)))

watch(
  [provider, slug, repoSlug, () => route.query.ref, severityFilter, toolFilter, statusFilter, () => pagination.value.page],
  async () => {
    if (!provider.value || !slug.value || !repoSlug.value) {
      findings.value = []
      return
    }

    loading.value = true
    try {
      const res = await api.listRefFindings(provider.value, slug.value, repoSlug.value, {
        ref: typeof route.query.ref === 'string' ? route.query.ref : undefined,
        severity: severityFilter.value || undefined,
        tool: toolFilter.value || undefined,
        status: statusFilter.value || undefined,
        page: pagination.value.page,
        per_page: pagination.value.per_page,
      })

      findings.value = res.data
      pagination.value = res.pagination
    } catch {
      findings.value = []
      pagination.value = { ...pagination.value, total: 0 }
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

watch([severityFilter, toolFilter, statusFilter, () => route.query.ref], () => {
  pagination.value.page = 1
})

function resetFilters() {
  severityFilter.value = ''
  toolFilter.value = ''
  statusFilter.value = ''
  pagination.value.page = 1
}

function changePage(page: number) {
  pagination.value.page = page
}

function severityClass(level: string) {
  return `sev-${level.toLowerCase()}`
}

function formatLocation(finding: Finding) {
  if (!finding.start_line) {
    return finding.file_path
  }

  return `${finding.file_path}:${finding.start_line}`
}
</script>

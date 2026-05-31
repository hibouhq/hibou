<template>
  <section class="space-y-6">
    <div class="rounded-3xl border border-surface-border bg-surface-raised p-6 shadow-[0_24px_80px_-48px_rgba(0,0,0,0.9)]">
      <div
        v-if="loading"
        class="text-sm text-gray-500"
      >
        Loading pull request review...
      </div>

      <div
        v-else-if="summary"
        class="space-y-6"
      >
        <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <RouterLink
              class="inline-flex items-center rounded-full border border-surface-border px-3 py-1 text-xs uppercase tracking-[0.18em] text-gray-400 transition hover:text-white"
              :to="{ name: 'repo-vulnerabilities', params: route.params, query: { ref: summary.ref.name } }"
            >
              Back to repository detail
            </RouterLink>
            <h1 class="mt-4 text-3xl font-semibold tracking-tight text-white">
              {{ summaryTitle }}
            </h1>
            <p class="mt-2 text-sm text-gray-400">
              {{ summarySubtitle }}
            </p>
          </div>

          <div class="rounded-3xl border border-surface-border bg-surface-overlay px-5 py-4 text-right">
            <p class="text-xs uppercase tracking-[0.2em] text-gray-500">
              Quality gate
            </p>
            <p
              class="mt-2 text-2xl font-semibold"
              :class="gateState.className"
            >
              {{ gateState.label }}
            </p>
            <p class="mt-2 text-xs text-gray-500">
              {{ gateState.detail }}
            </p>
          </div>
        </div>

        <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <article class="rounded-2xl border border-surface-border bg-surface-overlay p-4">
            <p class="text-xs uppercase tracking-[0.2em] text-gray-500">
              New vulnerabilities
            </p>
            <p class="mt-3 text-3xl font-semibold text-white">
              {{ newVulnerabilitiesCount }}
            </p>
          </article>
          <article class="rounded-2xl border border-surface-border bg-surface-overlay p-4">
            <p class="text-xs uppercase tracking-[0.2em] text-gray-500">
              Resolved vulnerabilities
            </p>
            <p class="mt-3 text-3xl font-semibold text-white">
              {{ resolvedVulnerabilitiesCount }}
            </p>
          </article>
        </div>

        <div
          v-if="showNoAnalysisData"
          class="rounded-2xl border border-surface-border bg-surface-overlay p-4 text-sm text-gray-300"
        >
          No analysis data is available for this pull request yet.
        </div>

        <div
          v-else-if="summary.gate?.reasons?.length"
          class="rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger"
        >
          <p class="font-medium text-white">
            Gate reasons
          </p>
          <ul class="mt-2 space-y-2">
            <li
              v-for="reason in summary.gate.reasons"
              :key="reason"
            >
              {{ reason }}
            </li>
          </ul>
        </div>
      </div>

      <div
        v-else
        class="text-sm text-gray-500"
      >
        Pull request review not found.
      </div>
    </div>

    <section class="rounded-3xl border border-surface-border bg-surface-raised p-6">
      <div>
        <h2 class="text-xl font-semibold text-white">
          New vulnerabilities
        </h2>
        <p class="mt-2 text-sm text-gray-400">
          Only vulnerabilities introduced by this pull request are listed here.
        </p>
      </div>

      <div class="mt-6 overflow-hidden rounded-2xl border border-surface-border-subtle">
        <div
          v-if="!summary?.delta?.new_vulnerabilities?.length"
          class="px-4 py-10 text-sm text-gray-500"
        >
          No newly introduced vulnerabilities were detected.
        </div>

        <div
          v-else
          class="overflow-x-auto"
        >
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.18em] text-gray-500">
              <tr>
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
                  Location
                </th>
                <th class="px-4 py-3 font-medium">
                  Title
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="vulnerability in summary.delta.new_vulnerabilities"
                :key="vulnerability.id"
                class="transition hover:bg-white/5"
              >
                <td class="px-4 py-4">
                  <span :class="['rounded-full px-2.5 py-1 text-xs font-medium', severityClass(vulnerability.severity)]">
                    {{ vulnerability.severity }}
                  </span>
                </td>
                <td class="px-4 py-4 text-gray-300">
                  {{ vulnerability.type }}
                </td>
                <td class="px-4 py-4 font-mono text-xs text-accent">
                  {{ vulnerability.primary_identifier?.value || vulnerability.scanner_name || 'n/a' }}
                </td>
                <td class="px-4 py-4 text-gray-400">
                  {{ vulnerabilityLocation(vulnerability) }}
                </td>
                <td class="px-4 py-4 text-gray-300">
                  {{ vulnerability.title }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  </section>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api, type PRSummary, type Vulnerability } from '@/api/client'

const route = useRoute()

const loading = ref(true)
const summary = ref<PRSummary | null>(null)

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)
const number = computed(() => route.params.number as string)

const summaryTitle = computed(() => summary.value?.ref.pr_title || `Pull request #${number.value}`)
const summarySubtitle = computed(() => {
  if (!summary.value) {
    return ''
  }
  const source = summary.value.ref.pr_source_branch || 'source'
  const target = summary.value.ref.merge_target_ref_name || 'target'
  return `#${number.value} · ${source} → ${target}`
})
const newVulnerabilitiesCount = computed(() => summary.value?.delta?.new_vulnerabilities?.length || 0)
const resolvedVulnerabilitiesCount = computed(() => summary.value?.delta?.resolved_vulnerabilities?.length || 0)
const showNoAnalysisData = computed(() => {
  if (!summary.value) {
    return false
  }

  return !summary.value.pr_snapshot_id || summary.value.summary.snapshot_status === 'no_data' || summary.value.gate == null
})
const gateState = computed(() => {
  if (showNoAnalysisData.value) {
    return {
      label: 'No analysis data',
      className: 'text-gray-300',
      detail: 'No snapshot available for this pull request',
    }
  }

  if (summary.value?.gate?.passed === false) {
    return {
      label: 'Fail',
      className: 'text-danger',
      detail: summary.value.ref.latest_snapshot_status || summary.value.summary.snapshot_status || 'Snapshot complete',
    }
  }

  return {
    label: 'Pass',
    className: 'text-emerald-300',
    detail: summary.value?.ref.latest_snapshot_status || summary.value?.summary.snapshot_status || 'Snapshot complete',
  }
})

watch(
  [provider, slug, repoSlug, number],
  async () => {
    if (!provider.value || !slug.value || !repoSlug.value || !number.value) {
      summary.value = null
      return
    }

    loading.value = true
    try {
      const response = await api.getPRSummary(provider.value, slug.value, repoSlug.value, number.value)
      summary.value = response.data
    } catch {
      summary.value = null
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

function severityClass(level: string) {
  return `sev-${level.toLowerCase()}`
}

function vulnerabilityLocation(vulnerability: Vulnerability) {
  if (vulnerability.file_path) {
    return vulnerability.start_line ? `${vulnerability.file_path}:${vulnerability.start_line}` : vulnerability.file_path
  }

  if (vulnerability.component_name) {
    return vulnerability.component_version
      ? `${vulnerability.component_name}@${vulnerability.component_version}`
      : vulnerability.component_name
  }

  return 'n/a'
}
</script>

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
              :to="{ name: 'repo-weaknesses', params: route.params, query: { ref: summary.ref.name } }"
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
              New findings
            </p>
            <p class="mt-3 text-3xl font-semibold text-white">
              {{ newFindingsCount }}
            </p>
          </article>
          <article class="rounded-2xl border border-surface-border bg-surface-overlay p-4">
            <p class="text-xs uppercase tracking-[0.2em] text-gray-500">
              Resolved findings
            </p>
            <p class="mt-3 text-3xl font-semibold text-white">
              {{ resolvedFindingsCount }}
            </p>
          </article>
          <article class="rounded-2xl border border-surface-border bg-surface-overlay p-4">
            <p class="text-xs uppercase tracking-[0.2em] text-gray-500">
              New vulns
            </p>
            <p class="mt-3 text-3xl font-semibold text-white">
              {{ newVulnsCount }}
            </p>
          </article>
          <article class="rounded-2xl border border-surface-border bg-surface-overlay p-4">
            <p class="text-xs uppercase tracking-[0.2em] text-gray-500">
              Resolved vulns
            </p>
            <p class="mt-3 text-3xl font-semibold text-white">
              {{ resolvedVulnsCount }}
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
          New findings
        </h2>
        <p class="mt-2 text-sm text-gray-400">
          Only findings introduced by this pull request are listed here.
        </p>
      </div>

      <div class="mt-6 overflow-hidden rounded-2xl border border-surface-border-subtle">
        <div
          v-if="!summary?.delta?.new_findings?.length"
          class="px-4 py-10 text-sm text-gray-500"
        >
          No newly introduced findings were detected.
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
                  Tool
                </th>
                <th class="px-4 py-3 font-medium">
                  Rule
                </th>
                <th class="px-4 py-3 font-medium">
                  File
                </th>
                <th class="px-4 py-3 font-medium">
                  Message
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="finding in summary.delta.new_findings"
                :key="finding.fingerprint"
                class="transition hover:bg-white/5"
              >
                <td class="px-4 py-4">
                  <span :class="['rounded-full px-2.5 py-1 text-xs font-medium', severityClass(finding.severity)]">
                    {{ finding.severity }}
                  </span>
                </td>
                <td class="px-4 py-4 text-gray-300">
                  {{ finding.tool }}
                </td>
                <td class="px-4 py-4 font-mono text-xs text-accent">
                  {{ finding.rule_id }}
                </td>
                <td class="px-4 py-4 text-gray-400">
                  {{ finding.file_path }}
                </td>
                <td class="px-4 py-4 text-gray-300">
                  {{ finding.message }}
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

import { api, type PRSummary } from '@/api/client'

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
const newFindingsCount = computed(() => summary.value?.delta?.new_findings?.length || 0)
const resolvedFindingsCount = computed(() => summary.value?.delta?.resolved_findings?.length || 0)
const newVulnsCount = computed(() => summary.value?.delta?.new_vulns?.length || 0)
const resolvedVulnsCount = computed(() => summary.value?.delta?.resolved_vulns?.length || 0)
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
</script>

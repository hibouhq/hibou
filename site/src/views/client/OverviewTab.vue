<template>
  <div>
    <!-- Stat rail (org-dashboard style) -->
    <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <div class="rounded-md border border-surface-border bg-surface-raised px-4 py-3">
        <p class="text-[11px] uppercase tracking-[0.14em] text-gray-500">
          Active version
        </p>
        <p
          class="mt-1 truncate font-mono text-xl font-semibold"
          :class="activeVersion ? 'text-emerald-300' : 'text-gray-600'"
        >
          {{ activeVersion || 'none' }}
        </p>
      </div>
      <div class="rounded-md border border-surface-border bg-surface-raised px-4 py-3">
        <p class="text-[11px] uppercase tracking-[0.14em] text-gray-500">
          Open vulnerabilities
        </p>
        <div class="mt-1 flex items-baseline gap-2.5">
          <span
            class="text-xl font-semibold"
            :class="impact.length > 0 ? 'text-white' : 'text-gray-600'"
          >{{ impact.length }}</span>
          <span
            v-for="(count, severity) in impactSeverityCounts"
            :key="severity"
            class="text-xs font-medium"
            :class="severityTextClass(severity)"
          >{{ count }} {{ severity }}</span>
        </div>
      </div>
      <div class="rounded-md border border-surface-border bg-surface-raised px-4 py-3">
        <p class="text-[11px] uppercase tracking-[0.14em] text-gray-500">
          Deployments
        </p>
        <p
          class="mt-1 text-xl font-semibold"
          :class="deployments.length > 0 ? 'text-white' : 'text-gray-600'"
        >
          {{ deployments.length }}
        </p>
      </div>
      <div class="rounded-md border border-surface-border bg-surface-raised px-4 py-3">
        <p class="text-[11px] uppercase tracking-[0.14em] text-gray-500">
          Environments
        </p>
        <div class="mt-1 flex flex-wrap items-baseline gap-x-2 gap-y-1">
          <span
            class="text-xl font-semibold"
            :class="environments.length > 0 ? 'text-white' : 'text-gray-600'"
          >{{ environments.length }}</span>
          <span
            v-for="environment in environments"
            :key="environment"
            class="rounded-full bg-surface-overlay px-2 py-0.5 font-mono text-[11px] text-gray-300"
          >{{ environment }}</span>
        </div>
      </div>
    </div>

    <!-- Current deployments -->
    <section class="mt-6">
      <div class="flex items-baseline justify-between">
        <h2 class="text-base font-semibold text-white">
          Current deployments
        </h2>
        <span class="text-xs text-gray-500">Latest active release per environment</span>
      </div>
      <div
        v-if="deploymentsLoading"
        class="mt-3 text-sm text-gray-500"
      >
        Loading deployments…
      </div>
      <div
        v-else-if="currentDeployments.length === 0"
        class="mt-3 rounded-md border border-dashed border-surface-border px-6 py-8 text-center"
      >
        <Rocket class="mx-auto h-7 w-7 text-gray-600" />
        <p class="mt-2 text-sm text-gray-400">
          No active deployments. Record one from the History tab.
        </p>
      </div>
      <div
        v-else
        class="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3"
      >
        <div
          v-for="deployment in currentDeployments"
          :key="deployment.id"
          class="rounded-md border border-surface-border bg-surface-raised px-4 py-3"
        >
          <div class="flex items-center justify-between gap-2">
            <span class="rounded-full bg-surface-overlay px-2 py-0.5 font-mono text-[11px] text-gray-300">{{ deployment.environment }}</span>
            <span
              class="text-xs text-gray-500"
              :title="formatDateTime(deployment.deployed_at)"
            >{{ relativeTime(deployment.deployed_at) }}</span>
          </div>
          <p class="mt-2 truncate font-mono text-sm font-semibold text-emerald-300">
            {{ deployment.release_version || deployment.release_id }}
          </p>
          <p class="mt-1 text-xs text-gray-500">
            Deployed by {{ deployment.deployed_by || 'System' }}
          </p>
        </div>
      </div>
    </section>

    <!-- Impact analysis -->
    <section class="mt-6">
      <div class="flex items-baseline justify-between">
        <h2 class="text-base font-semibold text-white">
          Impact analysis
        </h2>
        <span class="text-xs text-gray-500">Vulnerabilities affecting active deployments</span>
      </div>
      <div
        v-if="impactLoading"
        class="mt-3 text-sm text-gray-500"
      >
        Loading impact analysis…
      </div>
      <div
        v-else-if="impact.length === 0"
        class="mt-3 rounded-md border border-dashed border-surface-border px-6 py-8 text-center"
      >
        <ShieldCheck class="mx-auto h-7 w-7 text-emerald-500/60" />
        <p class="mt-2 text-sm text-gray-400">
          No open vulnerabilities reach this client's active deployments.
        </p>
      </div>
      <div
        v-else
        class="mt-3 overflow-hidden rounded-md border border-surface-border"
      >
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.14em] text-gray-500">
              <tr>
                <th class="px-4 py-2.5 font-medium">
                  Severity
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Advisory
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Component
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Release
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="item in impact"
                :key="`${item.canonical_id}-${item.component_name}-${item.release_version}`"
                class="transition hover:bg-surface-overlay/50"
              >
                <td class="px-4 py-2.5">
                  <span :class="['rounded-full px-2 py-0.5 text-[11px] font-medium', severityClass(item.severity)]">{{ item.severity }}</span>
                </td>
                <td class="px-4 py-2.5 font-mono text-xs">
                  <a
                    v-if="advisoryUrl(item.canonical_id)"
                    :href="advisoryUrl(item.canonical_id)"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="text-accent transition hover:underline"
                  >{{ item.canonical_id }}</a>
                  <span
                    v-else
                    class="text-gray-300"
                  >{{ item.canonical_id }}</span>
                </td>
                <td class="px-4 py-2.5 text-gray-300">
                  {{ item.component_name }}
                </td>
                <td class="px-4 py-2.5 font-mono text-xs text-gray-300">
                  {{ item.release_version }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { Rocket, ShieldCheck } from 'lucide-vue-next'
import { computed, inject, ref, type Ref } from 'vue'

import { type Deployment } from '@/api/client'
import { formatDateTime, relativeTime } from '@/lib/datetime'
import { advisoryUrl } from '@/lib/findingDisplay'

type ImpactItem = {
  canonical_id: string
  severity: string
  component_name: string
  release_version: string
}

const deployments = inject<Ref<Deployment[]>>('clientDeployments', ref([]))
const impact = inject<Ref<ImpactItem[]>>('clientImpact', ref([]))
const deploymentsLoading = inject<Ref<boolean>>('clientDeploymentsLoading', ref(false))
const impactLoading = inject<Ref<boolean>>('clientImpactLoading', ref(false))

const activeDeployment = computed(
  () =>
    deployments.value.find(
      (deployment) =>
        deployment.status.toLowerCase() === 'active',
    ) ?? null,
)
const activeVersion = computed(() => activeDeployment.value?.release_version || null)

const environments = computed(() =>
  [...new Set(deployments.value.map((deployment) => deployment.environment))].sort(),
)

const currentDeployments = computed(() => {
  const latestByEnvironment = new Map<string, Deployment>()
  for (const deployment of deployments.value) {
    if (deployment.status.toLowerCase() !== 'active') continue
    const existing = latestByEnvironment.get(deployment.environment)
    if (!existing || new Date(deployment.deployed_at).getTime() > new Date(existing.deployed_at).getTime()) {
      latestByEnvironment.set(deployment.environment, deployment)
    }
  }
  return [...latestByEnvironment.values()].sort((a, b) => a.environment.localeCompare(b.environment))
})

const IMPACT_SEVERITY_ORDER = ['critical', 'high', 'medium', 'unknown', 'low', 'info']

const impactSeverityCounts = computed(() => {
  const counts: Record<string, number> = {}
  for (const item of impact.value) {
    const severity = item.severity.toLowerCase()
    counts[severity] = (counts[severity] ?? 0) + 1
  }
  const ordered: Record<string, number> = {}
  for (const severity of IMPACT_SEVERITY_ORDER) {
    if (counts[severity]) ordered[severity] = counts[severity]
  }
  return ordered
})

function severityClass(level: string) {
  return `sev-${level.toLowerCase()}`
}

function severityTextClass(severity: string) {
  switch (severity) {
    case 'critical':
      return 'text-danger'
    case 'high':
      return 'text-orange-400'
    case 'medium':
      return 'text-amber-300'
    case 'low':
      return 'text-sky-300'
    default:
      return 'text-gray-400'
  }
}
</script>

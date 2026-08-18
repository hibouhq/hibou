<template>
  <section class="px-4 pb-8">
    <div class="mx-auto mt-6 max-w-2xl rounded-md border border-dashed border-surface-border px-8 py-10">
      <div class="flex items-center gap-3">
        <Container class="h-8 w-8 shrink-0 text-gray-600" />
        <div>
          <h2 class="flex items-center gap-2 text-base font-semibold text-white">
            Deployments
            <span class="rounded-full border border-accent/50 bg-accent/10 px-2 py-0.5 text-[11px] font-medium text-accent">Soon</span>
          </h2>
          <p class="mt-0.5 text-sm text-gray-500">
            Where releases actually run — reconciled from several sources of truth.
          </p>
        </div>
      </div>

      <ul class="mt-6 space-y-3 text-sm">
        <li
          v-for="source in sources"
          :key="source.title"
          class="flex gap-3"
        >
          <component
            :is="source.icon"
            class="mt-0.5 h-4 w-4 shrink-0 text-gray-500"
          />
          <div>
            <p class="font-medium text-gray-200">
              {{ source.title }}
            </p>
            <p class="text-gray-500">
              {{ source.description }}
            </p>
          </div>
        </li>
      </ul>

      <div class="mt-6 border-t border-surface-border-subtle pt-4">
        <p class="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">
          Available today
        </p>
        <p class="mt-2 text-sm text-gray-400">
          Record who runs a release from the
          <RouterLink
            class="text-accent hover:underline"
            :to="{ name: 'repo-releases', params: route.params }"
          >
            Releases tab
          </RouterLink>, from your deploy pipeline with
          <code class="rounded bg-surface-overlay px-1.5 py-0.5 text-xs text-gray-300">hibou release deploy</code>,
          or via the deployments API. The design for this page lives in ADR-024 §8.
        </p>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { Container, GitBranch, Radar, Satellite, TerminalSquare } from 'lucide-vue-next'
import { useRoute } from 'vue-router'

const route = useRoute()

// The four provenance sources of ADR-024 §8, in reconciliation order.
const sources = [
  {
    icon: TerminalSquare,
    title: 'Pipeline-reported',
    description: 'Your CD pipeline records the rollout as it deploys — the push path that exists today.',
  },
  {
    icon: GitBranch,
    title: 'GitOps-derived',
    description: 'Desired state read from your GitOps repo: image tags and chart versions matched to releases.',
  },
  {
    icon: Radar,
    title: 'Cluster-observed',
    description: 'An in-cluster agent reports running image digests — catches hotfixes and manual rollbacks.',
  },
  {
    icon: Satellite,
    title: 'Client self-reported',
    description: 'Client-operated installs ping in with a client-scoped token; labeled and never trusted to reduce exposure.',
  },
]
</script>

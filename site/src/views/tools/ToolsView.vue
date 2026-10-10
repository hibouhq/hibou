<template>
  <div class="mx-auto max-w-5xl px-4 py-6">
    <h1 class="text-lg font-semibold text-white">
      Tools
    </h1>
    <p class="mt-1 text-sm text-gray-400">
      Standalone utilities. They work on what you give them and never change stored data.
    </p>
    <div class="mt-5 grid gap-3 sm:grid-cols-2">
      <RouterLink
        v-for="tool in tools"
        :key="tool.name"
        :to="{ name: tool.route }"
        class="group rounded-xl border border-surface-border bg-surface-raised p-4 transition hover:border-accent/50"
      >
        <div class="flex items-center gap-2">
          <component
            :is="tool.icon"
            class="h-4 w-4 text-accent"
          />
          <span class="font-medium text-white group-hover:text-accent">{{ tool.name }}</span>
        </div>
        <p class="mt-1.5 text-sm text-gray-400">
          {{ tool.description }}
        </p>
      </RouterLink>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ArrowLeftRight, Calculator } from 'lucide-vue-next'

const tools = [
  {
    name: 'CVSS calculator',
    route: 'tool-cvss',
    icon: Calculator,
    description: 'Read any CVSS vector (2.0, 3.0, 3.1, 4.0) with every metric explained, or build a CVSS 4.0 score.',
  },
  {
    name: 'SBOM compare',
    route: 'tool-sbom-compare',
    icon: ArrowLeftRight,
    description: 'Compare two SBOMs: local CycloneDX or SPDX files, or a repository\'s snapshots.',
  },
]
</script>

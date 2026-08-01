<template>
  <section class="overflow-hidden rounded-2xl border border-surface-border bg-surface-raised">
    <div class="flex flex-wrap items-center justify-between gap-4 border-b border-surface-border-subtle px-6 py-4">
      <div>
        <h2 class="text-lg font-semibold text-white">
          API keys
        </h2>
        <p class="mt-0.5 text-sm text-gray-400">
          Fine-grained, scoped tokens for CI, the CLI, and agents.
        </p>
      </div>
      <button
        type="button"
        class="cursor-not-allowed rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 text-sm font-medium text-gray-500"
        disabled
        title="Coming soon"
      >
        New token
      </button>
    </div>

    <div class="px-6 py-12 text-center">
      <div class="mx-auto flex h-12 w-12 items-center justify-center rounded-full border border-surface-border bg-surface-overlay">
        <KeyRound class="h-5 w-5 text-gray-500" />
      </div>
      <p class="mt-3 text-sm text-gray-300">
        No API keys yet.
      </p>
      <p class="mt-1 text-xs text-gray-500">
        Fine-grained, scoped tokens are on the way.
      </p>
    </div>
  </section>
</template>

<script setup lang="ts">
import { KeyRound } from 'lucide-vue-next'
</script>

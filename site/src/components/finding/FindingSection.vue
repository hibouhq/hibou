<template>
  <section :class="boxed ? 'rounded-xl border border-surface-border-subtle bg-surface-overlay/40 p-4' : ''">
    <h3 class="flex items-baseline gap-2 text-xs uppercase tracking-[0.18em] text-gray-500">
      {{ title }}
      <span
        v-if="hint"
        class="text-[11px] normal-case tracking-normal text-gray-600"
      >{{ hint }}</span>
    </h3>
    <div class="mt-2">
      <slot />
    </div>
  </section>
</template>

<script setup lang="ts">
// The one section wrapper the finding detail views share, so every heading in
// the drawer has the same weight, spacing and casing.
defineProps<{
  title: string
  hint?: string
  boxed?: boolean
}>()
</script>

<template>
  <dl class="grid gap-x-6 gap-y-1.5 text-xs sm:grid-cols-2">
    <div
      v-for="fact in visibleFacts"
      :key="fact.label"
      class="flex gap-2"
      :class="fact.wide ? 'sm:col-span-2' : ''"
    >
      <dt
        class="w-28 shrink-0 text-gray-500"
        :title="fact.hint"
      >
        {{ fact.label }}
      </dt>
      <dd
        class="min-w-0 flex-1 break-words text-gray-200"
        :class="fact.mono ? 'font-mono' : ''"
      >
        <a
          v-if="fact.href"
          :href="fact.href"
          target="_blank"
          rel="noopener noreferrer"
          class="text-accent underline decoration-accent/30 underline-offset-2 hover:decoration-accent"
        >{{ fact.value }}</a>
        <template v-else>
          {{ fact.value }}
        </template>
      </dd>
    </div>
  </dl>
</template>

<script setup lang="ts">
import { computed } from 'vue'

import type { Fact } from '@/components/finding/facts'

// A label/value grid for the facts each finding kind carries. Empty values are
// dropped rather than rendered as dashes: a fact a scanner never reported is
// noise, not information.
const props = defineProps<{ facts: Fact[] }>()

const visibleFacts = computed(() =>
  props.facts.filter((fact) => fact.value !== undefined && fact.value !== null && String(fact.value).trim() !== ''),
)
</script>

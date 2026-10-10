<template>
  <div class="mx-auto max-w-5xl px-4 py-6">
    <RouterLink
      :to="{ name: 'tools' }"
      class="text-xs text-gray-500 hover:text-accent"
    >
      ← Tools
    </RouterLink>
    <h1 class="mt-1 text-lg font-semibold text-white">
      CVSS calculator
    </h1>
    <p class="mt-1 text-sm text-gray-400">
      Paste a vector from any advisory to see each metric explained, or choose metrics to build a CVSS 4.0 score.
      The vector stays in the address bar, so a link reproduces it.
    </p>
    <div class="mt-5">
      <CvssCalculator
        :model-value="vector"
        editable
        :allowed-versions="['4.0', '3.1', '3.0', '2.0']"
        @change="onChange"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import CvssCalculator from '@/components/cvss/CvssCalculator.vue'

const route = useRoute()
const router = useRouter()

// The vector lives in the URL hash ("#CVSS:4.0/AV:N/..."), the same shape as
// FIRST's calculator links, so a pasted link's fragment works here too.
const vector = computed(() => decodeURIComponent(route.hash.replace(/^#/, '')))

function onChange(state: { vector: string }) {
  if (state.vector && state.vector !== vector.value) {
    void router.replace({ hash: `#${state.vector}` })
  }
}
</script>

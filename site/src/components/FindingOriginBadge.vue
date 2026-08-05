<script setup lang="ts">
import { computed } from 'vue'

import type { Vulnerability } from '../api/client'

const props = defineProps<{ finding: Pick<Vulnerability, 'origin' | 'origin_token_name' | 'origin_owner_type' | 'scanner_name'> }>()

// Scanner output is the norm and stays unbadged — a badge on everything says
// nothing. Only a finding a person or an agent put there is called out.
const isAuthored = computed(() => props.finding.origin === 'human' || props.finding.origin === 'agent')

const label = computed(() => (props.finding.origin === 'agent' ? 'agent' : 'manual'))

const badgeClass = computed(() =>
  props.finding.origin === 'agent'
    ? 'rounded-full bg-cyan-500/15 px-2 py-0.5 text-[11px] font-medium text-cyan-300'
    : 'rounded-full bg-emerald-500/15 px-2 py-0.5 text-[11px] font-medium text-emerald-300',
)

const title = computed(() => {
  if (props.finding.origin === 'agent') {
    const agent = props.finding.origin_token_name || 'an API token'
    const owner = props.finding.origin_owner_type
    return owner ? `Filed by agent ${agent}, owned by the ${owner}` : `Filed by agent ${agent}`
  }
  return 'Filed manually by a person, not produced by a scanner'
})
</script>

<template>
  <span
    v-if="isAuthored"
    :class="badgeClass"
    :title="title"
  >{{ label }}</span>
</template>

<script setup lang="ts">
import { Clock } from 'lucide-vue-next'
import { computed } from 'vue'

import type { Vulnerability } from '@/api/client'
import { presenceTitle, showsPresenceBadge } from '@/lib/presence'

// ADR-034: a carried finding is still open but was not re-checked on this
// snapshot (grey) or vanished without a code change (amber). Reported
// findings stay unbadged.
const props = defineProps<{ finding: Pick<Vulnerability, 'presence' | 'presence_reason' | 'last_seen_commit'> }>()

const visible = computed(() => showsPresenceBadge(props.finding))
const tone = computed(() => (props.finding.presence === 'unconfirmed' ? 'text-amber-300' : 'text-gray-400'))
const title = computed(() => presenceTitle(props.finding))
</script>

<template>
  <span
    v-if="visible"
    class="ml-1 inline-flex align-middle"
    :class="tone"
    :title="title"
    :aria-label="title"
    role="img"
  >
    <Clock class="h-3.5 w-3.5" />
  </span>
</template>

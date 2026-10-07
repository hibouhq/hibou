<template>
  <section
    class="mb-5 border-l-2 border-danger/60 pl-4"
    aria-label="Known exploitation"
  >
    <h3 class="flex items-center gap-2 text-sm font-semibold text-white">
      <Flame class="h-4 w-4 text-danger" />
      Known exploitation
    </h3>
    <p class="mt-1 text-sm text-gray-300">
      Exploitation in the wild is documented. Catalog removal does not prove this vulnerability is safe.
    </p>
    <div class="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
      <template
        v-for="record in records"
        :key="`${record.source}-${record.identifier}`"
      >
        <a
          v-if="kevSourceUrl(record.source, record.identifier)"
          :href="kevSourceUrl(record.source, record.identifier)"
          target="_blank"
          rel="noopener noreferrer"
          class="inline-flex items-center gap-1 text-accent underline decoration-accent/30 underline-offset-2 hover:decoration-accent"
        >
          {{ kevSourceLabel(record.source) }}
          <span class="font-mono">{{ record.identifier }}</span>
          <ExternalLink class="h-3 w-3" />
        </a>
        <span
          v-else
          class="text-gray-400"
        >{{ kevSourceLabel(record.source) }}</span>
      </template>
    </div>
    <FindingFacts
      class="mt-3"
      :facts="facts"
    />
  </section>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { ExternalLink, Flame } from 'lucide-vue-next'
import type { FindingDetail } from '@/api/client'
import FindingFacts from '@/components/finding/FindingFacts.vue'
import type { Fact } from '@/components/finding/facts'
import { kevSourceLabel, kevSourceUrl } from '@/lib/kev'

const props = defineProps<{
  kev: NonNullable<FindingDetail['kev']>
  identifier: string
}>()

const records = computed(() => props.kev.sources.flatMap(source => {
  const entries = props.kev.entries?.filter(entry => entry.source === source) ?? []
  return entries.length ? entries : [{ source, identifier: source === 'cisa' ? props.identifier : '' }]
}))

const facts = computed<Fact[]>(() => [
  { label: 'Catalog listed on', value: props.kev.date_added },
  ...(props.kev.due_date
    ? [{ label: 'US federal due date', value: props.kev.due_date, hint: 'CISA BOD 22-01 deadline for US federal agencies, not a universal remediation deadline' }]
    : []),
  ...(props.kev.ransomware_use
    ? [{ label: 'Ransomware use', value: 'Known campaigns' }]
    : []),
])
</script>

<template>
  <!-- Everything fits one screen; the modal hides its Details tab for this kind. -->
  <div
    v-if="section !== 'details'"
    class="space-y-5"
  >
    <FindingSection
      v-if="finding.description && finding.description !== finding.title"
      title="Description"
    >
      <p class="whitespace-pre-wrap text-sm text-gray-300">
        {{ finding.description }}
      </p>
    </FindingSection>

    <FindingSection
      title="Details"
      boxed
    >
      <FindingFacts :facts="facts" />
    </FindingSection>

    <FindingSection
      v-if="finding.solution || finding.remediation_link"
      title="How to fix"
      boxed
      class="!border-ok/30 !bg-ok/5"
    >
      <p
        v-if="finding.solution"
        class="text-sm text-gray-300"
      >
        {{ finding.solution }}
      </p>
      <a
        v-if="safeHref(finding.remediation_link)"
        :href="safeHref(finding.remediation_link)"
        target="_blank"
        rel="noopener noreferrer"
        class="mt-1 inline-block text-xs text-accent underline underline-offset-2"
      >Remediation guidance</a>
    </FindingSection>
  </div>
</template>

<script setup lang="ts">
import { safeHref } from '@/lib/safeUrl'
import { computed } from 'vue'

import type { FindingDetail } from '@/api/client'
import type { Fact } from '@/components/finding/facts'
import FindingFacts from '@/components/finding/FindingFacts.vue'
import FindingSection from '@/components/finding/FindingSection.vue'

// Fallback for the kinds without a shape of their own (manual, generic, and
// anything a future scanner introduces): show what the record actually holds
// instead of pretending it is a dependency or a code finding.
const props = defineProps<{
  detail: FindingDetail
  /** Which half the modal is rendering: the overview or the reference tab. */
  section?: 'overview' | 'details'
  provider?: string
  slug?: string
  repoSlug?: string
  repoHtmlUrl?: string
  forgeProvider?: string
}>()

const finding = computed(() => props.detail.finding)

const facts = computed<Fact[]>(() => [
  { label: 'Identifier', value: finding.value.primary_identifier_value, mono: true },
  { label: 'Kind', value: finding.value.type },
  { label: 'Scanner', value: finding.value.scanner_name },
  { label: 'Component', value: componentLabel.value, mono: true },
  { label: 'File', value: fileLabel.value, mono: true, wide: true },
  { label: 'Reported by', value: finding.value.origin },
])

const componentLabel = computed(() => {
  const name = finding.value.component_name
  if (!name) return ''
  return finding.value.component_version ? `${name}@${finding.value.component_version}` : name
})

const fileLabel = computed(() => {
  const path = finding.value.file_path
  if (!path) return ''
  return finding.value.start_line ? `${path}:${finding.value.start_line}` : path
})
</script>

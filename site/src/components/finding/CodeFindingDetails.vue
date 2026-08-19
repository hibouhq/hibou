<template>
  <!-- Overview: the code and how to fix it. -->
  <div
    v-if="section !== 'details'"
    class="space-y-5"
  >
    <!-- The code is the finding. It leads, in place, with the offending lines
         marked — reading the rule id first tells you nothing you can act on. -->
    <FindingSection
      v-if="finding.file_path"
      title="Where"
      :hint="lineLabel"
    >
      <FindingCodeSnippet
        :provider="provider ?? ''"
        :slug="slug ?? ''"
        :repo-slug="repoSlug ?? ''"
        :snapshot-id="finding.snapshot_id"
        :path="finding.file_path"
        :start-line="finding.start_line"
        :end-line="finding.end_line"
        :repo-html-url="repoHtmlUrl"
        :forge-provider="forgeProvider"
        :fallback-sha="fallbackSha"
      />
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
        v-if="finding.remediation_link"
        :href="finding.remediation_link"
        target="_blank"
        rel="noopener noreferrer"
        class="mt-1 inline-block text-xs text-accent underline underline-offset-2"
      >Remediation guidance</a>
    </FindingSection>
  </div>

  <!-- Details: the rule record and the scanner's full message. -->
  <div
    v-else
    class="space-y-5"
  >
    <FindingSection
      v-if="message"
      title="What the rule found"
    >
      <MarkdownText :text="message" />
    </FindingSection>

    <FindingSection
      title="Rule"
      boxed
    >
      <div class="flex flex-wrap items-center gap-2">
        <span class="font-mono text-sm text-white">{{ finding.primary_identifier_value || 'unnamed rule' }}</span>
        <span
          v-if="finding.scanner_name"
          class="rounded-full bg-surface-overlay px-2 py-0.5 text-[11px] text-gray-400"
        >{{ finding.scanner_name }}</span>
      </div>
      <FindingFacts
        class="mt-2"
        :facts="ruleFacts"
      />
      <div
        v-if="cwes.length > 0"
        class="mt-2 flex flex-wrap gap-1.5"
      >
        <a
          v-for="cwe in cwes"
          :key="cwe"
          :href="cweUrl(cwe)"
          target="_blank"
          rel="noopener noreferrer"
          class="rounded-md border border-surface-border px-2 py-0.5 text-[11px] text-gray-300 transition hover:border-accent/50 hover:text-white"
        >{{ cwe }}</a>
      </div>
    </FindingSection>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

import type { FindingDetail } from '@/api/client'
import MarkdownText from '@/components/MarkdownText.vue'
import type { Fact } from '@/components/finding/facts'
import FindingCodeSnippet from '@/components/finding/FindingCodeSnippet.vue'
import FindingFacts from '@/components/finding/FindingFacts.vue'
import FindingSection from '@/components/finding/FindingSection.vue'
import { cweUrl } from '@/lib/findingDisplay'

// First-party code findings (sast, dast, fuzzing): a rule fired at a place in
// the source. No package, no advisory, no upgrade — a code change fixes it.
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
// The newest ref currently detecting the finding — the commit the snippet
// links against when the source fetch cannot supply one.
const fallbackSha = computed(() => props.detail.occurrences[0]?.commit_sha ?? '')
// The title is already in the drawer header; repeating it as the message adds
// nothing, so only a distinct description is shown.
const message = computed(() => (finding.value.description !== finding.value.title ? finding.value.description : ''))
const cwes = computed(() => props.detail.advisory?.cwes ?? [])

const lineLabel = computed(() => {
  const start = finding.value.start_line
  const end = finding.value.end_line
  if (!start) return ''
  return end && end !== start ? `lines ${start}–${end}` : `line ${start}`
})

const ruleFacts = computed<Fact[]>(() => [
  { label: 'Language', value: finding.value.language },
  { label: 'Confidence', value: finding.value.confidence },
  { label: 'OWASP', value: finding.value.owasp_top_10 },
  { label: 'Scanner', value: finding.value.scanner_vendor },
])
</script>

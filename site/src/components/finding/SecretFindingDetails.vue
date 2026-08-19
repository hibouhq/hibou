<template>
  <!-- Everything fits one screen; the modal hides its Details tab for this kind. -->
  <div
    v-if="section !== 'details'"
    class="space-y-5"
  >
    <!-- A leaked credential is an incident, not a defect: the first thing on
         screen is what to do about it, in order. -->
    <FindingSection
      v-if="resolved"
      title="Revoked"
      boxed
      class="!border-ok/30 !bg-ok/5"
    >
      <p class="text-sm text-gray-200">
        A revocation was attested for this credential, so it no longer counts against the gate.
      </p>
      <p class="mt-1 text-xs text-gray-500">
        If the credential was never actually rotated, reopen this finding — the history keeps who attested it and when.
      </p>
    </FindingSection>

    <FindingSection
      v-else
      title="Act on this"
      boxed
      class="!border-amber-500/30 !bg-amber-500/5"
    >
      <ol class="space-y-1.5 text-sm text-gray-200">
        <li
          v-for="(step, index) in steps"
          :key="step"
          class="flex gap-2"
        >
          <span class="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-amber-500/15 text-[11px] font-semibold text-amber-300">{{ index + 1 }}</span>
          <span>{{ step }}</span>
        </li>
      </ol>
      <p class="mt-2 text-xs text-amber-200/80">
        Removing the line does not fix it — the credential stays valid in the git history until it is revoked.
      </p>
    </FindingSection>

    <FindingSection
      title="The leak"
      boxed
    >
      <div class="flex flex-wrap items-center gap-2">
        <span class="font-mono text-sm text-white">{{ finding.secret_type || 'unclassified credential' }}</span>
        <span
          v-if="finding.verified === true"
          class="rounded-full border border-danger/40 bg-danger/10 px-2 py-0.5 text-[11px] text-danger"
          title="The scanner authenticated with this credential — it is live"
        >verified live</span>
        <span
          v-else-if="finding.verified === false"
          class="rounded-full border border-surface-border bg-surface-overlay px-2 py-0.5 text-[11px] text-gray-400"
          title="The scanner could not confirm the credential is still valid; it may still be"
        >unverified</span>
      </div>
      <FindingFacts
        class="mt-2"
        :facts="leakFacts"
      />
      <!-- Deliberately no inline source preview: rendering the surrounding
           lines would put the secret itself back on screen (and in caches) for
           everyone who can read this finding. -->
      <p class="mt-2 text-[11px] text-gray-600">
        The matching line is not shown here — displaying it would leak the credential again.
      </p>
    </FindingSection>

    <FindingSection
      v-if="finding.description && finding.description !== finding.title"
      title="Scanner notes"
    >
      <p class="whitespace-pre-wrap text-sm text-gray-300">
        {{ finding.description }}
      </p>
    </FindingSection>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

import type { FindingDetail } from '@/api/client'
import type { Fact } from '@/components/finding/facts'
import FindingFacts from '@/components/finding/FindingFacts.vue'
import FindingSection from '@/components/finding/FindingSection.vue'
import { forgeBlobAtCommitUrl, forgeCommitUrl } from '@/lib/forgeLinks'

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

const steps = [
  'Revoke the credential at its issuer.',
  'Rotate it and update whatever consumes it.',
  'Attest the revocation here — a secret never resolves by disappearing from a scan.',
]

const finding = computed(() => props.detail.finding)
const resolved = computed(() => finding.value.status === 'resolved')
const commitSha = computed(() => finding.value.commit_sha || props.detail.occurrences[0]?.commit_sha || '')

const leakFacts = computed<Fact[]>(() => [
  // File and commit link straight into the forge when its URL is known.
  { label: 'File', value: location.value, mono: true, wide: true, href: blobUrl.value || undefined },
  { label: 'Commit', value: commitSha.value ? commitSha.value.slice(0, 12) : '', mono: true, href: commitUrl.value || undefined },
  { label: 'Author', value: finding.value.author_email, hint: 'Who committed the leak — ask them which system the credential belongs to' },
  { label: 'Scanner', value: finding.value.scanner_name },
])

const commitUrl = computed(() => forgeCommitUrl(props.repoHtmlUrl, props.forgeProvider ?? 'github', commitSha.value))

const location = computed(() => {
  const path = finding.value.file_path
  if (!path) return ''
  return finding.value.start_line ? `${path}:${finding.value.start_line}` : path
})

const blobUrl = computed(() =>
  finding.value.file_path && commitSha.value
    ? forgeBlobAtCommitUrl(props.repoHtmlUrl, props.forgeProvider ?? 'github', commitSha.value, finding.value.file_path, { startLine: finding.value.start_line })
    : '',
)
</script>

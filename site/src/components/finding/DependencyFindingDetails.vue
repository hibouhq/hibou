<template>
  <!-- Overview: what is affected and what to do about it. -->
  <div
    v-if="section !== 'details'"
    class="space-y-5"
  >
    <!-- How bad, at a glance: the score decides priority, so it is on the
         overview rather than buried in Details. -->
    <FindingSection
      v-if="cvss"
      title="Score"
      boxed
    >
      <div class="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span
          class="text-2xl font-semibold tabular-nums"
          :class="cvss.className"
        >{{ cvss.score }}</span>
        <span class="text-xs text-gray-400">CVSS{{ cvss.version ? ` v${cvss.version}` : '' }} · {{ cvss.band }}</span>
      </div>
      <p
        v-if="advisory?.cvss_vector"
        class="mt-1 break-all font-mono text-[11px] text-gray-500"
      >
        {{ advisory.cvss_vector }}
      </p>
    </FindingSection>

    <!-- What is affected. For a dependency finding the package is the subject,
         so it leads; the file path a scanner may have attached is incidental. -->
    <FindingSection
      title="Affected package"
      boxed
    >
      <p class="font-mono text-sm text-white">
        {{ finding.component_name || 'unknown package' }}<span
          v-if="finding.component_version"
          class="text-gray-400"
        >@{{ finding.component_version }}</span>
      </p>
      <FindingFacts
        class="mt-2"
        :facts="packageFacts"
      />
    </FindingSection>

    <!-- Remediation before the advisory prose: the upgrade target is the
         decision, everything else is evidence for it. -->
    <FindingSection
      v-if="fixedVersions.length > 0 || finding.solution || finding.remediation_link"
      title="Remediation"
      boxed
      class="!border-ok/30 !bg-ok/5"
    >
      <div
        v-if="fixedVersions.length > 0"
        class="flex flex-wrap items-center gap-1.5"
      >
        <span class="text-xs text-gray-400">Fixed in</span>
        <span
          v-for="version in fixedVersions"
          :key="version"
          class="rounded-md border border-ok/30 bg-ok/10 px-2 py-0.5 font-mono text-xs text-ok"
        >{{ version }}</span>
      </div>
      <p
        v-if="finding.solution"
        class="mt-2 text-sm text-gray-300"
      >
        {{ finding.solution }}
      </p>
      <a
        v-if="finding.remediation_link"
        :href="finding.remediation_link"
        target="_blank"
        rel="noopener noreferrer"
        class="mt-2 inline-block text-xs text-accent underline underline-offset-2"
      >Remediation guidance</a>
    </FindingSection>

    <!-- Reachability: the one signal that changes the verdict on an otherwise
         identical CVE, so it gets a sentence rather than only the header chip. -->
    <FindingSection
      v-if="finding.reachability && finding.reachability !== 'unknown'"
      title="Reachability"
    >
      <p
        class="text-sm"
        :class="finding.reachability === 'not_reachable' ? 'text-gray-400' : 'text-danger'"
      >
        <template v-if="finding.reachability === 'not_reachable'">
          Call-graph analysis found no path from this code to the vulnerable symbol. Real, but not exploitable as used here.
        </template>
        <template v-else>
          Call-graph analysis put the vulnerable symbol on this code's call path — treat as exploitable.
        </template>
      </p>
    </FindingSection>
  </div>

  <!-- Details: the reference material — advisory record, full text, references. -->
  <div
    v-else
    class="space-y-5"
  >
    <FindingSection
      v-if="advisory || finding.primary_identifier_value"
      title="Advisory"
      boxed
    >
      <div class="flex flex-wrap items-center gap-2">
        <a
          v-if="identifierUrl"
          :href="identifierUrl"
          target="_blank"
          rel="noopener noreferrer"
          class="font-mono text-sm text-accent underline underline-offset-2"
        >{{ identifier }}</a>
        <span
          v-else
          class="font-mono text-sm text-white"
        >{{ identifier }}</span>
        <template
          v-for="alias in aliases"
          :key="alias"
        >
          <a
            v-if="advisoryUrl(alias)"
            :href="advisoryUrl(alias)"
            target="_blank"
            rel="noopener noreferrer"
            class="rounded-full bg-surface-overlay px-2 py-0.5 font-mono text-[11px] text-gray-400 transition hover:text-accent hover:underline"
          >{{ alias }}</a>
          <span
            v-else
            class="rounded-full bg-surface-overlay px-2 py-0.5 font-mono text-[11px] text-gray-400"
          >{{ alias }}</span>
        </template>
      </div>
      <p
        v-if="advisoryTitle"
        class="mt-1.5 text-sm text-gray-300"
      >
        {{ advisoryTitle }}
      </p>
      <FindingFacts
        class="mt-2"
        :facts="advisoryFacts"
      />
    </FindingSection>

    <FindingSection
      v-if="description"
      title="Description"
    >
      <!-- Advisory text is markdown (### Impact, lists, code spans). -->
      <MarkdownText :text="description" />
    </FindingSection>

    <FindingSection
      v-if="references.length > 0"
      title="References"
    >
      <ul class="space-y-1">
        <li
          v-for="reference in visibleReferences"
          :key="reference"
        >
          <a
            :href="reference"
            target="_blank"
            rel="noopener noreferrer"
            class="break-all text-xs text-accent underline decoration-accent/30 underline-offset-2 hover:decoration-accent"
          >{{ reference }}</a>
        </li>
      </ul>
      <button
        v-if="references.length > REFERENCE_PREVIEW && !allReferences"
        type="button"
        class="mt-1 text-xs text-gray-400 underline transition hover:text-white"
        @click="allReferences = true"
      >
        Show {{ references.length - REFERENCE_PREVIEW }} more
      </button>
    </FindingSection>

    <!-- The advisory's own history, which is not this finding's history. A
         finding timeline says what happened to it here; this says what happened
         to the advisory anywhere, and it is what explains a finding whose facts
         changed underneath somebody with no code change. -->
    <FindingSection
      v-if="advisoryHistory.length"
      title="Advisory history"
    >
      <ul class="space-y-2">
        <li
          v-for="(event, index) in advisoryHistory"
          :key="`${event.kind}-${event.occurred_at}-${index}`"
          class="flex items-baseline gap-2.5 text-xs"
        >
          <span
            class="mt-1 h-1.5 w-1.5 shrink-0 rounded-full"
            :class="event.external ? 'bg-gray-600' : 'bg-accent'"
          />
          <span class="text-gray-300">{{ historyLabel(event.kind) }}</span>
          <span
            v-if="!event.external"
            class="rounded-full bg-accent-muted/40 px-1.5 text-[10px] font-medium text-accent"
          >here</span>
          <span class="ml-auto shrink-0 text-gray-500">{{ historyDate(event.occurred_at) }}</span>
        </li>
      </ul>
    </FindingSection>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { api, type AdvisoryActivityEvent, type FindingDetail } from '@/api/client'
import MarkdownText from '@/components/MarkdownText.vue'
import { isLocallyCurated } from '@/lib/purl'
import type { Fact } from '@/components/finding/facts'
import FindingFacts from '@/components/finding/FindingFacts.vue'
import FindingSection from '@/components/finding/FindingSection.vue'
import { advisoryUrl } from '@/lib/findingDisplay'

// Component-backed findings (dependency, container, malware): a package, an
// advisory, and a version to upgrade to.
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

const REFERENCE_PREVIEW = 5
const allReferences = ref(false)

const finding = computed(() => props.detail.finding)
const advisory = computed(() => props.detail.advisory)
const identifier = computed(() => advisory.value?.canonical_id || finding.value.primary_identifier_value || finding.value.scanner_name || 'unknown')
const identifierUrl = computed(() => advisoryUrl(identifier.value))
const aliases = computed(() => advisory.value?.aliases ?? [])
// The drawer header already carries the title; only a different advisory title
// adds anything.
const advisoryTitle = computed(() => (advisory.value?.title !== finding.value.title ? advisory.value?.title ?? '' : ''))
const fixedVersions = computed(() => advisory.value?.fixed_versions ?? [])
const references = computed(() => advisory.value?.references ?? [])
const visibleReferences = computed(() => (allReferences.value ? references.value : references.value.slice(0, REFERENCE_PREVIEW)))
// The scanner's own text is usually the shorter one; the advisory's is the
// authoritative description when the scanner did not carry one.
const description = computed(() => finding.value.description || advisory.value?.description || '')

const locallyCurated = computed(() => isLocallyCurated(finding.value.scanner_name))

/**
 * The advisory's own history, which is not the finding's history.
 *
 * A finding's timeline says what happened to it here — detected, accepted,
 * fixed. This says what happened to the advisory anywhere, upstream included,
 * and it is the half that explains why a finding's facts changed underneath
 * somebody without anyone touching the code.
 */
const advisoryHistory = ref<AdvisoryActivityEvent[]>([])

const HISTORY_LABELS: Record<string, string> = {
  published: 'Published upstream',
  cna_revised: 'Vendor revised the record',
  enriched: 'Enriched upstream',
  withdrawn: 'Withdrawn upstream',
  coordinates_upstreamed: 'Upstream published coordinates',
  coordinates_authored: 'Packages mapped here',
  superseded: 'Superseded by upstream',
  diverged: 'Upstream disagrees with the mapping here',
  mapping_revoked: 'Mapping revoked',
  kev_listed: 'Listed as actively exploited (KEV)',
  kev_delisted: 'Removed from exploited catalogs',
}

function historyLabel(kind: string): string {
  return HISTORY_LABELS[kind] ?? kind
}

function historyDate(value: string): string {
  return new Date(value).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

watch(() => finding.value.primary_identifier_value, async identifier => {
  advisoryHistory.value = []
  if (!identifier?.startsWith('CVE-')) return
  try {
    const response = await api.getAdvisoryEvents(identifier)
    advisoryHistory.value = response.data ?? []
  } catch {
    // Supporting context: its absence must not break the finding view.
  }
}, { immediate: true })

const packageFacts = computed<Fact[]>(() => [
  { label: 'Ecosystem', value: finding.value.ecosystem },
  // Authored findings say who decided, not which feed reported: that is the
  // whole difference between "a heuristic matched this" and "someone here
  // decided this applies".
  {
    label: locallyCurated.value ? 'Source' : 'Scanner',
    value: locallyCurated.value ? 'Curated here' : finding.value.scanner_name,
  },
  { label: 'Package URL', value: finding.value.component_purl, mono: true, wide: true },
  { label: 'Manifest', value: finding.value.file_path, mono: true, wide: true, hint: 'The file the dependency was declared in' },
])

// CVSS v3/v4 qualitative bands (FIRST): the colour says the band before the
// number is read.
const cvss = computed(() => {
  const score = Number.parseFloat(advisory.value?.cvss_score ?? '')
  if (!Number.isFinite(score)) return null
  const version = /^CVSS:(\d\.\d)\//i.exec(advisory.value?.cvss_vector ?? '')?.[1]
  const band = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : score > 0 ? 'low' : 'none'
  const className = { critical: 'text-red-300', high: 'text-orange-300', medium: 'text-amber-300', low: 'text-sky-300', none: 'text-gray-400' }[band]
  return { score: score.toFixed(1), version, band, className }
})

const advisoryFacts = computed<Fact[]>(() => [
  { label: 'CVSS', value: advisory.value?.cvss_score },
  { label: 'Vector', value: advisory.value?.cvss_vector, mono: true },
  ...(advisory.value?.is_malware
    ? [{ label: 'Malware', value: (advisory.value.malware_type || 'malicious code').replace(/_/g, ' '), hint: 'This package is known malicious — remove it; do not upgrade' } satisfies Fact]
    : []),
])
</script>

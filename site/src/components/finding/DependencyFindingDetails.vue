<template>
  <!-- Overview: what is affected and what to do about it. -->
  <div
    v-if="section !== 'details'"
    class="space-y-5"
  >
    <!-- How bad, how likely, and says who: the score decides priority, so it
         is on the overview rather than buried in Details. -->
    <RiskScoreBlock :finding="finding" />

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
        @navigate="emit('navigate')"
      />
    </FindingSection>

    <!-- Remediation before the advisory prose: the upgrade target is the
         decision, everything else is evidence for it. -->
    <FindingSection
      v-if="fixedVersions.length > 0 || suggestedVersion || finding.solution || finding.remediation_link"
      title="Remediation"
      boxed
      class="!border-ok/30 !bg-ok/5"
    >
      <div
        v-if="fixedVersions.length > 0"
        class="flex flex-wrap items-center gap-1.5"
      >
        <span class="text-xs text-gray-400">Fixed in</span>
        <!-- A fix still in cooldown is marked before anyone bumps to it: the
             gate would hold that PR (ADR-048 §8). -->
        <span
          v-for="version in fixedVersions"
          :key="version"
          class="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-xs"
          :class="versionChipClass(version, 'ok')"
          :title="versionTitle(version)"
        >
          {{ version }}
          <Clock
            v-if="remediationFor(version)?.in_cooldown"
            class="signal-icon signal-cooldown"
          />
          <ShieldAlert
            v-else-if="remediationFor(version)?.decision === 'deny'"
            class="signal-icon signal-unpublished"
          />
        </span>
      </div>
      <!-- deps.dev's "low risk" pick (ADR-048 §8): shown when the advisory names
           no fix, or names one still in cooldown. Labelled with its source; it
           is a suggestion, not the advisory's fix. -->
      <div
        v-if="suggestedVersion"
        class="flex flex-wrap items-center gap-1.5"
        :class="fixedVersions.length > 0 ? 'mt-2' : ''"
      >
        <span class="text-xs text-gray-400">Suggested by deps.dev</span>
        <span
          class="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-xs"
          :class="versionChipClass(suggestedVersion, 'accent')"
          :title="versionTitle(suggestedVersion)"
        >
          {{ suggestedVersion }}
          <Clock
            v-if="remediationFor(suggestedVersion)?.in_cooldown"
            class="signal-icon signal-cooldown"
          />
        </span>
      </div>
      <p
        v-if="finding.solution"
        class="mt-2 text-sm text-gray-300"
      >
        {{ finding.solution }}
      </p>
      <a
        v-if="safeHref(finding.remediation_link)"
        :href="safeHref(finding.remediation_link)"
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
            :href="safeHref(reference)"
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
import { safeHref } from '@/lib/safeUrl'
import { computed, ref, watch } from 'vue'

import { api, type AdvisoryActivityEvent, type FindingDetail, type RemediationVersion } from '@/api/client'
import { Clock, ShieldAlert } from 'lucide-vue-next'
import MarkdownText from '@/components/MarkdownText.vue'
import { isLocallyCurated } from '@/lib/purl'
import type { Fact } from '@/components/finding/facts'
import FindingFacts from '@/components/finding/FindingFacts.vue'
import FindingSection from '@/components/finding/FindingSection.vue'
import RiskScoreBlock from '@/components/finding/RiskScoreBlock.vue'
import { advisoryUrl } from '@/lib/findingDisplay'
import { raterName } from '@/lib/riskMetrics'

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

const emit = defineEmits<{ (event: 'navigate'): void }>()

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
const signals = computed(() => props.detail.signals)
/** deps.dev's pick, only when it adds to what the advisory says. */
const suggestedVersion = computed(() => {
  const version = signals.value?.recommended_version
  if (!version || fixedVersions.value.includes(version)) return ''
  return version
})

const remediation = computed(() => props.detail.remediation ?? [])
function remediationFor(version: string): RemediationVersion | undefined {
  return remediation.value.find((entry) => entry.version === version)
}
/** Chip colour follows the policy verdict: amber while held, red when denied. */
function versionChipClass(version: string, base: 'ok' | 'accent'): string {
  const entry = remediationFor(version)
  if (entry?.in_cooldown) return 'border-[#d29922]/40 bg-[#d29922]/10 text-[#d29922]'
  if (entry?.decision === 'deny') return 'border-danger/40 bg-danger/10 text-danger'
  return base === 'ok' ? 'border-ok/30 bg-ok/10 text-ok' : 'border-accent/30 bg-accent/10 text-accent'
}
function versionTitle(version: string): string {
  const entry = remediationFor(version)
  if (!entry) return ''
  if (entry.in_cooldown) return `In cooldown until ${shortDate(entry.cooldown_until)}: the gate holds a bump to this version until then`
  if (entry.decision === 'deny') return entry.reason || 'Denied by the package policy'
  if (entry.warnings?.length) return entry.warnings.join('; ')
  return entry.evaluated ? 'Clear: no cooldown or policy hold on this version' : entry.reason || ''
}

function shortDate(value?: string): string {
  if (!value) return ''
  return new Date(value).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

/** Package signals as facts (ADR-048): the registry's view of this version. */
const signalFacts = computed<Fact[]>(() => {
  const state = signals.value
  if (!state) return []
  const facts: Fact[] = []
  if (state.published_at) {
    facts.push({
      label: 'Published',
      value: shortDate(state.published_at),
      hint: state.in_cooldown ? `In cooldown: deps.dev recommends waiting until ${shortDate(state.cooldown_until)} before adopting this version` : undefined,
    })
  }
  if (state.in_cooldown) {
    facts.push({ label: 'Cooldown', value: `until ${shortDate(state.cooldown_until)}`, hint: 'A fresh release: give scanners and reviewers time before it reaches a build' })
  }
  if (state.unpublished) {
    facts.push({ label: 'Registry', value: 'unpublished', hint: 'This version is no longer on the public registry; often a takedown' })
  }
  if (state.deprecated) {
    facts.push({ label: 'Registry', value: 'deprecated', hint: state.deprecated_reason || undefined, wide: Boolean(state.deprecated_reason) })
  }
  if (state.low_usage) {
    facts.push({
      label: 'Usage',
      value: 'low',
      hint: state.alternatives?.length ? `Did you mean ${state.alternatives.join(', ')}?` : 'Verify this is the package you meant',
    })
  }
  return facts
})
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
  // The package is the subject: link it to the dependencies view, where the
  // same version shows its other advisories and where it is used.
  {
    label: 'Package URL',
    value: finding.value.component_purl,
    mono: true,
    wide: true,
    to: finding.value.component_purl && props.provider && props.slug && props.repoSlug
      ? { name: 'repo-dependencies', params: { provider: props.provider, slug: props.slug, repoSlug: props.repoSlug }, query: { component: finding.value.component_purl } }
      : undefined,
    hint: 'Open in Dependencies',
  },
  { label: 'Manifest', value: finding.value.file_path, mono: true, wide: true, hint: 'The file the dependency was declared in' },
  ...signalFacts.value,
])

const advisoryFacts = computed<Fact[]>(() => [
  // The advisory's headline, which a distro's own rating on this finding may
  // override (the Score block says which applies).
  { label: 'Advisory CVSS', value: advisory.value?.cvss?.score?.toFixed(1), hint: advisory.value?.rated_by ? `Rated by ${raterName(advisory.value.rated_by)}` : undefined },
  { label: 'Vector', value: advisory.value?.cvss?.vector, mono: true },
  ...(advisory.value?.is_malware
    ? [{ label: 'Malware', value: (advisory.value.malware_type || 'malicious code').replace(/_/g, ' '), hint: 'This package is known malicious — remove it; do not upgrade' } satisfies Fact]
    : []),
])
</script>

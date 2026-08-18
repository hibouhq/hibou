<template>
  <div class="space-y-5">
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

    <!-- Advisory -->
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
        <span
          v-for="alias in aliases"
          :key="alias"
          class="rounded-full bg-surface-overlay px-2 py-0.5 font-mono text-[11px] text-gray-400"
        >{{ alias }}</span>
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

    <FindingSection
      v-if="description"
      title="Description"
    >
      <p class="whitespace-pre-wrap text-sm text-gray-300">
        {{ description }}
      </p>
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
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'

import type { FindingDetail } from '@/api/client'
import type { Fact } from '@/components/finding/facts'
import FindingFacts from '@/components/finding/FindingFacts.vue'
import FindingSection from '@/components/finding/FindingSection.vue'
import { advisoryUrl, cweUrl } from '@/lib/findingDisplay'

// Component-backed findings (dependency, container, malware): a package, an
// advisory, and a version to upgrade to.
const props = defineProps<{
  detail: FindingDetail
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
const cwes = computed(() => advisory.value?.cwes ?? [])
const fixedVersions = computed(() => advisory.value?.fixed_versions ?? [])
const references = computed(() => advisory.value?.references ?? [])
const visibleReferences = computed(() => (allReferences.value ? references.value : references.value.slice(0, REFERENCE_PREVIEW)))
// The scanner's own text is usually the shorter one; the advisory's is the
// authoritative description when the scanner did not carry one.
const description = computed(() => finding.value.description || advisory.value?.description || '')

const packageFacts = computed<Fact[]>(() => [
  { label: 'Ecosystem', value: finding.value.ecosystem },
  { label: 'Scanner', value: finding.value.scanner_name },
  { label: 'Package URL', value: finding.value.component_purl, mono: true, wide: true },
  { label: 'Manifest', value: finding.value.file_path, mono: true, wide: true, hint: 'The file the dependency was declared in' },
])

const advisoryFacts = computed<Fact[]>(() => [
  { label: 'CVSS', value: advisory.value?.cvss_score },
  { label: 'Vector', value: advisory.value?.cvss_vector, mono: true },
])
</script>

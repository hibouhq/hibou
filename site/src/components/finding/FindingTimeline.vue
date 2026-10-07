<template>
  <div>
    <p
      v-if="loading"
      class="py-8 text-center text-sm text-gray-500"
    >
      Loading history…
    </p>

    <p
      v-else-if="error"
      class="py-8 text-center text-sm text-danger"
    >
      {{ error }}
    </p>

    <div
      v-else-if="events.length === 0"
      class="py-10 text-center"
    >
      <History class="mx-auto h-6 w-6 text-gray-600" />
      <p class="mt-2 text-sm text-gray-300">
        No history yet
      </p>
      <p class="mt-1 text-xs text-gray-500">
        Scans and triage decisions on this finding will appear here.
      </p>
    </div>

    <template v-else>
      <ol class="relative space-y-0 border-l border-surface-border pl-5">
        <li
          v-for="(event, index) in events"
          :key="`${event.source}-${event.at}-${index}`"
          class="relative py-2.5"
        >
          <!-- Marker on the rail: colour carries the meaning, icon the source -->
          <span
            class="absolute -left-[27px] flex h-4 w-4 items-center justify-center rounded-full border"
            :class="markerClass(event)"
            :title="event.source === 'scan' ? 'Observed by a scan' : event.source === 'advisory' ? 'Exploitation catalog update' : 'Recorded decision'"
          >
            <component
              :is="event.source === 'scan' ? Radar : event.source === 'advisory' ? Flame : UserCheck"
              class="h-2.5 w-2.5"
            />
          </span>

          <div class="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
            <span class="text-sm font-medium text-gray-100">{{ eventLabel(event) }}</span>
            <span
              v-if="event.source === 'advisory' && stringOf(event, 'source')"
              class="text-xs text-gray-400"
            >{{ kevSourceLabel(stringOf(event, 'source')) }}</span>
            <span
              v-if="event.actor_display"
              class="text-xs text-gray-400"
            >by {{ event.actor_display }}</span>
            <span
              v-if="event.ref_name"
              class="font-mono text-xs text-gray-500"
            >on {{ shortRef(event.ref_name) }}</span>
            <CommitLink
              v-if="event.commit_sha"
              class="text-xs"
              :sha="event.commit_sha"
              :repo-html-url="repoHtmlUrl"
              :provider="forgeProvider"
            />
            <span
              class="ml-auto shrink-0 text-xs"
              :class="event.kind === 'first_detected' ? 'text-gray-300' : 'text-gray-500'"
              :title="formatDateTime(event.at)"
            >{{ event.kind === 'first_detected' ? formatDateTime(event.at) : relativeTime(event.at) }}</span>
          </div>

          <p
            v-if="eventDetail(event)"
            class="mt-0.5 text-xs text-gray-400"
          >
            {{ eventDetail(event) }}
          </p>
          <p
            v-else-if="event.kind === 'became_unreachable'"
            class="mt-0.5 text-xs text-gray-500"
          >
            Call-graph analysis found no execution path to the vulnerable symbol; with reachability gating on, this stops blocking merges.
          </p>
          <p
            v-else-if="event.kind === 'became_reachable'"
            class="mt-0.5 text-xs text-gray-500"
          >
            Analysis now finds an execution path to the vulnerable symbol — this counts as real risk again.
          </p>
          <p
            v-else-if="event.kind === 'kev_listed'"
            class="mt-0.5 text-xs text-gray-400"
          >
            This catalog documented exploitation in the wild, independently of scans on this repository.
          </p>
          <p
            v-else-if="event.kind === 'kev_delisted'"
            class="mt-0.5 text-xs text-gray-400"
          >
            No longer listed by this catalog. Other catalogs may still list it; removal does not prove exploitation stopped.
          </p>
          <p
            v-else-if="event.kind === 'first_detected'"
            class="mt-0.5 text-xs text-gray-500"
          >
            First observed in this repository. Exploitation catalog entries may predate this scan.
          </p>

          <div
            v-if="labelsOf(event).length > 0"
            class="mt-1 flex flex-wrap gap-1"
          >
            <span
              v-for="label in labelsOf(event)"
              :key="label"
              class="rounded-full bg-surface-overlay px-2 py-0.5 text-[11px] text-gray-400"
            >{{ label }}</span>
          </div>
        </li>
      </ol>

      <p
        v-if="truncated"
        class="mt-3 text-[11px] text-gray-600"
      >
        Older events are not shown — this finding has more history than one page.
      </p>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'

import { Flame, History, Radar, UserCheck } from 'lucide-vue-next'

import { api, type FindingHistoryEvent } from '@/api/client'
import CommitLink from '@/components/CommitLink.vue'
import { formatDateTime, relativeTime } from '@/lib/datetime'
import { kevSourceLabel } from '@/lib/kev'

// The finding's own timeline: scan observations merged with triage decisions.
// It reads the fingerprint-scoped history endpoint, not the org audit log —
// that one is admin-only, this one is open to anyone who can read the finding.
const props = defineProps<{
  provider: string
  slug: string
  repoSlug: string
  fingerprint: string
  // Forge coordinates so commit shas link to the commit.
  repoHtmlUrl?: string
  forgeProvider?: string
}>()

const events = ref<FindingHistoryEvent[]>([])
const truncated = ref(false)
const loading = ref(true)
const error = ref('')

watch(() => [props.provider, props.slug, props.repoSlug, props.fingerprint], load, { immediate: true })

async function load() {
  loading.value = true
  error.value = ''
  try {
    const response = await api.getFindingHistory(props.provider, props.slug, props.repoSlug, props.fingerprint)
    events.value = response.data?.events ?? []
    truncated.value = response.data?.truncated ?? false
  } catch (loadError) {
    events.value = []
    error.value = loadError instanceof Error ? loadError.message : 'Failed to load the history'
  } finally {
    loading.value = false
  }
}

const LABELS: Record<string, string> = {
  first_detected: 'First detected',
  detected: 'Detected',
  resolved: 'No longer detected',
  reintroduced: 'Reintroduced',
  suppressed: 'Suppressed by the scanner',
  became_unreachable: 'Proven unreachable',
  became_reachable: 'Reachable again',
  status_change: 'Status changed',
  reported: 'Reported manually',
  accepted: 'Risk accepted',
  false_positive: 'Marked false positive',
  reopened: 'Reopened',
  revoked: 'Secret revoked & rotated',
  disputed: 'Suppression disputed',
  dispute_withdrawn: 'Dispute withdrawn',
  triaged: 'Triaged',
  kev_listed: 'Known exploitation listed',
  kev_delisted: 'Exploitation listing removed',
}

function eventLabel(event: FindingHistoryEvent): string {
  return LABELS[event.kind] ?? event.kind.replace(/_/g, ' ')
}

function markerClass(event: FindingHistoryEvent): string {
  switch (event.kind) {
    case 'first_detected':
      return 'border-accent/50 bg-accent/15 text-accent'
    case 'detected':
    case 'reintroduced':
    case 'became_reachable':
    case 'kev_listed':
      return 'border-danger/40 bg-danger/15 text-danger'
    case 'resolved':
    case 'revoked':
    case 'became_unreachable':
      return 'border-ok/40 bg-ok/15 text-ok'
    case 'accepted':
    case 'reopened':
      return 'border-amber-500/40 bg-amber-500/15 text-amber-300'
    case 'disputed':
      return 'border-danger/40 bg-danger/15 text-danger'
    case 'false_positive':
    case 'kev_delisted':
      return 'border-surface-border bg-surface-overlay text-gray-400'
    default:
      return 'border-surface-border bg-surface-overlay text-gray-500'
  }
}

// The reason is the part of a decision worth reading; expiry matters because an
// acceptance that lapses turns back into an open finding.
function eventDetail(event: FindingHistoryEvent): string {
  const parts: string[] = []
  const reason = stringOf(event, 'reason')
  const comment = stringOf(event, 'comment')
  const justification = stringOf(event, 'vex_justification')
  const expires = stringOf(event, 'expires_at')
  if (reason) parts.push(reason)
  if (comment) parts.push(comment)
  if (justification) parts.push(`VEX: ${justification.replace(/_/g, ' ')}`)
  if (expires) parts.push(`expires ${formatDateTime(expires)}`)
  return parts.join(' · ')
}

function labelsOf(event: FindingHistoryEvent): string[] {
  const labels = event.detail?.labels
  return Array.isArray(labels) ? labels.filter((label): label is string => typeof label === 'string') : []
}

function stringOf(event: FindingHistoryEvent, key: string): string {
  const value = event.detail?.[key]
  return typeof value === 'string' ? value : ''
}

function shortRef(refName: string): string {
  return refName.replace(/^refs\/(heads|tags)\//, '')
}
</script>

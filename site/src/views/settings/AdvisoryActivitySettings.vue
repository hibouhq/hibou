<template>
  <div class="space-y-5">
    <div>
      <h2 class="text-lg font-semibold text-white">
        Advisory activity
      </h2>
      <p class="mt-1 max-w-[66ch] text-sm leading-relaxed text-gray-400">
        What moved since you last looked. Most of what the feed carries is revision rather than
        arrival, so a quiet stream is normal — the numbers below are how you tell that apart from a
        feed that has stopped.
      </p>
    </div>

    <!-- Health strip. Without it an empty stream and a broken poller look identical. -->
    <div
      v-if="health"
      class="flex flex-wrap items-center divide-x divide-surface-border-subtle overflow-hidden rounded-md border border-surface-border bg-surface-raised"
    >
      <div class="flex items-center gap-2 px-4 py-2.5">
        <span
          class="h-1.5 w-1.5 rounded-full"
          :class="feedFailing ? 'bg-danger' : feedStale ? 'bg-warn' : 'bg-ok'"
        />
        <span
          class="text-xs"
          :class="feedFailing ? 'text-danger' : feedStale ? 'text-warn' : 'text-gray-300'"
        >{{ feedFailing ? 'Feed failing' : feedStale ? 'Feed may be stalled' : 'Feed healthy' }}</span>
      </div>
      <div class="px-4 py-2.5 text-xs text-gray-400">
        Last swept <span class="text-gray-200">{{ relative(health.at) }}</span>
      </div>
      <div class="px-4 py-2.5 text-xs text-gray-400">
        <span class="font-mono text-gray-200">{{ health.seen }}</span> records seen
      </div>
      <div class="px-4 py-2.5 text-xs text-gray-400">
        <span
          class="font-mono"
          :class="health.queued > 0 ? 'text-sev-high' : 'text-gray-200'"
        >{{ health.queued }}</span> queued
      </div>
      <div
        v-if="health.failed > 0"
        class="px-4 py-2.5 text-xs text-warn"
      >
        {{ health.failed }} failed — cursor held so they retry
      </div>
      <!-- How old the corpus is, which the sweep time does not say: a feed that
           swept a minute ago still answers from whatever the seed captured. -->
      <div
        v-if="corpus"
        class="px-4 py-2.5 text-xs text-gray-400"
      >
        Corpus from
        <span
          class="font-mono text-gray-200"
          :title="corpus.commit"
        >{{ corpus.commit.slice(0, 7) }}</span>
        <span
          v-if="corpus.committed_at"
          :class="corpusStale ? 'text-warn' : 'text-gray-400'"
        >, {{ relative(corpus.committed_at) }}</span>
      </div>
    </div>

    <!-- Exploited-catalog mirrors (ADR-032), one card per source: "CISA synced
         an hour ago, EUVD failing since Tuesday" is the actual state, and a
         merged status would hide exactly the half that is broken. These are
         status, not switches — sources are configured in hibou-server.yaml. -->
    <div
      v-if="kev && kev.sources.length > 0"
      class="grid gap-3 sm:grid-cols-2"
    >
      <div
        v-for="source in kev.sources"
        :key="source.source"
        class="rounded-md border bg-surface-raised px-4 py-3"
        :class="kevSyncTone(source) === 'failing' ? 'border-danger/40' : 'border-surface-border'"
      >
        <div class="flex items-center justify-between">
          <span class="text-sm font-medium text-gray-200">{{ kevSourceLabel(source.source) }}</span>
          <span
            class="flex items-center gap-1.5 text-xs"
            :class="kevToneText(source)"
          >
            <span
              class="h-1.5 w-1.5 rounded-full"
              :class="kevToneDot(source)"
            />
            {{ kevToneLabel(source) }}
          </span>
        </div>
        <div class="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-400">
          <span v-if="source.at">
            Synced <span class="text-gray-200">{{ relative(source.at) }}</span>
          </span>
          <span v-if="source.entries">
            <span class="font-mono text-gray-200">{{ source.entries.toLocaleString() }}</span> exploited entries
          </span>
          <span
            v-if="source.catalog_version"
            class="font-mono"
          >{{ source.catalog_version }}</span>
        </div>
        <div
          v-if="source.error"
          class="mt-2 border-t border-danger/20 pt-2"
        >
          <p class="text-xs text-red-200">
            Failing
            <template v-if="source.failing_since">
              since {{ relative(source.failing_since) }}
            </template>
            — the gate keeps blocking on the last good catalog.
          </p>
          <p class="mt-1 break-all font-mono text-[11px] text-red-300/80">
            {{ source.error }}
          </p>
        </div>
      </div>
    </div>

    <!-- Why it is failing. A status colour tells someone to look; only the
         reason tells them where. -->
    <div
      v-if="feedFailing"
      class="rounded-md border border-danger/30 bg-danger/10 px-4 py-3"
    >
      <p class="text-sm text-red-200">
        The feed sweep has been failing
        <template v-if="health?.failing_since">
          since {{ relative(health.failing_since) }}
        </template>.
        Counts below are from the last pass that worked.
      </p>
      <p class="mt-1.5 break-all font-mono text-xs text-red-300/80">
        {{ health?.error }}
      </p>
    </div>

    <div
      v-if="error"
      class="rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
    >
      {{ error }}
    </div>

    <div
      v-if="loading"
      class="py-8 text-sm text-gray-500"
    >
      Loading activity…
    </div>

    <div
      v-else-if="events.length === 0"
      class="rounded-md border border-dashed border-surface-border px-6 py-10 text-center"
    >
      <p class="text-sm text-gray-300">
        Nothing has moved yet.
      </p>
      <p class="mx-auto mt-1.5 max-w-[52ch] text-xs leading-relaxed text-gray-500">
        Activity appears once the feed has swept and something you watch changes upstream. If the
        health strip above is missing, the feed has never completed a sweep — it runs every
        15 minutes and needs outbound access to the CVE list.
      </p>
    </div>

    <div v-else>
      <div
        v-for="(group, day) in grouped"
        :key="day"
      >
        <div class="border-b border-surface-border-subtle pb-2 pt-4 text-[11px] font-semibold uppercase tracking-[0.08em] text-gray-500">
          {{ day }}
        </div>
        <div
          v-for="(event, index) in group"
          :key="`${event.cve_id}-${event.occurred_at}-${index}`"
          class="flex gap-3 border-b border-surface-border-subtle py-3"
        >
          <span
            class="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full"
            :class="tone(event.kind).bg"
          >
            <component
              :is="tone(event.kind).icon"
              class="h-3 w-3"
              :class="tone(event.kind).fg"
            />
          </span>
          <div class="min-w-0 flex-1">
            <div class="flex flex-wrap items-baseline gap-2">
              <span class="text-[13px] text-gray-200">{{ label(event.kind) }}</span>
              <a
                :href="`https://www.cve.org/CVERecord?id=${event.cve_id}`"
                target="_blank"
                rel="noopener"
                class="font-mono text-xs"
              >{{ event.cve_id }}</a>
              <span class="text-[11px] text-gray-600">{{ time(event.occurred_at) }}</span>
              <span
                v-if="!event.external"
                class="rounded-full bg-accent-muted/40 px-1.5 text-[10px] font-medium text-accent"
              >by someone here</span>
            </div>
            <p
              v-if="detailLine(event)"
              class="mt-1 font-mono text-[11px] text-gray-500"
            >
              {{ detailLine(event) }}
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Check, Flame, Plus, RefreshCw, TriangleAlert, X } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'

import { api, type AdvisoryActivityEvent, type CorpusState, type FeedHealth, type KEVHealth, type KEVSourceHealth } from '@/api/client'
import { kevSourceLabel, kevSyncTone } from '@/lib/kev'

const events = ref<AdvisoryActivityEvent[]>([])
const health = ref<FeedHealth | null>(null)
const corpus = ref<CorpusState | null>(null)
const kev = ref<KEVHealth | null>(null)

function kevToneDot(source: KEVSourceHealth): string {
  const tone = kevSyncTone(source, kev.value?.interval_seconds)
  return tone === 'failing' ? 'bg-danger' : tone === 'stale' ? 'bg-warn' : 'bg-ok'
}

function kevToneText(source: KEVSourceHealth): string {
  const tone = kevSyncTone(source, kev.value?.interval_seconds)
  return tone === 'failing' ? 'text-danger' : tone === 'stale' ? 'text-warn' : 'text-ok'
}

function kevToneLabel(source: KEVSourceHealth): string {
  const tone = kevSyncTone(source, kev.value?.interval_seconds)
  return tone === 'failing' ? 'Failing' : tone === 'stale' ? 'Stale' : 'Up to date'
}

/**
 * The corpus is the answer to every watch preview, so its age bounds how much a
 * "no matches" result is worth. A week behind is worth saying out loud.
 */
const corpusStale = computed(() => {
  if (!corpus.value?.committed_at) return false
  return Date.now() - new Date(corpus.value.committed_at).getTime() > 7 * 86_400_000
})
const loading = ref(true)
const error = ref('')

/** Set whenever the most recent sweep failed, whatever the last success said. */
const feedFailing = computed(() => Boolean(health.value?.error))

/** The feed polls every 15 minutes; an hour of silence means something is wrong. */
const feedStale = computed(() => {
  if (!health.value) return false
  return Date.now() - new Date(health.value.at).getTime() > 3_600_000
})

const KINDS: Record<string, string> = {
  published: 'Published upstream',
  cna_revised: 'Vendor revised the record',
  enriched: 'Enriched upstream',
  withdrawn: 'Withdrawn upstream',
  kev_listed: 'Listed as actively exploited (KEV)',
  kev_delisted: 'Removed from exploited catalogs',
  coordinates_upstreamed: 'Upstream published coordinates',
  coordinates_authored: 'Packages mapped here',
  superseded: 'Our mapping superseded',
  diverged: 'Upstream disagrees with our mapping',
  mapping_revoked: 'Mapping revoked',
}

function label(kind: string): string {
  return KINDS[kind] ?? kind
}

function tone(kind: string) {
  switch (kind) {
    case 'withdrawn':
      return { icon: X, bg: 'bg-gray-500/15', fg: 'text-gray-400' }
    case 'cna_revised':
      return { icon: RefreshCw, bg: 'bg-warn/15', fg: 'text-warn' }
    case 'diverged':
      return { icon: TriangleAlert, bg: 'bg-danger/15', fg: 'text-danger' }
    case 'kev_listed':
      return { icon: Flame, bg: 'bg-danger/15', fg: 'text-danger' }
    case 'kev_delisted':
      return { icon: Flame, bg: 'bg-gray-500/15', fg: 'text-gray-400' }
    case 'coordinates_authored':
    case 'coordinates_upstreamed':
    case 'superseded':
      return { icon: Check, bg: 'bg-ok/15', fg: 'text-ok' }
    default:
      return { icon: Plus, bg: 'bg-sev-high/15', fg: 'text-sev-high' }
  }
}

/** A revision that does not say what moved is not actionable. */
function detailLine(event: AdvisoryActivityEvent): string {
  const detail = event.detail
  if (!detail) return ''
  const before = typeof detail.before === 'string' ? detail.before : ''
  const after = typeof detail.after === 'string' ? detail.after : ''
  if (before && after) return `${before}  →  ${after}`
  return ''
}

function time(value: string): string {
  return new Date(value).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

function relative(value: string): string {
  const minutes = Math.floor((Date.now() - new Date(value).getTime()) / 60_000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

const grouped = computed(() => {
  const groups: Record<string, AdvisoryActivityEvent[]> = {}
  for (const event of events.value) {
    const day = new Date(event.occurred_at).toLocaleDateString(undefined, {
      weekday: 'short', day: 'numeric', month: 'short',
    })
    ;(groups[day] ??= []).push(event)
  }
  return groups
})

onMounted(async () => {
  try {
    const response = await api.listAdvisoryEvents()
    events.value = response.data.events ?? []
    health.value = response.data.health
    corpus.value = response.data.corpus
    kev.value = response.data.kev ?? null
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load advisory activity'
  } finally {
    loading.value = false
  }
})
</script>

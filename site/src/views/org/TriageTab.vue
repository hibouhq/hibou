<template>
  <div class="space-y-5">
    <div class="flex items-baseline justify-between gap-4">
      <div>
        <h2 class="text-lg font-semibold text-white">
          Triage queue
        </h2>
        <p class="mt-1 max-w-[64ch] text-sm leading-relaxed text-gray-400">
          Advisories for watched products that arrived without package coordinates, waiting on the
          one thing no upstream record supplied: which packages they actually affect.
        </p>
      </div>
      <span
        v-if="items.length"
        class="shrink-0 text-sm text-gray-400"
      >
        <span class="font-semibold text-sev-high">{{ items.length }}</span> remaining
      </span>
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
      Loading the queue…
    </div>

    <!-- An empty queue is the goal, so it reads as success rather than absence. -->
    <div
      v-else-if="items.length === 0"
      class="rounded-md border border-ok/25 bg-ok/5 px-6 py-10 text-center"
    >
      <Check class="mx-auto h-5 w-5 text-ok" />
      <p class="mt-2 text-sm text-gray-200">
        Nothing waiting.
      </p>
      <p class="mx-auto mt-1 max-w-[48ch] text-xs text-gray-500">
        Every advisory for your watched products has been decided. New ones appear here within
        about fifteen minutes of the CVE Program publishing them.
      </p>
    </div>

    <div
      v-else
      class="flex gap-4"
    >
      <!-- Queue rail -->
      <div class="w-56 shrink-0 overflow-hidden rounded-md border border-surface-border">
        <div
          v-for="(item, index) in items"
          :key="item.id"
          class="cursor-pointer border-l-2 px-3 py-2.5 transition"
          :class="item.id === selectedID
            ? 'border-l-accent bg-accent-muted/20'
            : 'border-l-transparent hover:bg-white/5'"
          @click="select(index)"
        >
          <div class="flex items-center justify-between gap-2">
            <code class="font-mono text-[11px] text-gray-200">{{ item.cve_id }}</code>
            <span
              v-if="item.cvss_score"
              class="shrink-0 rounded-full px-1.5 text-[10px] font-semibold"
              :class="`sev-${item.severity || 'low'}`"
            >{{ item.cvss_score }}</span>
          </div>
          <div class="mt-1 truncate text-[11px] text-gray-500">
            {{ item.label }}
          </div>
        </div>
        <div class="border-t border-surface-border-subtle px-3 py-2 text-[11px] text-gray-600">
          j / k to move
        </div>
      </div>

      <!-- Decision surface -->
      <div class="min-w-0 flex-1">
        <div
          v-if="detailLoading"
          class="py-8 text-sm text-gray-500"
        >
          Loading…
        </div>
        <div
          v-else-if="detail"
          class="space-y-4"
        >
          <div>
            <div class="flex items-start gap-2.5">
              <span
                v-if="detail.severity"
                class="mt-0.5 shrink-0 rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase"
                :class="`sev-${detail.severity}`"
              >{{ detail.severity }}</span>
              <h3 class="text-[15px] font-semibold leading-snug text-white">
                {{ detail.summary || detail.cve_id }}
              </h3>
            </div>
            <div class="mt-2 flex flex-wrap items-center gap-2 text-[11px]">
              <a
                :href="`https://www.cve.org/CVERecord?id=${detail.cve_id}`"
                target="_blank"
                rel="noopener"
                class="font-mono"
              >{{ detail.cve_id }}</a>
              <span class="source-badge source-nvd">CNA {{ detail.assigner || 'unknown' }}</span>
            </div>
          </div>

          <!-- Dates split by whose clock they are on: conflating "published"
               with "we learned of it" hides the lag that matters. -->
          <div class="grid grid-cols-2 gap-3">
            <div class="rounded-md border border-surface-border bg-surface-raised px-3 py-2.5">
              <div class="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">
                Upstream
              </div>
              <div class="mt-2 flex justify-between text-xs">
                <span class="text-gray-500">Published</span>
                <span class="text-gray-300">{{ shortDate(detail.published_at) }}</span>
              </div>
              <div class="mt-1 flex justify-between text-xs">
                <span class="text-gray-500">Revised</span>
                <span class="text-gray-300">{{ shortDate(detail.record_updated_at) }}</span>
              </div>
            </div>
            <div class="rounded-md border border-surface-border bg-surface-raised px-3 py-2.5">
              <div class="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">
                Here
              </div>
              <div class="mt-2 flex justify-between text-xs">
                <span class="text-gray-500">Known here</span>
                <span class="text-gray-300">{{ shortDate(detail.first_seen_at) }}</span>
              </div>
              <div class="mt-1 flex justify-between text-xs">
                <span class="text-gray-500">First detected</span>
                <span class="text-gray-500">needs a decision</span>
              </div>
            </div>
          </div>
          <p
            v-if="detectionLag !== null"
            class="flex items-center gap-1.5 text-[11px] text-warn"
          >
            <Clock class="h-3 w-3" />
            {{ detectionLag }} days between upstream publication and this instance learning of it
          </p>

          <!-- Ranges are derived, never typed. -->
          <div>
            <div class="flex items-center gap-2">
              <span class="text-[10px] font-semibold uppercase tracking-[0.16em] text-gray-500">Affected versions</span>
              <span class="inline-flex items-center gap-1 rounded border border-surface-border px-1.5 text-[10px] text-gray-500">
                <Lock class="h-2.5 w-2.5" /> from the CNA record
              </span>
            </div>
            <div class="mt-2 flex flex-wrap gap-1.5">
              <code
                v-for="(range, i) in detail.ranges"
                :key="i"
                class="rounded border border-surface-border-subtle bg-surface-raised px-2 py-1 font-mono text-[11px] text-gray-300"
              >{{ range.introduced }} → {{ range.last_affected || `< ${range.fixed}` }}</code>
              <span
                v-if="!detail.ranges.length"
                class="text-xs text-gray-500"
              >none published</span>
            </div>
          </div>

          <!-- The only question a person answers. -->
          <div class="overflow-hidden rounded-md border border-surface-border bg-surface-raised">
            <div class="flex items-center justify-between gap-3 border-b border-surface-border-subtle px-4 py-2.5">
              <span class="text-[13px] font-semibold text-gray-200">Which packages does this affect?</span>
              <span
                v-if="detail.existing_mapping.length"
                class="inline-flex items-center gap-1.5 text-[11px] text-ok"
              >
                <Check class="h-3 w-3" /> pre-filled from an earlier decision
              </span>
            </div>

            <label
              v-for="candidate in detail.candidates"
              :key="`${candidate.ecosystem}:${candidate.name}`"
              class="flex cursor-pointer items-center gap-3 border-b border-surface-border-subtle px-4 py-2 transition hover:bg-white/5"
            >
              <input
                type="checkbox"
                :checked="isSelected(candidate)"
                class="h-3.5 w-3.5 accent-accent"
                @change="toggle(candidate)"
              >
              <code class="min-w-0 flex-1 truncate font-mono text-[12px] text-gray-200">{{ candidate.name }}</code>
              <span
                class="eco-badge"
                :class="`eco-${candidate.ecosystem}`"
              >{{ candidate.ecosystem }}</span>
              <span class="shrink-0 text-[11px] text-gray-500">{{ candidate.repo_count }} {{ candidate.repo_count === 1 ? 'repo' : 'repos' }}</span>
            </label>

            <p
              v-if="!detail.candidates.length"
              class="px-4 py-4 text-xs text-gray-500"
            >
              Nothing in this org's inventory resembles that product name — which may itself be the answer.
            </p>

            <div class="flex items-center justify-between gap-3 bg-surface-overlay/50 px-4 py-3">
              <span class="text-[11px] text-gray-500">
                {{ selected.length }} selected · ranges come from the record
              </span>
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  class="rounded-md border border-surface-border px-3 py-1.5 text-xs text-gray-400 transition hover:text-gray-200 disabled:opacity-50"
                  :disabled="deciding"
                  @click="decide(true)"
                >
                  Not affected
                </button>
                <button
                  type="button"
                  class="rounded-md border border-ok/40 bg-ok/15 px-4 py-1.5 text-xs font-semibold text-ok transition hover:bg-ok/25 disabled:cursor-not-allowed disabled:opacity-50"
                  :disabled="deciding || selected.length === 0"
                  @click="decide(false)"
                >
                  {{ deciding ? 'Saving…' : `Map ${selected.length} ${selected.length === 1 ? 'package' : 'packages'}` }}
                </button>
              </div>
            </div>
          </div>

          <p
            v-if="decideError"
            class="text-xs text-red-300"
          >
            {{ decideError }}
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Check, Clock, Lock } from 'lucide-vue-next'
import { computed, onMounted, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import { api, type TriageCandidate, type TriageDetail, type TriageQueueItem, type TriagePackage } from '@/api/client'

const route = useRoute()
const provider = computed(() => String(route.params.provider))
const slug = computed(() => String(route.params.slug))

const items = ref<TriageQueueItem[]>([])
const detail = ref<TriageDetail | null>(null)
const selectedID = ref('')
const selected = ref<TriagePackage[]>([])
const loading = ref(true)
const detailLoading = ref(false)
const deciding = ref(false)
const error = ref('')
const decideError = ref('')

/** How long this instance was unaware of a published advisory. */
const detectionLag = computed(() => {
  if (!detail.value?.published_at) return null
  const days = Math.floor(
    (new Date(detail.value.first_seen_at).getTime() - new Date(detail.value.published_at).getTime()) / 86_400_000,
  )
  return days > 0 ? days : null
})

function shortDate(value: string | null): string {
  if (!value) return '—'
  return new Date(value).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

function isSelected(candidate: TriageCandidate): boolean {
  return selected.value.some(p => p.name === candidate.name && p.ecosystem === candidate.ecosystem)
}

function toggle(candidate: TriageCandidate) {
  if (isSelected(candidate)) {
    selected.value = selected.value.filter(p => !(p.name === candidate.name && p.ecosystem === candidate.ecosystem))
  } else {
    selected.value = [...selected.value, { name: candidate.name, ecosystem: candidate.ecosystem }]
  }
}

function select(index: number) {
  const item = items.value[index]
  if (item) selectedID.value = item.id
}

/** j/k move through the queue: a work list is faster with the hands on keys. */
function onKey(event: KeyboardEvent) {
  if (event.target instanceof HTMLInputElement) return
  const index = items.value.findIndex(i => i.id === selectedID.value)
  if (event.key === 'j') select(Math.min(index + 1, items.value.length - 1))
  if (event.key === 'k') select(Math.max(index - 1, 0))
}

async function loadDetail(id: string) {
  detailLoading.value = true
  decideError.value = ''
  try {
    const response = await api.getTriageItem(provider.value, slug.value, id)
    detail.value = response.data
    // Pre-fill from the stored mapping: the second advisory for a product
    // should arrive already answered.
    selected.value = [...(response.data.existing_mapping ?? [])]
  } catch (e) {
    decideError.value = e instanceof Error ? e.message : 'Failed to load the advisory'
  } finally {
    detailLoading.value = false
  }
}

async function decide(dismiss: boolean) {
  if (!detail.value) return
  deciding.value = true
  decideError.value = ''
  try {
    await api.decideTriageItem(provider.value, slug.value, detail.value.id, {
      packages: dismiss ? undefined : selected.value,
      dismiss,
    })
    items.value = items.value.filter(i => i.id !== detail.value?.id)
    detail.value = null
    if (items.value.length) select(0)
  } catch (e) {
    decideError.value = e instanceof Error ? e.message : 'Failed to record the decision'
  } finally {
    deciding.value = false
  }
}

async function load() {
  loading.value = true
  try {
    const response = await api.listTriageQueue(provider.value, slug.value)
    items.value = response.data ?? []
    if (items.value.length) select(0)
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load the queue'
  } finally {
    loading.value = false
  }
}

watch(selectedID, id => { if (id) void loadDetail(id) })
onMounted(() => { void load(); window.addEventListener('keydown', onKey) })
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))
</script>

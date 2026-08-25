<template>
  <div class="space-y-5">
    <!-- Title -->
    <div class="flex items-start justify-between gap-6">
      <div class="max-w-[62ch]">
        <h2 class="text-lg font-semibold text-white">
          Watches
        </h2>
        <p class="mt-1 text-sm leading-relaxed text-gray-400">
          Products whose advisories sometimes name a version range but no package. Nothing upstream maps
          those to coordinates, so a person does it once — and every later advisory for that product
          resolves on its own.
        </p>
      </div>
      <button
        type="button"
        class="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-accent/40 bg-accent-muted/40 px-3 py-1.5 text-xs font-semibold text-accent transition hover:border-accent/60 hover:bg-accent-muted/60"
        @click="startWatching"
      >
        <Plus class="h-3.5 w-3.5" />
        Watch a product
      </button>
    </div>

    <div
      v-if="loadError"
      class="rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
    >
      {{ loadError }}
    </div>

    <!-- Coverage strip. The uncovered count is deliberately here and not hidden
         in a report: it is the only warning that something is unwatched. -->
    <div class="grid grid-cols-1 gap-3 sm:grid-cols-3">
      <div class="rounded-md border border-surface-border bg-surface-raised px-4 py-3">
        <div class="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">
          Watched
        </div>
        <div class="mt-1.5 text-xl font-semibold leading-none text-white">
          {{ products.length }}
        </div>
        <div class="mt-1.5 text-[11px] text-gray-500">
          across every org on this instance
        </div>
      </div>
      <div
        class="rounded-md border border-surface-border bg-surface-raised px-4 py-3"
        :class="pendingTotal > 0 ? 'border-l-2 border-l-sev-high' : ''"
      >
        <div class="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">
          Awaiting triage
        </div>
        <div
          class="mt-1.5 text-xl font-semibold leading-none"
          :class="pendingTotal > 0 ? 'text-sev-high' : 'text-white'"
        >
          {{ pendingTotal }}
        </div>
        <div class="mt-1.5 text-[11px] text-gray-500">
          advisories needing a decision
        </div>
      </div>
      <div
        class="rounded-md border border-surface-border bg-surface-raised px-4 py-3"
        :class="neverMatched.length > 0 ? 'border-l-2 border-l-warn' : ''"
      >
        <div class="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">
          Never matched
        </div>
        <div
          class="mt-1.5 text-xl font-semibold leading-none"
          :class="neverMatched.length > 0 ? 'text-warn' : 'text-white'"
        >
          {{ neverMatched.length }}
        </div>
        <div class="mt-1.5 text-[11px] text-gray-500">
          {{ neverMatched.length ? 'check the names below' : 'every product is catching advisories' }}
        </div>
      </div>
    </div>

    <!-- The table -->
    <div
      v-if="loading"
      class="py-8 text-sm text-gray-500"
    >
      Loading watched software…
    </div>

    <div
      v-else-if="products.length === 0"
      class="rounded-md border border-dashed border-surface-border px-6 py-10 text-center"
    >
      <p class="text-sm text-gray-300">
        Nothing is watched yet.
      </p>
      <p class="mx-auto mt-1.5 max-w-[52ch] text-xs leading-relaxed text-gray-500">
        Watch a product when its advisories keep arriving without package coordinates — an application
        server or runtime installed into an image, rather than a declared dependency.
      </p>
    </div>

    <div
      v-else
      class="overflow-hidden rounded-md border border-surface-border"
    >
      <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
        <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.16em] text-gray-500">
          <tr>
            <th class="px-3 py-2 font-medium">
              Watching
            </th>
            <th class="px-3 py-2 font-medium">
              Matched on
            </th>
            <th class="px-3 py-2 font-medium">
              Last matched
            </th>
            <th class="px-3 py-2 text-right font-medium">
              Queue
            </th>
            <th class="w-10 px-3 py-2" />
          </tr>
        </thead>
        <tbody class="divide-y divide-surface-border-subtle">
          <tr
            v-for="product in products"
            :key="product.id"
            class="transition hover:bg-white/5"
            :class="isStale(product) ? 'bg-warn/5' : ''"
          >
            <td class="px-3 py-2.5">
              <span class="font-medium text-gray-200">{{ product.label }}</span>
            </td>
            <td class="px-3 py-2.5">
              <div class="flex flex-wrap gap-1">
                <code
                  v-for="key in product.product_keys"
                  :key="key"
                  class="rounded bg-surface-overlay px-1.5 py-0.5 font-mono text-[11px] text-gray-400"
                >{{ key }}</code>
              </div>
            </td>
            <td class="px-3 py-2.5">
              <!-- Silence is ambiguous, so it is never rendered as a blank cell. -->
              <div
                v-if="product.last_matched_at"
                class="flex items-center gap-2 text-xs text-gray-300"
              >
                <span class="h-1.5 w-1.5 rounded-full bg-ok" />
                {{ relativeTime(product.last_matched_at) }}
              </div>
              <div
                v-else
                class="flex items-center gap-2 text-xs"
                :class="isStale(product) ? 'text-warn' : 'text-gray-500'"
              >
                <span
                  class="h-1.5 w-1.5 rounded-full"
                  :class="isStale(product) ? 'bg-warn' : 'bg-gray-600'"
                />
                <span>
                  Never
                  <span
                    v-if="isStale(product)"
                    class="text-warn"
                  >— {{ daysWatched(product) }} days watched, check the name</span>
                </span>
              </div>
            </td>
            <td class="px-3 py-2.5 text-right">
              <span
                v-if="product.pending_triage > 0"
                class="inline-block rounded-full bg-sev-high/15 px-2 py-0.5 text-xs font-semibold text-sev-high"
              >{{ product.pending_triage }}</span>
              <span
                v-else
                class="text-xs text-gray-600"
              >—</span>
            </td>
            <td class="px-3 py-2.5 text-right">
              <button
                type="button"
                class="rounded p-1 text-gray-600 transition hover:bg-white/5 hover:text-danger"
                :aria-label="`Stop watching ${product.label}`"
                :title="`Stop watching ${product.label}`"
                @click="unwatch(product)"
              >
                <Trash2 class="h-3.5 w-3.5" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <p
      v-if="products.length"
      class="px-1 text-[11px] leading-relaxed text-gray-500"
    >
      A product that has never matched may be safe, or may be watched under a name its vendor does not
      publish under. The last-matched column is what separates the two.
    </p>

    <!-- Uncovered components. Not proof of a gap — a component with no findings
         may simply be clean — but it is the only signal that exists before
         somebody watches a product, and it is what turns "you were never told"
         into "you were told and did not act". -->
    <div
      v-if="candidates.length"
      class="pt-2"
    >
      <h3 class="text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-400">
        Nothing covers these
      </h3>
      <p class="mt-1.5 max-w-[70ch] text-xs leading-relaxed text-gray-500">
        Components no advisory source has said anything about. Most are simply clean. The ones worth
        watching are the products whose vendors publish advisories without package coordinates —
        application servers, runtimes, anything installed into an image rather than declared.
      </p>
      <div class="mt-3 flex flex-wrap gap-1.5">
        <button
          v-for="candidate in candidates.slice(0, showAllCandidates ? candidates.length : 12)"
          :key="`${candidate.ecosystem}:${candidate.name}`"
          type="button"
          class="group inline-flex items-center gap-2 rounded-full border border-surface-border bg-surface-raised py-1 pl-3 pr-2 text-[11px] text-gray-300 transition hover:border-accent/40 hover:text-accent"
          :title="`Watch ${candidate.name}`"
          @click="watchCandidate(candidate)"
        >
          <span class="font-mono">{{ candidate.name }}</span>
          <span class="text-gray-600">{{ candidate.repo_count }}</span>
          <Plus class="h-3 w-3 text-gray-600 transition group-hover:text-accent" />
        </button>
        <button
          v-if="!showAllCandidates && candidates.length > 12"
          type="button"
          class="rounded-full px-2 text-[11px] text-gray-500 transition hover:text-gray-300"
          @click="showAllCandidates = true"
        >
          +{{ candidates.length - 12 }} more
        </button>
      </div>
    </div>

    <WatchProductDialog
      v-if="dialogOpen"
      :prefill="prefill"
      @close="dialogOpen = false"
      @created="onCreated"
    />
  </div>
</template>

<script setup lang="ts">
import { Plus, Trash2 } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'

import { api, type WatchCandidate, type WatchedProduct } from '@/api/client'
import WatchProductDialog from '@/components/WatchProductDialog.vue'

const products = ref<WatchedProduct[]>([])
const candidates = ref<WatchCandidate[]>([])
const showAllCandidates = ref(false)
const prefill = ref('')
const loading = ref(true)
const loadError = ref('')
const dialogOpen = ref(false)

const pendingTotal = computed(() => products.value.reduce((sum, p) => sum + p.pending_triage, 0))

/**
 * A product is suspicious once it has been watched long enough that silence is
 * more likely to be a wrong name than a quiet quarter. Two weeks is a judgement
 * call, chosen so a genuinely quiet product is not accused on its first day.
 */
const STALE_AFTER_DAYS = 14
const neverMatched = computed(() => products.value.filter(isStale))

function daysWatched(product: WatchedProduct): number {
  const created = new Date(product.created_at).getTime()
  return Math.floor((Date.now() - created) / 86_400_000)
}

function isStale(product: WatchedProduct): boolean {
  return !product.last_matched_at && daysWatched(product) >= STALE_AFTER_DAYS
}

function relativeTime(value: string): string {
  const days = Math.floor((Date.now() - new Date(value).getTime()) / 86_400_000)
  if (days <= 0) return 'today'
  if (days === 1) return 'yesterday'
  if (days < 30) return `${days} days ago`
  const months = Math.floor(days / 30)
  return months === 1 ? 'a month ago' : `${months} months ago`
}

function startWatching() {
  prefill.value = ''
  dialogOpen.value = true
}

/**
 * Promoting a candidate opens the dialog pre-filled rather than watching it
 * outright: the component's package name is rarely the name its vendor files
 * advisories under, and the preview is what proves which one is right.
 */
function watchCandidate(candidate: WatchCandidate) {
  prefill.value = candidate.name
  dialogOpen.value = true
}

function onCreated(product: WatchedProduct) {
  products.value = [...products.value, product].sort((a, b) => a.label.localeCompare(b.label))
  dialogOpen.value = false
  void loadCandidates()
}

async function loadCandidates() {
  try {
    const response = await api.listWatchCandidates()
    candidates.value = response.data ?? []
  } catch {
    // Advisory information only: failing to load it must not break the page.
    candidates.value = []
  }
}

async function unwatch(product: WatchedProduct) {
  try {
    await api.deleteWatch(product.id)
    products.value = products.value.filter(p => p.id !== product.id)
  } catch (error) {
    loadError.value = error instanceof Error ? error.message : 'Failed to stop watching'
  }
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    const response = await api.listWatches()
    products.value = response.data ?? []
  } catch (error) {
    loadError.value = error instanceof Error ? error.message : 'Failed to load watched software'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void load()
  void loadCandidates()
})
</script>

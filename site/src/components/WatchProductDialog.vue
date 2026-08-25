<template>
  <div
    class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-6 pt-[10vh]"
    @click.self="emit('close')"
  >
    <div class="w-full max-w-lg overflow-hidden rounded-xl border border-surface-border bg-surface-raised shadow-2xl">
      <div class="border-b border-surface-border-subtle px-5 py-4">
        <h3 class="text-[15px] font-semibold text-white">
          Watch a product
        </h3>
        <p class="mt-1 text-xs text-gray-400">
          Match on the name its vendor publishes advisories under — not the package name.
          Applies to every org on this instance.
        </p>
      </div>

      <div class="space-y-4 px-5 py-4">
        <div>
          <label
            for="watch-label"
            class="text-[10px] font-semibold uppercase tracking-[0.16em] text-gray-500"
          >Product</label>
          <input
            id="watch-label"
            v-model="label"
            type="text"
            placeholder="Apache Tomcat"
            class="mt-1.5 w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-100 outline-none transition placeholder:text-gray-600 focus:border-accent/60"
            @input="schedulePreview"
          >
        </div>

        <div>
          <div class="flex items-center justify-between">
            <span class="text-[10px] font-semibold uppercase tracking-[0.16em] text-gray-500">Also known as</span>
            <span class="text-[11px] text-gray-500">vendors name the same product differently</span>
          </div>
          <div class="mt-1.5 flex flex-wrap items-center gap-1.5">
            <span
              v-for="alias in aliases"
              :key="alias"
              class="inline-flex items-center gap-1.5 rounded-full border border-surface-border bg-surface-overlay py-1 pl-2.5 pr-1.5 font-mono text-[11px] text-gray-300"
            >
              {{ alias }}
              <button
                type="button"
                class="text-gray-600 transition hover:text-danger"
                :aria-label="`Remove ${alias}`"
                @click="removeAlias(alias)"
              ><X class="h-3 w-3" /></button>
            </span>
            <input
              v-model="aliasDraft"
              type="text"
              placeholder="+ add a name"
              class="w-32 bg-transparent py-1 text-[11px] text-gray-300 outline-none placeholder:text-gray-600"
              @keydown.enter.prevent="addAlias"
              @keydown.,.prevent="addAlias"
            >
          </div>
        </div>

        <!-- The preview. This is the point of the dialog: a name that catches
             nothing is caught here, in seconds, instead of as an absence of
             alerts nobody notices for months. -->
        <div
          v-if="previewState !== 'idle'"
          class="overflow-hidden rounded-lg border"
          :class="previewTone"
        >
          <div
            class="flex items-center gap-2 px-3 py-2.5 text-xs"
            :class="previewState === 'empty' ? 'text-warn' : 'text-gray-200'"
          >
            <Loader2
              v-if="previewState === 'loading'"
              class="h-3.5 w-3.5 animate-spin text-gray-500"
            />
            <Check
              v-else-if="previewState === 'matches'"
              class="h-3.5 w-3.5 text-ok"
            />
            <TriangleAlert
              v-else
              class="h-3.5 w-3.5"
            />
            <span
              v-if="previewState === 'loading'"
              class="text-gray-500"
            >Checking against known advisories…</span>
            <span v-else-if="previewState === 'matches'">
              <strong class="font-semibold">{{ preview?.total }}</strong>
              {{ preview?.total === 1 ? 'advisory' : 'advisories' }} would have matched
            </span>
            <span v-else>Nothing matched — this name may not be the one its vendor files under</span>
          </div>

          <ul
            v-if="previewState === 'matches' && preview"
            class="divide-y divide-surface-border-subtle border-t border-surface-border-subtle"
          >
            <li
              v-for="match in preview.matches.slice(0, 3)"
              :key="match.cve_id"
              class="flex items-center gap-2.5 px-3 py-1.5"
            >
              <code class="w-[112px] shrink-0 font-mono text-[11px] text-gray-300">{{ match.cve_id }}</code>
              <span
                v-if="match.cvss_score"
                class="shrink-0 rounded-full px-1.5 text-[10px] font-semibold"
                :class="`sev-${match.severity || 'low'}`"
              >{{ match.cvss_score }}</span>
              <span class="truncate text-[11px] text-gray-500">{{ match.summary }}</span>
            </li>
          </ul>
        </div>

        <p
          v-if="submitError"
          class="text-xs text-red-300"
        >
          {{ submitError }}
        </p>
      </div>

      <div class="flex items-center justify-end gap-2 border-t border-surface-border-subtle bg-surface-overlay/50 px-5 py-3">
        <button
          type="button"
          class="rounded-lg px-3 py-1.5 text-xs text-gray-400 transition hover:text-gray-200"
          @click="emit('close')"
        >
          Cancel
        </button>
        <button
          type="button"
          class="rounded-lg border border-accent/40 bg-accent-muted/40 px-4 py-1.5 text-xs font-semibold text-accent transition hover:bg-accent-muted/60 disabled:cursor-not-allowed disabled:opacity-50"
          :disabled="!label.trim() || submitting"
          @click="submit"
        >
          {{ submitting ? 'Watching…' : 'Watch it' }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Check, Loader2, TriangleAlert, X } from 'lucide-vue-next'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

import { api, type WatchedProduct, type WatchPreview } from '@/api/client'

const props = withDefaults(defineProps<{ prefill?: string }>(), { prefill: '' })
const emit = defineEmits<{ close: []; created: [WatchedProduct] }>()

const label = ref(props.prefill)
const aliases = ref<string[]>([])
const aliasDraft = ref('')
const preview = ref<WatchPreview | null>(null)
const previewState = ref<'idle' | 'loading' | 'matches' | 'empty'>('idle')
const submitting = ref(false)
const submitError = ref('')

const previewTone = computed(() => {
  if (previewState.value === 'empty') return 'border-warn/30 bg-warn/5'
  if (previewState.value === 'matches') return 'border-ok/25 bg-ok/5'
  return 'border-surface-border bg-surface-overlay/40'
})

function addAlias() {
  const value = aliasDraft.value.trim()
  if (value && !aliases.value.includes(value)) {
    aliases.value.push(value)
    schedulePreview()
  }
  aliasDraft.value = ''
}

function removeAlias(alias: string) {
  aliases.value = aliases.value.filter(a => a !== alias)
  schedulePreview()
}

let previewTimer: ReturnType<typeof setTimeout> | undefined

/** Debounced so typing a name does not fire a query per keystroke. */
function schedulePreview() {
  clearTimeout(previewTimer)
  const keys = [label.value, ...aliases.value].map(k => k.trim()).filter(Boolean)
  if (keys.length === 0) {
    previewState.value = 'idle'
    return
  }
  previewState.value = 'loading'
  previewTimer = setTimeout(() => void runPreview(keys), 350)
}

async function runPreview(keys: string[]) {
  try {
    const response = await api.listAdvisories(keys)
    preview.value = response.data
    previewState.value = (response.data?.total ?? 0) > 0 ? 'matches' : 'empty'
  } catch {
    // A failed preview must not block the decision — it is an aid, not a gate.
    previewState.value = 'idle'
  }
}

async function submit() {
  submitting.value = true
  submitError.value = ''
  try {
    const response = await api.createWatch({
      label: label.value.trim(),
      product_keys: aliases.value,
    })
    emit('created', response.data)
  } catch (error) {
    submitError.value = error instanceof Error ? error.message : 'Failed to watch product'
  } finally {
    submitting.value = false
  }
}

// A promoted candidate arrives with a name already in hand, so check it
// immediately: the answer is the reason the dialog exists.
onMounted(() => { if (label.value) schedulePreview() })
onBeforeUnmount(() => clearTimeout(previewTimer))
</script>

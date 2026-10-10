<template>
  <Teleport to="body">
    <Transition
      enter-active-class="transition-opacity duration-100"
      enter-from-class="opacity-0"
      leave-active-class="transition-opacity duration-100"
      leave-to-class="opacity-0"
    >
      <div
        v-if="open"
        class="fixed inset-0 z-[80] flex items-start justify-center bg-black/60 px-4 pt-[14vh] backdrop-blur-sm"
        @click.self="emit('close')"
      >
        <div class="w-full max-w-xl overflow-hidden rounded-2xl border border-surface-border bg-surface-raised shadow-2xl">
          <div class="flex items-center gap-3 border-b border-surface-border-subtle px-4 py-3">
            <Search class="h-4 w-4 shrink-0 text-gray-500" />
            <input
              ref="inputRef"
              v-model="draft"
              type="text"
              placeholder="Search vulnerabilities, components, clients…"
              class="min-w-0 flex-1 bg-transparent text-sm text-gray-100 placeholder:text-gray-500 focus:outline-none"
              @keydown.down.prevent="move(1)"
              @keydown.up.prevent="move(-1)"
              @keydown.enter.prevent="onEnter"
              @keydown.esc.prevent="emit('close')"
            >
            <span class="shrink-0 rounded border border-surface-border-subtle px-1.5 py-0.5 text-[10px] text-gray-500">esc</span>
          </div>

          <div class="max-h-[52vh] overflow-y-auto py-1">
            <p
              v-if="entity"
              class="px-4 pb-1 pt-2 text-[11px] text-gray-500"
            >
              Looks like a {{ entity.label }} — press Enter to search for it.
            </p>

            <button
              v-for="(item, index) in items"
              :key="`${item.type}-${item.id}`"
              type="button"
              class="flex w-full items-center gap-3 px-4 py-2 text-left transition"
              :class="index === highlight ? 'bg-accent-muted' : 'hover:bg-surface-overlay'"
              @mouseenter="highlight = index"
              @click="activate(item)"
            >
              <MalwareIcon
                v-if="item.metadata?.is_malware === true"
                size="sm"
              />
              <component
                :is="typeIcon(item.type)"
                v-else
                class="h-4 w-4 shrink-0 text-gray-500"
              />
              <span class="min-w-0 flex-1">
                <span class="block truncate text-sm text-gray-100">{{ item.title }}</span>
                <span class="block truncate text-xs text-gray-500">{{ item.subtitle }}</span>
              </span>
              <span
                v-if="item.severity"
                class="shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide"
                :class="severityClass(item.severity)"
              >{{ item.severity }}</span>
            </button>

            <p
              v-if="!items.length && draft.trim().length >= 2 && !loading"
              class="px-4 py-6 text-center text-sm text-gray-500"
            >
              No matches. Press Enter to search everything.
            </p>
            <p
              v-else-if="draft.trim().length < 2"
              class="px-4 py-6 text-center text-sm text-gray-500"
            >
              Type at least two characters.
            </p>
          </div>

          <div class="flex items-center justify-between border-t border-surface-border-subtle px-4 py-2 text-[11px] text-gray-500">
            <span class="flex items-center gap-1.5">
              <kbd class="rounded border border-surface-border-subtle px-1">↑</kbd>
              <kbd class="rounded border border-surface-border-subtle px-1">↓</kbd>
              to navigate
            </span>
            <button
              type="button"
              class="flex items-center gap-1.5 text-gray-400 transition hover:text-white"
              @click="fullSearch"
            >
              <CornerDownLeft class="h-3 w-3" />
              Search everything for “{{ draft.trim() || '…' }}”
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { Bug, CornerDownLeft, Package, Search, Users } from 'lucide-vue-next'

import { api, type SearchResult } from '@/api/client'
import MalwareIcon from '@/components/finding/MalwareIcon.vue'

const props = defineProps<{ open: boolean; provider: string; slug: string }>()
const emit = defineEmits<{ (e: 'close'): void }>()

const router = useRouter()
const inputRef = ref<HTMLInputElement | null>(null)
const draft = ref('')
const loading = ref(false)
const items = ref<SearchResult[]>([])
const highlight = ref(-1)
let debounce: ReturnType<typeof setTimeout> | undefined
let requestSeq = 0

interface DetectedEntity {
  label: string
}

const ADVISORY_PATTERNS: { re: RegExp; label: string }[] = [
  { re: /\bCVE-\d{4}-\d{4,}\b/i, label: 'CVE' },
  { re: /\bGHSA(?:-[0-9a-z]{4}){3}\b/i, label: 'GHSA advisory' },
  { re: /\bPYSEC-\d{4}-\d+\b/i, label: 'PySec advisory' },
  { re: /\bGO-\d{4}-\d+\b/i, label: 'Go advisory' },
  { re: /\bRUSTSEC-\d{4}-\d{4}\b/i, label: 'RustSec advisory' },
  { re: /\bGSD-\d{4}-\d+\b/i, label: 'GSD advisory' },
  { re: /\bOSV-\d{4}-\d+\b/i, label: 'OSV advisory' },
  { re: /\bSNYK-[A-Z0-9]+-\d+\b/i, label: 'Snyk advisory' },
  { re: /\b(?:DSA|DLA)-\d+(?:-\d+)?\b/i, label: 'Debian advisory' },
  { re: /\bUSN-\d+(?:-\d+)?\b/i, label: 'Ubuntu advisory' },
  { re: /\bRH(?:SA|BA|EA)-\d{4}:\d+\b/i, label: 'Red Hat advisory' },
  { re: /\bELSA-\d{4}-\d+\b/i, label: 'Oracle advisory' },
  { re: /\bALAS2?-\d{4}-\d+\b/i, label: 'Amazon Linux advisory' },
  { re: /\bALSA-\d{4}:\d+\b/i, label: 'AlmaLinux advisory' },
  { re: /\bCGA(?:-[0-9a-z]{4}){3}\b/i, label: 'Chainguard advisory' },
  { re: /\bMAL-\d{4}-\d+\b/i, label: 'malware advisory' },
  { re: /\bCWE-\d+\b/i, label: 'CWE weakness' },
]

const entity = computed<DetectedEntity | null>(() => {
  const value = draft.value.trim()
  for (const pattern of ADVISORY_PATTERNS) {
    if (pattern.re.test(value)) return { label: pattern.label }
  }
  if (/\bpkg:[a-z.+-]+\/\S+/i.test(value)) return { label: 'package' }
  if (/^[0-9a-f]{7,40}$/i.test(value)) return { label: 'commit' }
  return null
})

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen) {
      draft.value = ''
      items.value = []
      highlight.value = -1
      void nextTick(() => inputRef.value?.focus())
    }
  },
)

watch(draft, () => {
  if (debounce) clearTimeout(debounce)
  highlight.value = -1
  const parsed = parseQuery(draft.value)
  if (parsed.q.trim().length < 2 && !parsed.severity && !parsed.type) {
    items.value = []
    return
  }
  debounce = setTimeout(() => void runSearch(parsed), 200)
})

interface ParsedQuery {
  q: string
  severity?: string
  type?: string
}

function parseQuery(raw: string): ParsedQuery {
  const out: ParsedQuery = { q: '' }
  const terms: string[] = []
  for (const token of raw.trim().split(/\s+/).filter(Boolean)) {
    const match = token.match(/^([a-z]+):(.+)$/i)
    if (match) {
      const key = match[1].toLowerCase()
      if (key === 'severity') { out.severity = match[2]; continue }
      if (key === 'type') { out.type = match[2]; continue }
      terms.push(match[2])
      continue
    }
    terms.push(token)
  }
  out.q = terms.join(' ')
  return out
}

async function runSearch(parsed: ParsedQuery): Promise<void> {
  if (!props.provider || !props.slug) return
  const seq = ++requestSeq
  loading.value = true
  try {
    const response = await api.search(props.provider, props.slug, {
      q: parsed.q,
      type: parsed.type,
      severity: parsed.severity,
      per_page: 6,
    })
    if (seq !== requestSeq) return
    items.value = response.data.results
  } catch {
    if (seq === requestSeq) items.value = []
  } finally {
    if (seq === requestSeq) loading.value = false
  }
}

function move(delta: number): void {
  if (!items.value.length) return
  const next = highlight.value + delta
  if (next < 0) highlight.value = -1
  else if (next >= items.value.length) highlight.value = items.value.length - 1
  else highlight.value = next
}

function onEnter(): void {
  if (highlight.value >= 0 && items.value[highlight.value]) {
    activate(items.value[highlight.value])
    return
  }
  fullSearch()
}

function activate(item: SearchResult): void {
  navigate(item.title, item.type)
}

function fullSearch(): void {
  const query = draft.value.trim()
  if (!query) return
  navigate(query)
}

function navigate(q: string, type?: string): void {
  const query: Record<string, string> = { q }
  if (type) query.type = type
  void router.push({ name: 'search', params: { provider: props.provider, slug: props.slug }, query })
  emit('close')
}

function typeIcon(type: SearchResult['type']) {
  if (type === 'component') return Package
  if (type === 'client') return Users
  return Bug
}

function severityClass(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical': return 'bg-red-500/15 text-red-300'
    case 'high': return 'bg-orange-500/15 text-orange-300'
    case 'medium': return 'bg-amber-500/15 text-amber-300'
    case 'low': return 'bg-blue-500/15 text-blue-300'
    default: return 'bg-surface-overlay text-gray-400'
  }
}
</script>

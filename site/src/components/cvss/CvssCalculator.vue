<template>
  <div class="space-y-4">
    <!-- Score and vector: the answer first, kept in view while choosing. -->
    <div
      class="sticky z-10 -mx-1 px-1 pb-1"
      :class="inDialog ? 'top-0 bg-surface-raised' : 'top-[calc(3.5rem+var(--app-banner-height,0px))] bg-surface'"
    >
      <div class="flex flex-wrap items-start gap-4 rounded-xl border border-surface-border-subtle bg-surface-overlay/40 p-4">
        <div class="min-w-[7rem]">
          <p
            class="text-3xl font-semibold tabular-nums"
            :class="score === null ? 'text-gray-600' : bandTextClass(score)"
          >
            {{ score === null ? '–' : score.toFixed(1) }}
          </p>
          <p class="text-xs text-gray-400">
            <template v-if="score !== null">
              CVSS {{ version }} · {{ severityOf(score) }}
            </template>
            <template v-else-if="missing.length">
              {{ missing.length }} required {{ missing.length === 1 ? 'metric' : 'metrics' }} left
            </template>
            <template v-else>
              No vector
            </template>
          </p>
        </div>
        <div class="min-w-0 flex-1 space-y-2">
          <div
            v-if="editable && allowedVersions.length > 1"
            class="flex flex-wrap items-center gap-1.5"
            role="radiogroup"
            aria-label="CVSS version"
          >
            <span class="text-[11px] uppercase tracking-[0.14em] text-gray-500">Version</span>
            <button
              v-for="candidate in allowedVersions"
              :key="candidate"
              type="button"
              role="radio"
              :aria-checked="candidate === version"
              class="rounded-md border px-2 py-0.5 text-xs transition"
              :class="candidate === version ? 'border-accent/60 bg-accent/15 text-accent' : 'border-surface-border text-gray-400 hover:text-white'"
              @click="switchVersion(candidate)"
            >
              {{ candidate }}
            </button>
          </div>
          <div class="relative flex items-center">
            <input
              v-if="editable"
              v-model="vectorDraft"
              type="text"
              spellcheck="false"
              class="min-w-0 flex-1 rounded-md border border-surface-border bg-surface py-1 pl-2 pr-8 font-mono text-xs text-gray-200 focus:border-accent focus:outline-none"
              :aria-label="'CVSS vector'"
              placeholder="Paste a vector, or choose each metric below"
              @input="applyDraft"
            >
            <code
              v-else
              class="min-w-0 flex-1 break-all py-1 pr-8 font-mono text-xs text-gray-300"
            >{{ vectorText || modelValue }}</code>
            <button
              type="button"
              class="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1 transition disabled:opacity-30"
              :class="copied ? 'text-emerald-400' : 'text-gray-500 enabled:hover:bg-surface-overlay enabled:hover:text-white'"
              :disabled="!vectorText"
              :aria-label="copied ? 'Copied' : 'Copy vector'"
              :title="vectorText ? (copied ? 'Copied' : 'Copy vector') : 'Choose every required metric first'"
              @click="copy"
            >
              <Check
                v-if="copied"
                class="h-3.5 w-3.5"
              />
              <Copy
                v-else
                class="h-3.5 w-3.5"
              />
            </button>
          </div>
          <p
            v-if="error"
            class="text-xs text-danger"
          >
            {{ error }}
          </p>
          <p
            v-if="version !== '4.0' && editable && allowedVersions.includes('4.0')"
            class="text-[11px] text-gray-500"
          >
            New findings are scored in CVSS 4.0.
          </p>
        </div>
      </div>
    </div>

    <!-- One section per metric group; optional groups fold away. -->
    <section
      v-for="group in groups"
      :key="group.id"
      class="rounded-xl border border-surface-border-subtle"
    >
      <button
        type="button"
        class="flex w-full items-baseline gap-2 px-4 py-2.5 text-left"
        :aria-expanded="isOpen(group)"
        @click="toggle(group)"
      >
        <span class="text-xs font-semibold uppercase tracking-[0.16em] text-gray-300">{{ group.name }}</span>
        <span class="min-w-0 flex-1 truncate text-[11px] text-gray-500">{{ group.description }}</span>
        <span
          v-if="group.optional"
          class="text-[11px] text-gray-500"
        >{{ definedCount(group) }} set · {{ isOpen(group) ? 'hide' : 'show' }}</span>
      </button>
      <div
        v-if="isOpen(group)"
        class="divide-y divide-surface-border-subtle border-t border-surface-border-subtle"
      >
        <div
          v-for="metric in group.metrics"
          :key="metric.key"
          class="grid gap-2 px-4 py-3 md:grid-cols-[14rem_minmax(0,1fr)]"
        >
          <div>
            <p class="text-sm text-gray-200">
              {{ metric.name }} <span class="font-mono text-[11px] text-gray-500">{{ metric.key }}</span>
              <span
                v-if="metric.required && editable && !selected[metric.key]"
                class="ml-1 text-[11px] text-amber-300"
              >required</span>
            </p>
            <p class="text-[11px] text-gray-500">
              {{ metric.question }}
            </p>
          </div>
          <div>
            <div
              class="flex flex-wrap gap-1.5"
              role="radiogroup"
              :aria-label="metric.name"
            >
              <button
                v-for="value in metric.values"
                :key="value.code"
                type="button"
                role="radio"
                :aria-checked="currentValue(metric.key) === value.code"
                :disabled="!editable"
                class="rounded-md border px-2.5 py-1 text-xs transition"
                :class="valueClass(metric.key, value.code)"
                @click="choose(metric.key, value.code)"
                @mouseenter="hovered = `${metric.key}:${value.code}`"
                @mouseleave="hovered = ''"
                @focus="hovered = `${metric.key}:${value.code}`"
                @blur="hovered = ''"
              >
                {{ value.label }}
              </button>
            </div>
            <p class="mt-1.5 min-h-[1rem] text-[11px] text-gray-400">
              {{ explanation(metric) }}
            </p>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { Check, Copy } from 'lucide-vue-next'
import { computed, reactive, ref, watch } from 'vue'

import { CVSS_GROUPS, type CvssGroup, type CvssMetric, type CvssVersion, metricIndex } from '@/lib/cvss/definitions'
import { formatVector, parseVector, scoreVector, severityOf } from '@/lib/cvss/score'
import { bandTextClass } from '@/lib/riskMetrics'

// The one CVSS calculator: explains any vector (view) and builds one (edit),
// for the Tools page, the drawer and finding creation alike.
const props = withDefaults(defineProps<{
  modelValue?: string
  editable?: boolean
  /** Versions a user may build in edit mode. New findings: 4.0 only. */
  allowedVersions?: CvssVersion[]
  /** Rendered in a dialog: the score card sticks to the dialog's top. */
  inDialog?: boolean
}>(), {
  modelValue: '',
  editable: false,
  allowedVersions: () => ['4.0'],
  inDialog: false,
})

const emit = defineEmits<{
  (event: 'update:modelValue', vector: string): void
  /** Fires on every change: the vector when complete, '' otherwise. */
  (event: 'change', state: { vector: string; score: number | null; complete: boolean }): void
}>()

const version = ref<CvssVersion>('4.0')
const selected = reactive<Record<string, string>>({})
const error = ref('')
const hovered = ref('')
const vectorDraft = ref('')
const copied = ref(false)
const openGroups = reactive<Record<string, boolean>>({})
// Choices per version, so switching 3.1 → 4.0 → 3.1 gets the 3.1 ones back.
const remembered = new Map<CvssVersion, Record<string, string>>()

const groups = computed(() => CVSS_GROUPS[version.value])
const index = computed(() => metricIndex(version.value))
const missing = computed(() => [...index.value.values()].filter(metric => metric.required && !selected[metric.key]))
const vectorText = computed(() => (missing.value.length ? '' : formatVector(version.value, new Map(Object.entries(selected)))))
// What the vector box shows: the vector so far, complete or not.
const partialText = computed(() => (Object.keys(selected).length ? formatVector(version.value, new Map(Object.entries(selected))) : ''))
const score = computed<number | null>(() => {
  if (!vectorText.value) return null
  const parsed = parseVector(vectorText.value)
  return parsed.ok ? scoreVector(parsed.vector) : null
})

function load(raw: string, fromUser: boolean): boolean {
  if (!raw.trim()) {
    for (const key of Object.keys(selected)) delete selected[key]
    error.value = ''
    return true
  }
  const parsed = parseVector(raw)
  if (!parsed.ok) {
    error.value = parsed.error
    return false
  }
  if (props.editable && fromUser && !props.allowedVersions.includes(parsed.vector.version)) {
    error.value = `CVSS ${parsed.vector.version} vectors can be read here, but new scores use ${props.allowedVersions.join(' or ')}.`
    return false
  }
  error.value = ''
  version.value = parsed.vector.version
  for (const key of Object.keys(selected)) delete selected[key]
  for (const [key, value] of parsed.vector.metrics) selected[key] = value
  return true
}

watch(() => props.modelValue, (value) => {
  if (value === vectorText.value) return
  load(value, false)
  vectorDraft.value = value
}, { immediate: true })

watch(partialText, (text) => {
  vectorDraft.value = text
})

watch([vectorText, score], () => {
  emit('change', { vector: vectorText.value, score: score.value, complete: Boolean(vectorText.value) })
  if (props.editable && vectorText.value && vectorText.value !== props.modelValue) emit('update:modelValue', vectorText.value)
})

function applyDraft() {
  load(vectorDraft.value, true)
}

function switchVersion(next: CvssVersion) {
  if (next === version.value) return
  remembered.set(version.value, { ...selected })
  version.value = next
  for (const key of Object.keys(selected)) delete selected[key]
  Object.assign(selected, remembered.get(next) ?? {})
  vectorDraft.value = partialText.value
  error.value = ''
}

function choose(key: string, code: string) {
  if (!props.editable) return
  selected[key] = code
}

function currentValue(key: string): string {
  return selected[key] ?? (key.length > 0 && !index.value.get(key)?.required ? (index.value.get(key)?.values[0]?.code ?? '') : '')
}

function valueClass(key: string, code: string): string {
  const active = currentValue(key) === code
  if (active) return 'border-accent/70 bg-accent/15 text-white'
  return props.editable ? 'border-surface-border text-gray-400 hover:border-gray-500 hover:text-white' : 'border-surface-border/60 text-gray-600'
}

function explanation(metric: CvssMetric): string {
  const [hoverKey, hoverCode] = hovered.value.split(':')
  const code = hoverKey === metric.key ? hoverCode : currentValue(metric.key)
  const value = metric.values.find(candidate => candidate.code === code)
  return value ? `${value.label}: ${value.description}` : ''
}

function definedCount(group: CvssGroup): number {
  return group.metrics.filter(metric => selected[metric.key] && selected[metric.key] !== 'X' && selected[metric.key] !== 'ND').length
}

function isOpen(group: CvssGroup): boolean {
  return openGroups[group.id] ?? (!group.optional || definedCount(group) > 0)
}

function toggle(group: CvssGroup) {
  openGroups[group.id] = !isOpen(group)
}

async function copy() {
  try {
    await navigator.clipboard.writeText(vectorText.value)
    copied.value = true
    setTimeout(() => { copied.value = false }, 1500)
  } catch {
    // Clipboard unavailable (insecure context): the vector stays selectable.
  }
}
</script>

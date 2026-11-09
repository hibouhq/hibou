<template>
  <div
    v-if="cards.length > 0"
    class="grid gap-2 [grid-template-columns:repeat(auto-fill,minmax(14rem,1fr))]"
    aria-label="Clocks"
  >
    <div
      v-for="card in cards"
      :key="card.step"
      class="rounded-lg border px-3 py-2"
      :class="cardClass(card)"
    >
      <div class="flex items-baseline justify-between gap-2">
        <span class="truncate text-[11px] font-medium uppercase tracking-[0.12em] text-gray-400">{{ card.label }}</span>
        <span
          class="shrink-0 text-[11px] text-gray-500"
          :title="card.primary ? primaryTitle(card) : INTERNAL_TITLE"
        >{{ card.window ? `${card.window} · ` : '' }}{{ card.primary ? shortRegime(card.primary.regime) : 'own target' }}</span>
      </div>

      <div class="mt-1 text-lg leading-tight">
        <span
          v-if="card.met"
          class="inline-flex items-center gap-1.5 text-green-300"
        >
          <Check class="h-4 w-4" />
          <span class="text-sm">met <DateTime :value="card.met" /></span>
        </span>
        <CountdownText
          v-else
          :at="card.due"
        />
      </div>

      <div
        v-if="!card.met && card.progress !== null"
        class="mt-1.5 h-1 overflow-hidden rounded-full bg-surface-overlay"
        :title="progressTitle(card)"
      >
        <div
          class="h-full rounded-full"
          :class="barClass(card.progress)"
          :style="{ width: `${Math.max(2, Math.round(card.progress * 100))}%` }"
        />
      </div>

      <div
        v-if="card.reference || card.others.length > 0 || (card.primary && card.internal)"
        class="mt-1.5 space-y-0.5 text-[11px] text-gray-500"
      >
        <div
          v-if="card.reference"
          class="truncate font-mono text-gray-400"
          :title="card.reference"
        >
          {{ card.reference }}
        </div>
        <div
          v-if="card.primary && card.internal && !card.met"
          class="flex items-center gap-1"
          :title="INTERNAL_TITLE"
        >
          <span class="shrink-0 whitespace-nowrap">Own target{{ card.internalWindow ? ` (${card.internalWindow})` : '' }}:</span>
          <span
            v-if="nullTime(card.internal.met_at)"
            class="text-green-300"
          >met</span>
          <CountdownText
            v-else
            :at="card.internal.due_at"
          />
        </div>
        <div
          v-for="other in card.others"
          :key="other.regime"
          class="flex items-center gap-1"
        >
          <span
            class="shrink-0 whitespace-nowrap"
            :title="regimeLabel(other.regime)"
          >{{ shortRegime(other.regime) }}{{ stepWindow(other) ? ` (${stepWindow(other)})` : '' }}:</span>
          <span
            v-if="nullTime(other.met_at)"
            class="text-green-300"
          >met</span>
          <CountdownText
            v-else
            :at="other.due_at"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Check } from 'lucide-vue-next'
import { computed } from 'vue'

import { nullTime, type IncidentDeadline, type Regime } from '@/api/incidents'
import DateTime from '@/components/DateTime.vue'
import CountdownText from '@/components/incidents/CountdownText.vue'
import { useNow } from '@/composables/useNow'
import { clockRows, elapsedText, humanize, windowLabel } from '@/lib/incidentView'

// The clocks as one compact strip: a card per step, its earliest regulatory
// deadline as a live countdown with the window it comes from ("24 h · CRA
// Art. 14"), a bar for the share of that window already used since T0, and
// the internal target and other regimes beneath, each with its own window.
const props = defineProps<{
  deadlines: IncidentDeadline[]
  regimes: Regime[]
  awareAt: string | null
}>()

interface ClockCard {
  step: string
  label: string
  primary: IncidentDeadline | null
  internal: IncidentDeadline | null
  others: IncidentDeadline[]
  due: string
  met: string | null
  reference: string
  progress: number | null
  window: string
  internalWindow: string
}

const INTERNAL_TITLE = 'Your organisation\'s own target, set in the incident settings. Not a legal deadline.'

const now = useNow()

const cards = computed<ClockCard[]>(() => clockRows(props.deadlines).map((row) => {
  const primary = row.regulatory[0] ?? null
  const shown = primary ?? row.internal
  const due = shown?.due_at ?? ''
  return {
    step: row.step,
    label: stepLabel(row.step),
    primary,
    internal: row.internal,
    others: row.regulatory.slice(1),
    due,
    met: shown ? nullTime(shown.met_at) : null,
    reference: shown?.reference ?? '',
    progress: progress(due),
    window: shown ? stepWindow(shown) : '',
    internalWindow: row.internal ? stepWindow(row.internal) : '',
  }
}))

function progress(due: string): number | null {
  if (!props.awareAt || !due) return null
  const start = new Date(props.awareAt).getTime()
  const end = new Date(due).getTime()
  if (!(end > start)) return null
  return Math.min(1, Math.max(0, (now.value - start) / (end - start)))
}

function progressTitle(card: ClockCard) {
  const used = props.awareAt ? elapsedText(props.awareAt, card.due, now.value) : ''
  return card.window
    ? `${used} of the ${card.window} since T0 used`
    : `${Math.round(card.progress! * 100)}% of the time since T0 used`
}

function primaryTitle(card: ClockCard) {
  const spec = findStep(card.primary!)
  const regime = regimeLabel(card.primary!.regime)
  if (!spec) return regime
  const anchor = spec.anchor === 'aware' ? 'T0, the moment of awareness' : humanize(spec.anchor).toLowerCase()
  return `${regime}: due ${windowLabel(spec.after)} after ${anchor}${spec.recipient ? `, to the ${spec.recipient}` : ''}`
}

function stepLabel(step: string) {
  for (const regime of props.regimes) {
    const spec = regime.steps.find(entry => entry.step === step)
    if (spec) return spec.label
  }
  return humanize(step)
}

function findStep(deadline: IncidentDeadline) {
  return props.regimes.find(regime => regime.name === deadline.regime)?.steps.find(entry => entry.step === deadline.step)
}

// The window a deadline comes from: the regime's step duration ("24 h",
// "1 month"); for an internal target, which has no step spec, the distance
// from T0.
function stepWindow(deadline: IncidentDeadline): string {
  const spec = findStep(deadline)
  if (spec) return windowLabel(spec.after)
  if (!props.awareAt) return ''
  const hours = Math.round((new Date(deadline.due_at).getTime() - new Date(props.awareAt).getTime()) / 3600000)
  return hours > 0 ? windowLabel(`${hours}h`) : ''
}

function regimeLabel(name: string) {
  return props.regimes.find(regime => regime.name === name)?.label ?? name
}

// "cra-article-14" → "CRA Art. 14"; others as their label.
function shortRegime(name: string) {
  const match = /^([a-z0-9]+)-article-(\d+)$/i.exec(name)
  if (match) return `${match[1].toUpperCase()} Art. ${match[2]}`
  return regimeLabel(name)
}

function cardClass(card: ClockCard) {
  if (card.met) return 'border-surface-border-subtle bg-surface-raised/30'
  if (card.due && new Date(card.due).getTime() < now.value) return 'border-danger/50 bg-danger/5'
  if (card.progress !== null && card.progress >= 0.75) return 'border-warn/40 bg-warn/5'
  return 'border-surface-border bg-surface-raised/40'
}

function barClass(value: number) {
  if (value >= 1) return 'bg-danger'
  if (value >= 0.75) return 'bg-warn'
  return 'bg-accent'
}
</script>

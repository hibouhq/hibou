<template>
  <div>
    <p
      v-if="modelValue.length === 0"
      class="text-xs text-gray-500"
    >
      {{ emptyText }}
    </p>
    <div
      v-else
      class="overflow-x-auto rounded-md border border-surface-border"
    >
      <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
        <thead :class="ui.thead">
          <tr>
            <th :class="ui.th">
              Match
            </th>
            <th :class="ui.th">
              Kind
            </th>
            <th :class="ui.th">
              Refs
            </th>
            <th :class="ui.th">
              Regimes
            </th>
            <th :class="ui.th">
              Priority
            </th>
            <th :class="ui.th">
              Due
            </th>
            <th
              v-if="!readonly"
              :class="ui.th"
            />
          </tr>
        </thead>
        <tbody class="divide-y divide-surface-border-subtle">
          <tr
            v-for="(rule, index) in modelValue"
            :key="index"
          >
            <template v-if="readonly">
              <td :class="[ui.td, 'font-mono text-xs text-gray-200']">
                {{ rule.match }}
              </td>
              <td :class="[ui.td, 'text-xs text-gray-300']">
                {{ rule.kind ? KIND_LABELS[rule.kind] : 'derived' }}
              </td>
              <td :class="[ui.td, 'font-mono text-xs text-gray-300']">
                {{ rule.refs?.length ? rule.refs.join(', ') : 'kind default' }}
              </td>
              <td :class="[ui.td, 'font-mono text-xs text-gray-300']">
                {{ rule.regimes?.length ? rule.regimes.join(', ') : 'internal' }}
              </td>
              <td :class="[ui.td, 'text-xs text-gray-300']">
                {{ rule.priority || 'P2' }}
              </td>
              <td :class="[ui.td, 'text-xs text-gray-300']">
                {{ rule.due || '—' }}
              </td>
            </template>
            <template v-else>
              <td :class="ui.td">
                <input
                  :value="rule.match"
                  type="text"
                  aria-label="Match"
                  :class="[ui.input, 'w-56 font-mono text-xs']"
                  placeholder="exploited:true"
                  @input="patch(index, { match: ($event.target as HTMLInputElement).value })"
                >
              </td>
              <td :class="ui.td">
                <select
                  :value="rule.kind || ''"
                  aria-label="Kind"
                  :class="[ui.input, 'text-xs']"
                  @change="patch(index, { kind: ($event.target as HTMLSelectElement).value as IncidentKind | '' })"
                >
                  <option value="">
                    Derived
                  </option>
                  <option
                    v-for="kind in INCIDENT_KINDS"
                    :key="kind"
                    :value="kind"
                    :title="KIND_DESCRIPTIONS[kind]"
                  >
                    {{ KIND_LABELS[kind] }}
                  </option>
                </select>
              </td>
              <td :class="ui.td">
                <input
                  :value="(rule.refs ?? []).join(', ')"
                  type="text"
                  aria-label="Refs"
                  :class="[ui.input, 'w-40 font-mono text-xs']"
                  placeholder="released, default"
                  @change="patch(index, { refs: splitList(($event.target as HTMLInputElement).value) })"
                >
              </td>
              <td :class="ui.td">
                <input
                  :value="(rule.regimes ?? []).join(', ')"
                  type="text"
                  aria-label="Regimes"
                  :class="[ui.input, 'w-40 font-mono text-xs']"
                  placeholder="cra-article-14"
                  @change="patch(index, { regimes: splitList(($event.target as HTMLInputElement).value) })"
                >
              </td>
              <td :class="ui.td">
                <select
                  :value="rule.priority || ''"
                  aria-label="Priority"
                  :class="[ui.input, 'text-xs']"
                  @change="patch(index, { priority: ($event.target as HTMLSelectElement).value as IncidentPriority | '' })"
                >
                  <option value="">
                    P2 (default)
                  </option>
                  <option
                    v-for="priority in PRIORITIES"
                    :key="priority"
                    :value="priority"
                  >
                    {{ priority }}
                  </option>
                </select>
              </td>
              <td :class="ui.td">
                <input
                  :value="rule.due || ''"
                  type="text"
                  aria-label="Due"
                  :class="[ui.input, 'w-16 text-xs']"
                  placeholder="7d"
                  @input="patch(index, { due: ($event.target as HTMLInputElement).value })"
                >
              </td>
              <td :class="[ui.td, 'whitespace-nowrap']">
                <button
                  type="button"
                  class="rounded-md p-1 text-gray-500 transition hover:text-gray-200 disabled:opacity-30"
                  aria-label="Move up"
                  :disabled="index === 0"
                  @click="move(index, -1)"
                >
                  <ChevronUp class="h-3.5 w-3.5" />
                </button>
                <button
                  type="button"
                  class="rounded-md p-1 text-gray-500 transition hover:text-gray-200 disabled:opacity-30"
                  aria-label="Move down"
                  :disabled="index === modelValue.length - 1"
                  @click="move(index, 1)"
                >
                  <ChevronDown class="h-3.5 w-3.5" />
                </button>
                <button
                  type="button"
                  class="rounded-md p-1 text-gray-500 transition hover:text-danger"
                  aria-label="Remove rule"
                  @click="remove(index)"
                >
                  <X class="h-3.5 w-3.5" />
                </button>
              </td>
            </template>
          </tr>
        </tbody>
      </table>
    </div>
    <button
      v-if="!readonly"
      type="button"
      class="mt-2 text-xs text-accent transition hover:underline"
      @click="add"
    >
      Add rule
    </button>
  </div>
</template>

<script setup lang="ts">
import { ChevronDown, ChevronUp, X } from 'lucide-vue-next'

import { INCIDENT_KINDS, KIND_DESCRIPTIONS, KIND_LABELS, type IncidentKind, type IncidentPriority, type IncidentRule } from '@/api/incidents'
import { ui } from '@/components/incidents/ui'
import { splitList } from '@/lib/incidentView'

// An ordered trigger rule list (first match wins). Refs and regimes are
// comma-separated and committed on change, so a trailing comma survives typing.
const props = withDefaults(defineProps<{
  modelValue: IncidentRule[]
  readonly?: boolean
  emptyText?: string
}>(), { readonly: false, emptyText: 'No rules.' })
const emit = defineEmits<{ 'update:modelValue': [rules: IncidentRule[]] }>()

const PRIORITIES: IncidentPriority[] = ['P1', 'P2', 'P3']

function patch(index: number, change: Partial<IncidentRule>) {
  emit('update:modelValue', props.modelValue.map((rule, position) => (position === index ? { ...rule, ...change } : rule)))
}

function move(index: number, delta: number) {
  const next = [...props.modelValue]
  const [rule] = next.splice(index, 1)
  next.splice(index + delta, 0, rule)
  emit('update:modelValue', next)
}

function remove(index: number) {
  emit('update:modelValue', props.modelValue.filter((_, position) => position !== index))
}

function add() {
  emit('update:modelValue', [...props.modelValue, { match: '' }])
}
</script>

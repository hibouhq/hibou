<template>
  <section :class="ui.card">
    <h2 :class="ui.heading">
      Timeline
    </h2>
    <p class="mt-1 text-xs text-gray-500">
      The register, newest first: every decision, scope change, action, delivery and approval, with its time and actor.
    </p>

    <form
      v-if="canNote"
      class="mt-3 space-y-2"
      @submit.prevent="addNote"
    >
      <label :class="ui.label">
        Add a note
        <textarea
          v-model="note"
          rows="2"
          :class="ui.textarea"
          placeholder="A call with the customer, an analysis result, …"
        />
      </label>
      <div class="flex items-center gap-3">
        <button
          type="submit"
          :class="ui.primary"
          :disabled="busy || !note.trim()"
        >
          Add note
        </button>
        <p
          v-if="error"
          class="text-sm text-danger"
        >
          {{ error }}
        </p>
      </div>
    </form>

    <ol
      v-if="events.length > 0"
      class="mt-4 space-y-3 border-l border-surface-border pl-4"
    >
      <li
        v-for="event in newestFirst"
        :key="event.id"
        class="relative"
      >
        <span class="absolute -left-[21px] top-1.5 h-2 w-2 rounded-full bg-surface-border" />
        <div class="flex flex-wrap items-baseline gap-x-2 text-sm">
          <span class="font-medium text-gray-100">{{ humanize(event.kind) }}</span>
          <span class="text-xs text-gray-400">{{ event.actor_display || event.actor_type }}</span>
          <DateTime
            :value="event.at"
            class="text-xs text-gray-500"
          />
        </div>
        <dl
          v-if="detailEntries(event.detail).length > 0"
          class="mt-0.5 space-y-0.5 text-xs"
        >
          <div
            v-for="[key, value] in detailEntries(event.detail)"
            :key="key"
            class="flex gap-1.5"
          >
            <dt class="shrink-0 text-gray-500">
              {{ key }}:
            </dt>
            <dd class="min-w-0 text-gray-300">
              <AutolinkedText
                :text="String(value)"
                :provider="provider"
                :slug="slug"
              />
            </dd>
          </div>
        </dl>
      </li>
    </ol>
    <p
      v-else
      class="mt-3 text-sm text-gray-500"
    >
      No events.
    </p>
  </section>
</template>

<script setup lang="ts">
import AutolinkedText from '@/components/incidents/AutolinkedText.vue'
import { computed, ref } from 'vue'

import { incidentsApi, type IncidentEvent } from '@/api/incidents'
import DateTime from '@/components/DateTime.vue'
import { ui } from '@/components/incidents/ui'
import { detailEntries, errorText, humanize } from '@/lib/incidentView'

const props = defineProps<{
  provider: string
  slug: string
  number: number
  events: IncidentEvent[]
  canNote: boolean
}>()
const emit = defineEmits<{ changed: [] }>()

const newestFirst = computed(() => [...props.events].sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime()))

const note = ref('')
const busy = ref(false)
const error = ref('')

async function addNote() {
  busy.value = true
  error.value = ''
  try {
    await incidentsApi.note(props.provider, props.slug, props.number, note.value.trim())
    note.value = ''
    emit('changed')
  } catch (noteError) {
    error.value = errorText(noteError, 'Failed to add the note')
  } finally {
    busy.value = false
  }
}
</script>

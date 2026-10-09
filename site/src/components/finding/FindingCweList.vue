<template>
  <FindingSection
    v-if="cwes.length > 0 || editable"
    title="Weakness (CWE)"
    :hint="hint"
  >
    <ul
      v-if="cwes.length > 0"
      class="space-y-2"
    >
      <li
        v-for="item in cwes"
        :key="item.id"
        class="flex items-start gap-2.5"
      >
        <a
          :href="mitreCWEUrl(item.id)"
          target="_blank"
          rel="noopener noreferrer"
          class="mt-px shrink-0 rounded border border-sky-500/30 bg-sky-500/10 px-1.5 py-px font-mono text-[11px] text-sky-200 transition hover:border-sky-400/60"
          :class="item.deprecated ? 'line-through decoration-gray-500' : ''"
          :title="`Open CWE-${item.id} on cwe.mitre.org`"
        >CWE-{{ item.id }}</a>
        <div class="min-w-0">
          <div class="text-sm text-gray-200">
            {{ item.name || 'Not in the CWE catalog' }}
          </div>
          <div class="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-gray-500">
            <span v-if="item.category">{{ item.category.name }}</span>
            <span
              v-for="set in displaySets(item.sets)"
              :key="set.slug"
              class="rounded-full bg-surface-overlay px-1.5 py-px text-gray-400"
            >{{ set.rank ? `${set.name} #${set.rank}` : set.name }}</span>
            <span v-if="item.deprecated">deprecated</span>
            <span class="text-gray-600">· {{ sourceLabel(item.source) }}</span>
          </div>
        </div>
      </li>
    </ul>
    <p
      v-else
      class="text-sm text-gray-500"
    >
      No CWE declared.
    </p>

    <!-- Manual findings (human or agent) carry the CWEs their author declares;
         scanner findings take theirs from the rule or advisory. -->
    <form
      v-if="editable"
      class="mt-3 flex items-center gap-2"
      @submit.prevent="save"
    >
      <input
        v-model="draft"
        type="text"
        spellcheck="false"
        placeholder="CWE-89, CWE-78"
        aria-label="Declared CWEs"
        class="min-w-0 flex-1 rounded-md border border-surface-border bg-surface-overlay px-2 py-1 font-mono text-xs text-gray-200 placeholder:text-gray-600 focus:border-accent focus:outline-none"
      >
      <button
        type="submit"
        class="rounded-md border border-surface-border px-2.5 py-1 text-xs text-gray-300 transition hover:border-accent/50 hover:text-white disabled:opacity-50"
        :disabled="saving || !dirty"
      >
        {{ saving ? 'Saving…' : 'Save' }}
      </button>
    </form>
    <p
      v-if="error"
      class="mt-1 text-xs text-amber-300"
    >
      {{ error }}
    </p>
  </FindingSection>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { api, type FindingCWE, type FindingCWESource, type Vulnerability } from '@/api/client'
import FindingSection from '@/components/finding/FindingSection.vue'
import { displaySets, mitreCWEUrl } from '@/lib/cweCatalog'

const props = defineProps<{
  finding: Vulnerability
  provider?: string
  slug?: string
  repoSlug?: string
}>()

const emit = defineEmits<{
  (event: 'updated', cwes: FindingCWE[]): void
}>()

const cwes = computed(() => props.finding.cwes ?? [])
const editable = computed(() => props.finding.type === 'manual' && Boolean(props.provider && props.slug && props.repoSlug))
const hint = computed(() => (cwes.value.length > 1 ? `${cwes.value.length} CWEs` : undefined))

const draft = ref('')
const saving = ref(false)
const error = ref('')
const initial = computed(() => cwes.value.filter(item => item.source === 'declared').map(item => `CWE-${item.id}`).join(', '))
const dirty = computed(() => draft.value.trim() !== initial.value)
watch(initial, value => { draft.value = value }, { immediate: true })

function sourceLabel(source: FindingCWESource): string {
  switch (source) {
    case 'rule': return 'from the scanner rule'
    case 'advisory': return 'from the advisory'
    case 'sarif_result': return 'reported for this occurrence'
    case 'declared': return 'declared by the author'
    case 'type': return 'leaked secrets are CWE-798'
    default: return source
  }
}

async function save() {
  if (!props.provider || !props.slug || !props.repoSlug) return
  saving.value = true
  error.value = ''
  try {
    const values = draft.value.split(/[\s,]+/).map(value => value.trim()).filter(Boolean)
    const res = await api.setFindingCWEs(props.provider, props.slug, props.repoSlug, props.finding.fingerprint, values)
    emit('updated', res.data.cwes ?? [])
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : 'Could not save the CWEs'
  } finally {
    saving.value = false
  }
}
</script>

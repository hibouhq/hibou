<template>
  <a
    v-if="url"
    :href="url"
    target="_blank"
    rel="noopener noreferrer"
    class="font-mono text-gray-500 underline decoration-transparent underline-offset-2 transition hover:text-gray-300 hover:decoration-gray-500"
    :title="`${sha} — open the commit in ${forgeLabel(provider ?? 'github')}`"
    @click.stop
  >{{ short }}</a>
  <span
    v-else
    class="font-mono text-gray-600"
    :title="sha"
  >{{ short }}</span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

import { forgeCommitUrl, forgeLabel } from '@/lib/forgeLinks'

// An abbreviated sha that goes to the commit when the repository's forge URL is
// known, and stays plain text when it is not — a dead link is worse than none.
const props = defineProps<{
  sha: string
  repoHtmlUrl?: string
  provider?: string
}>()

const short = computed(() => (props.sha ?? '').slice(0, 7))
const url = computed(() => forgeCommitUrl(props.repoHtmlUrl, props.provider ?? 'github', props.sha ?? ''))
</script>

<template>
  <span class="whitespace-pre-wrap break-words"><template
    v-for="(segment, index) in segments"
    :key="index"
  ><a
    v-if="segment.kind === 'link'"
    :href="segment.href"
    target="_blank"
    rel="noopener noreferrer"
    class="text-accent underline decoration-accent/40 underline-offset-2 transition hover:decoration-accent"
    @click.stop
  >{{ segment.text }}</a><template v-else>{{ segment.text }}</template></template></span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

import { useAutolinks } from '@/composables/useAutolinks'
import { autolinkSegments } from '@/lib/autolink'

// Free text people wrote (notes, reasons, references) with the
// organisation's autolink references and bare URLs turned into links.
const props = defineProps<{
  text: string
  provider: string
  slug: string
}>()

const autolinks = useAutolinks(props.provider, props.slug)
const segments = computed(() => autolinkSegments(props.text, autolinks.value))
</script>

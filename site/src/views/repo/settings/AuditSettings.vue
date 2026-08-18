<template>
  <AuditLogPanel
    :provider="provider"
    :slug="slug"
    :repo="repoSlug"
  />
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'

import AuditLogPanel from '@/components/AuditLogPanel.vue'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)
</script>

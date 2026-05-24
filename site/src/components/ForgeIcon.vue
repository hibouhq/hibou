<template>
  <span
    class="inline-flex items-center justify-center"
    :class="sizeClass"
    :title="label"
  >
    <!-- GitHub -->
    <svg v-if="normalized === 'github'" viewBox="0 0 16 16" fill="currentColor" class="h-full w-full">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
    </svg>

    <!-- GitLab -->
    <svg v-else-if="normalized === 'gitlab'" viewBox="0 0 16 16" fill="currentColor" class="h-full w-full">
      <path d="M8 14.932L10.37 8.3H5.63L8 14.932z" fill="#E24329" />
      <path d="M8 14.932L5.63 8.3H1.09L8 14.932z" fill="#FC6D26" />
      <path d="M1.09 8.3L.22 10.97c-.08.24.01.5.22.64L8 14.932 1.09 8.3z" fill="#FCA326" />
      <path d="M1.09 8.3h4.54L3.56 2.04c-.09-.27-.47-.27-.56 0L1.09 8.3z" fill="#E24329" />
      <path d="M8 14.932L10.37 8.3h4.54L8 14.932z" fill="#FC6D26" />
      <path d="M14.91 8.3l.87 2.67c.08.24-.01.5-.22.64L8 14.932 14.91 8.3z" fill="#FCA326" />
      <path d="M14.91 8.3h-4.54l2.07-6.26c.09-.27.47-.27.56 0L14.91 8.3z" fill="#E24329" />
    </svg>

    <!-- Forgejo / Gitea -->
    <svg v-else-if="normalized === 'forgejo' || normalized === 'gitea'" viewBox="0 0 16 16" fill="currentColor" class="h-full w-full">
      <path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 1.5a5.5 5.5 0 110 11 5.5 5.5 0 010-11zM5.75 6a.75.75 0 100 1.5.75.75 0 000-1.5zm4.5 0a.75.75 0 100 1.5.75.75 0 000-1.5zM5.25 9.5a.5.5 0 00-.4.8A3.49 3.49 0 008 11.5a3.49 3.49 0 003.15-1.2.5.5 0 00-.4-.8h-5.5z" fill="#68A357" />
    </svg>

    <!-- Fallback -->
    <svg v-else viewBox="0 0 16 16" fill="currentColor" class="h-full w-full text-gray-500">
      <path d="M2 2.5A2.5 2.5 0 014.5 0h8.75a.75.75 0 01.75.75v12.5a.75.75 0 01-.75.75h-2.5a.75.75 0 110-1.5h1.75v-2h-8a1 1 0 00-.714 1.7.75.75 0 01-1.072 1.05A2.495 2.495 0 012 11.5v-9zm10.5-1h-8a1 1 0 00-1 1v6.708A2.486 2.486 0 014.5 9h8V1.5z" />
    </svg>
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  provider: string
  size?: 'sm' | 'md' | 'lg'
}>(), {
  size: 'md',
})

const normalized = computed(() => {
  const raw = props.provider?.toLowerCase().replace(/\s+/g, '') || ''
  if (raw.includes('github')) return 'github'
  if (raw.includes('gitlab')) return 'gitlab'
  if (raw.includes('forgejo')) return 'forgejo'
  if (raw.includes('gitea')) return 'gitea'
  return raw
})

const label = computed(() => {
  switch (normalized.value) {
    case 'github': return 'GitHub'
    case 'gitlab': return 'GitLab'
    case 'forgejo': return 'Forgejo'
    case 'gitea': return 'Gitea'
    default: return props.provider || 'Unknown'
  }
})

const sizeClass = computed(() => {
  switch (props.size) {
    case 'sm': return 'h-3.5 w-3.5'
    case 'lg': return 'h-5 w-5'
    default: return 'h-4 w-4'
  }
})
</script>

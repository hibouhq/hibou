<template>
  <div class="flex min-h-screen items-center justify-center bg-gray-950">
    <div class="w-full max-w-sm rounded-lg border border-gray-800 bg-gray-900 p-8">
      <h1 class="mb-6 text-center text-2xl font-bold text-gray-100">
        Hibou
      </h1>
      <p class="mb-6 text-center text-sm text-gray-400">
        Sign in to continue
      </p>
      <div
        v-if="signInError"
        role="alert"
        class="mb-6 rounded-md border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-200"
      >
        <p class="font-medium">
          {{ signInError.title }}
        </p>
        <p class="mt-1 text-red-300/80">
          {{ signInError.detail }}
        </p>
      </div>
      <div class="space-y-3">
        <a
          v-for="provider in providers"
          :key="provider.id"
          :href="`/api/v1/auth/login?provider=${provider.id}`"
          class="flex w-full items-center justify-center rounded-md border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-gray-200 transition-colors hover:bg-gray-700"
        >
          Sign in with {{ provider.name }}
        </a>
        <form
          v-if="providers.length === 0"
          method="POST"
          action="/api/v1/auth/dev-login"
        >
          <button
            type="submit"
            class="flex w-full items-center justify-center rounded-md border border-amber-700 bg-amber-900/30 px-4 py-2 text-sm text-amber-200 transition-colors hover:bg-amber-800/40"
          >
            Dev Login (no OAuth configured)
          </button>
          <p class="mt-2 text-center text-xs text-gray-600">
            Creates a local admin user for development.
          </p>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { api, type AuthProvider } from '@/api/client'

const providers = ref<AuthProvider[]>([])
const route = useRoute()

// The OAuth callback sends a failed sign-in back here with a fixed code. Only
// known codes map to text; nothing from the URL is ever rendered.
const signInErrors: Record<string, { title: string; detail: string }> = {
  not_allowed: {
    title: 'This account is not allowed to sign in here.',
    detail: 'Sign-in on this instance is limited to approved users and organizations. Ask an administrator for access.',
  },
  sign_in_failed: {
    title: 'Sign-in failed.',
    detail: 'Please try again. If it keeps failing, contact an administrator.',
  },
}

const signInError = computed(() => {
  const code = route.query.error
  return typeof code === 'string' ? signInErrors[code] ?? null : null
})

onMounted(async () => {
  try {
    const res = await api.getProviders()
    providers.value = res.data || []
  } catch {
    providers.value = []
  }
})
</script>
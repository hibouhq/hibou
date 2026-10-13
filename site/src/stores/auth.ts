import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

import { api, type User } from '@/api/client'
import { resetSearchPresets } from '@/composables/useSearchPresets'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const loading = ref(true)
  const isAuthenticated = computed(() => !!user.value)
  // Cosmetic gate only — the server re-checks instance admin on every request.
  const isInstanceAdmin = computed(() => user.value?.is_instance_admin === true)

  async function fetchUser() {
    loading.value = true
    try {
      const res = await api.getMe()
      user.value = res.data
    } catch {
      user.value = null
    } finally {
      loading.value = false
    }
  }

  // Throws when the server refused: the user stays signed in, so the caller
  // must not present the logout as done.
  async function logout() {
    await api.logout()
    user.value = null
    resetSearchPresets()
  }

  return { user, loading, isAuthenticated, isInstanceAdmin, fetchUser, logout }
})
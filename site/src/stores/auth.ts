import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

import { api, type User } from '@/api/client'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const loading = ref(true)
  const isAuthenticated = computed(() => !!user.value)

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

  async function logout() {
    await api.logout()
    user.value = null
  }

  return { user, loading, isAuthenticated, fetchUser, logout }
})
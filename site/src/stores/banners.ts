import { defineStore } from 'pinia'
import { ref } from 'vue'

import { api, type AnnouncementBanner } from '@/api/client'

// Instance-wide announcement banners. Loaded once over HTTP (public endpoint,
// works on the login page too) and then kept live by `banner.updated`
// WebSocket broadcasts — recorded by the notifications store, which owns the
// app's single WS — so no HTTP polling is involved.
export const useBannersStore = defineStore('banners', () => {
  const activeBanners = ref<AnnouncementBanner[]>([])
  let hasFetched = false

  async function fetch() {
    if (hasFetched) {
      return
    }
    hasFetched = true
    try {
      const response = await api.getActiveBanners()
      activeBanners.value = response.data ?? []
    } catch {
      activeBanners.value = []
    }
  }

  // The broadcast payload IS the new active set — replace, don't merge.
  function record(payload: AnnouncementBanner[]) {
    hasFetched = true
    activeBanners.value = Array.isArray(payload) ? payload : []
  }

  return { activeBanners, fetch, record }
})

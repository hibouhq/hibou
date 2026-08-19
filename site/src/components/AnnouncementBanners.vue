<template>
  <div
    v-if="banners.length > 0"
    ref="container"
    class="fixed inset-x-0 top-0 z-50"
  >
    <div
      v-for="banner in banners"
      :key="banner.id"
      class="flex items-center justify-center gap-2 px-4 py-1.5 text-center text-sm font-medium"
      :style="{ backgroundColor: banner.background_color, color: readableTextColor(banner.background_color) }"
    >
      <Megaphone class="h-3.5 w-3.5 shrink-0 opacity-80" />
      <span>{{ banner.message }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Megaphone } from 'lucide-vue-next'
import { storeToRefs } from 'pinia'
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'

import { readableTextColor } from '@/lib/color'
import { useBannersStore } from '@/stores/banners'

// One HTTP fetch on mount (works on the login page); afterwards the list stays
// live via `banner.updated` WebSocket broadcasts — no polling.
const bannersStore = useBannersStore()
const { activeBanners: banners } = storeToRefs(bannersStore)
const container = ref<HTMLElement | null>(null)

// The app header is `fixed top-0`; the banner stack pushes it (and the page
// content) down through this CSS variable instead of reflowing the layout.
let observer: ResizeObserver | null = null

function publishHeight() {
  const height = container.value?.offsetHeight ?? 0
  document.documentElement.style.setProperty('--app-banner-height', `${height}px`)
}

watch(
  [banners, container],
  () => {
    observer?.disconnect()
    if (container.value) {
      observer = new ResizeObserver(publishHeight)
      observer.observe(container.value)
    }
    publishHeight()
  },
  { flush: 'post' },
)

onMounted(() => {
  void bannersStore.fetch()
})

onBeforeUnmount(() => {
  observer?.disconnect()
  document.documentElement.style.setProperty('--app-banner-height', '0px')
})
</script>

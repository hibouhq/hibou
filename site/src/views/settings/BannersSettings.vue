<template>
  <div class="space-y-5">
    <div>
      <h2 class="text-lg font-semibold text-white">
        Announcement banners
      </h2>
      <p class="mt-1 text-sm text-gray-400">
        Instance-wide banners shown at the top of every page, including the login page.
      </p>
    </div>

    <div
      v-if="loadError"
      class="rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
    >
      {{ loadError }}
    </div>

    <template v-else>
      <div
        v-if="loading"
        class="py-6 text-sm text-gray-500"
      >
        Loading banners…
      </div>

      <template v-else>
        <div
          v-if="banners.length === 0"
          class="rounded-md border border-dashed border-surface-border px-6 py-8 text-center text-sm text-gray-500"
        >
          No banners configured.
        </div>

        <section
          v-for="(banner, index) in banners"
          :key="banner.id || `new-${index}`"
          class="space-y-3 rounded-md border border-surface-border bg-surface-raised p-4"
        >
          <!-- Live preview -->
          <div
            class="flex items-center justify-center gap-2 rounded-md px-4 py-1.5 text-center text-sm font-medium"
            :style="{ backgroundColor: previewColor(banner), color: readableTextColor(previewColor(banner)) }"
          >
            <Megaphone class="h-3.5 w-3.5 shrink-0 opacity-80" />
            <span>{{ banner.message || 'Banner message preview' }}</span>
          </div>

          <div class="flex flex-col gap-3 sm:flex-row sm:items-end">
            <div class="flex min-w-0 flex-1 flex-col gap-1.5">
              <label
                class="text-xs font-medium text-gray-300"
                :for="`banner-message-${index}`"
              >Message</label>
              <input
                :id="`banner-message-${index}`"
                v-model="banner.message"
                class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
                type="text"
                maxlength="500"
                placeholder="Scheduled maintenance on Saturday 02:00–04:00 UTC"
              >
            </div>

            <div class="flex flex-col gap-1.5">
              <span class="text-xs font-medium text-gray-300">Background</span>
              <div class="flex items-center gap-1.5">
                <button
                  v-for="swatch in SWATCHES"
                  :key="swatch"
                  type="button"
                  class="h-6 w-6 rounded-full border transition"
                  :class="banner.background_color === swatch ? 'border-white' : 'border-surface-border hover:border-gray-400'"
                  :style="{ backgroundColor: swatch }"
                  :aria-label="`Use color ${swatch}`"
                  @click="banner.background_color = swatch"
                />
                <input
                  v-model="banner.background_color"
                  class="h-8 w-24 rounded-md border border-surface-border bg-surface-overlay px-2 font-mono text-xs text-gray-200 focus:border-accent/50 focus:outline-none"
                  type="text"
                  placeholder="#004852"
                  aria-label="Background color hex"
                >
              </div>
            </div>

            <label class="flex h-8 items-center gap-2 text-sm text-gray-300">
              <input
                v-model="banner.enabled"
                type="checkbox"
                class="h-3.5 w-3.5 rounded border-surface-border bg-surface-overlay accent-[--color-accent]"
              >
              Enabled
            </label>

            <button
              type="button"
              class="inline-flex h-8 items-center gap-1.5 rounded-md border border-surface-border px-2.5 text-xs text-gray-400 transition hover:border-danger/50 hover:text-danger"
              @click="removeBanner(index)"
            >
              <Trash2 class="h-3.5 w-3.5" />
              Remove
            </button>
          </div>
        </section>

        <div class="flex items-center gap-3">
          <button
            type="button"
            class="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-200 transition hover:border-accent/50 hover:text-white"
            :disabled="banners.length >= 10"
            @click="addBanner"
          >
            <Plus class="h-3.5 w-3.5" />
            Add banner
          </button>
          <button
            type="button"
            class="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="saving"
            @click="save"
          >
            {{ saving ? 'Saving…' : 'Save banners' }}
          </button>
          <p
            v-if="saveError"
            class="text-sm text-danger"
          >
            {{ saveError }}
          </p>
        </div>
      </template>
    </template>
  </div>
</template>

<script setup lang="ts">
import { Megaphone, Plus, Trash2 } from 'lucide-vue-next'
import { onMounted, ref } from 'vue'

import { api, type AnnouncementBanner } from '@/api/client'
import { useToast } from '@/composables/useToast'
import { readableTextColor } from '@/lib/color'

const SWATCHES = ['#004852', '#1d4ed8', '#7c3aed', '#b45309', '#b91c1c', '#166534']

const { pushToast } = useToast()

const banners = ref<AnnouncementBanner[]>([])
const loading = ref(true)
const loadError = ref('')
const saving = ref(false)
const saveError = ref('')

onMounted(async () => {
  try {
    const response = await api.getBannerSettings()
    banners.value = response.data ?? []
  } catch (error) {
    loadError.value = error instanceof Error ? error.message : 'Failed to load banners'
  } finally {
    loading.value = false
  }
})

function previewColor(banner: AnnouncementBanner) {
  return /^#[0-9a-f]{6}$/i.test(banner.background_color.trim()) ? banner.background_color.trim() : '#004852'
}

function addBanner() {
  banners.value.push({ id: '', message: '', background_color: SWATCHES[0], enabled: true })
}

function removeBanner(index: number) {
  banners.value.splice(index, 1)
}

async function save() {
  saveError.value = ''
  saving.value = true
  try {
    const response = await api.updateBannerSettings(banners.value)
    banners.value = response.data ?? []
    pushToast({ title: 'Banners saved', tone: 'success' })
  } catch (error) {
    saveError.value = error instanceof Error ? error.message : 'Failed to save banners'
  } finally {
    saving.value = false
  }
}
</script>

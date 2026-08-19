<template>
  <AnnouncementBanners />
  <RouterView />
  <ToastViewport />
  <DialogHost />
</template>

<script setup lang="ts">
import { RouterView } from 'vue-router'

import AnnouncementBanners from '@/components/AnnouncementBanners.vue'
import DialogHost from '@/components/DialogHost.vue'
import ToastViewport from '@/components/ToastViewport.vue'
</script>
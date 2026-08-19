<template>
  <RouterView />
  <ToastViewport />
  <DialogHost />
</template>

<script setup lang="ts">
import { RouterView } from 'vue-router'

import DialogHost from '@/components/DialogHost.vue'
import ToastViewport from '@/components/ToastViewport.vue'
</script>
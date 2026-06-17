<template>
  <RouterView />
  <ToastViewport />
</template>

<script setup lang="ts">
import { RouterView } from 'vue-router'

import ToastViewport from '@/components/ToastViewport.vue'
</script>
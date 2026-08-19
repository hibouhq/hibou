<template>
  <div class="space-y-5">
    <div>
      <h2 class="text-lg font-semibold text-white">
        Instance audit log
      </h2>
      <p class="mt-1 text-sm text-gray-400">
        Every recorded action across the instance: all organizations plus instance-level events (banner changes, administrator grants and revocations).
      </p>
    </div>

    <AuditLogPanel instance />
  </div>
</template>

<script setup lang="ts">
import AuditLogPanel from '@/components/AuditLogPanel.vue'
</script>

<template>
  <SettingsLayout
    :groups="groups"
    :is-admin="canViewAudit"
  />
</template>

<script setup lang="ts">
import { FileCog, ScrollText, Settings2 } from 'lucide-vue-next'
import type { Ref } from 'vue'
import { computed, inject, ref } from 'vue'

import type { Repository } from '@/api/client'
import SettingsLayout, { type SettingsNavGroup } from '@/components/settings/SettingsLayout.vue'
import { useOrgRole } from '@/composables/useOrgRole'

const { isOrgAdmin } = useOrgRole()
const repo = inject<Ref<Repository | null>>('repo', ref(null))

// Org admins and owning-team admins may open the repo audit log; the server
// reports the combined verdict on the repo detail (viewer_can_audit).
const canViewAudit = computed(() => isOrgAdmin.value || Boolean(repo.value?.viewer_can_audit))

const groups: SettingsNavGroup[] = [
  {
    items: [
      { label: 'General', icon: Settings2, name: 'repo-settings-general' },
      { label: 'Configuration', icon: FileCog, name: 'repo-settings-config' },
      { label: 'Audit log', icon: ScrollText, name: 'repo-settings-audit', adminOnly: true },
    ],
  },
]
</script>

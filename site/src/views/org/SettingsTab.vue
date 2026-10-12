<template>
  <SettingsLayout
    :groups="groups"
    :is-admin="isOrgAdmin"
  />
</template>

<script setup lang="ts">
import { Bell, GitPullRequestArrow, KeyRound, Plug, Radar, Scale, ScrollText, Settings2, ShieldCheck, Users } from 'lucide-vue-next'

import SettingsLayout, { type SettingsNavGroup } from '@/components/settings/SettingsLayout.vue'
import { useOrgRole } from '@/composables/useOrgRole'

const { isOrgAdmin } = useOrgRole()

const groups: SettingsNavGroup[] = [
  {
    items: [
      { label: 'General', icon: Settings2, name: 'org-settings-general' },
    ],
  },
  {
    title: 'Access',
    items: [
      { label: 'Members', icon: Users, name: 'org-settings-members' },
      { label: 'API tokens', icon: KeyRound, name: 'org-settings-access' },
    ],
  },
  {
    title: 'Scanning & alerts',
    items: [
      { label: 'Quality gates', icon: GitPullRequestArrow, name: 'org-settings-gates' },
      { label: 'License policy', icon: Scale, name: 'org-settings-license-policy' },
      { label: 'Tools', icon: Radar, name: 'org-settings-tools' },
      { label: 'Scanner requirements', icon: ShieldCheck, name: 'org-settings-scanner-requirements' },
      { label: 'Integrations', icon: Plug, name: 'org-settings-integrations' },
      { label: 'Notifications', icon: Bell, name: 'org-settings-notifications' },
    ],
  },
  {
    title: 'Archive',
    items: [
      { label: 'Audit log', icon: ScrollText, name: 'org-settings-audit', adminOnly: true },
    ],
  },
]
</script>

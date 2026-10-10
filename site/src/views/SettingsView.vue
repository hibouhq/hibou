<template>
  <div class="mx-auto w-full max-w-6xl">
    <h1 class="mb-6 text-2xl font-bold text-white">
      Settings
    </h1>

    <div class="flex flex-col gap-6 lg:flex-row">
      <nav class="lg:w-56 lg:shrink-0">
        <div
          v-for="group in nav"
          :key="group.title"
          class="mb-5"
        >
          <div class="px-3 pb-1.5 text-[11px] font-semibold uppercase tracking-wide text-gray-500">
            {{ group.title }}
          </div>
          <ul class="space-y-0.5">
            <li
              v-for="item in group.items"
              :key="item.label"
            >
              <RouterLink
                v-if="item.name"
                :to="{ name: item.name }"
                class="flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition"
                :class="item.name === route.name ? 'bg-accent-muted text-white' : 'text-gray-300 hover:bg-surface-raised hover:text-white'"
              >
                <component
                  :is="item.icon"
                  class="h-4 w-4 shrink-0"
                />
                {{ item.label }}
              </RouterLink>
              <span
                v-else
                class="flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm text-gray-600"
                title="Coming soon"
              >
                <component
                  :is="item.icon"
                  class="h-4 w-4 shrink-0"
                />
                {{ item.label }}
                <span class="ml-auto rounded-full border border-surface-border-subtle px-1.5 py-0.5 text-[9px] uppercase tracking-wide">soon</span>
              </span>
            </li>
          </ul>
        </div>
      </nav>

      <div class="min-w-0 flex-1">
        <RouterView />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { Component } from 'vue'
import { Activity, HardDrive, History, KeyRound, Megaphone, Radar, ScrollText, ShieldCheck, User, UsersRound } from 'lucide-vue-next'
import { computed } from 'vue'
import { RouterLink, RouterView, useRoute } from 'vue-router'

import { useAuthStore } from '@/stores/auth'

interface NavItem {
  label: string
  icon: Component
  name?: string
}

const route = useRoute()
const auth = useAuthStore()

const nav = computed<{ title: string; items: NavItem[] }[]>(() => {
  const groups: { title: string; items: NavItem[] }[] = [
    {
      title: 'Personal',
      items: [
        { label: 'API keys', icon: KeyRound, name: 'settings-api-keys' },
        { label: 'Profile', icon: User },
      ],
    },
  ]
  // Instance-level settings: visible only to instance admins
  // (HIBOU_INSTANCE_ADMINS); the server enforces regardless.
  if (auth.isInstanceAdmin) {
    groups.push({
      title: 'Instance',
      items: [
        { label: 'Announcement banners', icon: Megaphone, name: 'settings-banners' },
        { label: 'Administrators', icon: ShieldCheck, name: 'settings-instance-admins' },
        { label: 'Audit log', icon: ScrollText, name: 'settings-instance-audit' },
        { label: 'Jobs & workers', icon: Activity, name: 'settings-instance-jobs' },
        { label: 'Storage', icon: HardDrive, name: 'settings-instance-storage' },
        { label: 'People', icon: UsersRound, name: 'settings-instance-people' },
        { label: 'Advisories', icon: History, name: 'settings-instance-advisories' },
        { label: 'Watches', icon: Radar, name: 'settings-instance-watches' },
      ],
    })
  }
  return groups
})
// Org-scoped settings (members, integrations, notifications, gates) live under
// each organization's Settings tab, not here.
</script>

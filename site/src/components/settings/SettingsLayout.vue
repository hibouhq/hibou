<template>
  <div class="flex flex-col gap-6 lg:flex-row">
    <nav
      class="lg:w-56 lg:shrink-0"
      aria-label="Settings sections"
    >
      <template
        v-for="group in visibleGroups"
        :key="group.title || 'default'"
      >
        <div
          v-if="group.title"
          class="px-3 pb-1 pt-4 text-xs font-semibold text-gray-500 first:pt-0"
        >
          {{ group.title }}
        </div>
        <ul class="space-y-0.5">
          <li
            v-for="item in group.items"
            :key="item.name"
          >
            <RouterLink
              :to="{ name: item.name, params: route.params }"
              class="relative flex items-center gap-2.5 rounded-md px-3 py-1.5 text-sm transition"
              :class="route.name === item.name
                ? 'bg-surface-overlay font-medium text-white before:absolute before:-left-px before:top-1/2 before:h-5 before:w-[3px] before:-translate-y-1/2 before:rounded-full before:bg-accent'
                : 'text-gray-300 hover:bg-surface-raised hover:text-white'"
            >
              <component
                :is="item.icon"
                class="h-4 w-4 shrink-0 text-gray-500"
              />
              {{ item.label }}
            </RouterLink>
          </li>
        </ul>
      </template>
    </nav>

    <div class="min-w-0 flex-1">
      <RouterView />
    </div>
  </div>
</template>

<script setup lang="ts">
import type { Component } from 'vue'
import { computed } from 'vue'
import { RouterLink, RouterView, useRoute } from 'vue-router'

export interface SettingsNavItem {
  label: string
  icon: Component
  // Route name; params are inherited from the current route.
  name: string
  // Item is only rendered for org admins.
  adminOnly?: boolean
}

export interface SettingsNavGroup {
  title?: string
  items: SettingsNavItem[]
}

const props = defineProps<{
  groups: SettingsNavGroup[]
  isAdmin: boolean
}>()

const route = useRoute()

const visibleGroups = computed(() => props.groups
  .map((group) => ({
    ...group,
    items: group.items.filter((item) => !item.adminOnly || props.isAdmin),
  }))
  .filter((group) => group.items.length > 0))
</script>

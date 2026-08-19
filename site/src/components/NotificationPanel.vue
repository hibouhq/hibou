<template>
  <div class="absolute right-0 top-[calc(100%+0.5rem)] z-50 w-[22rem] max-w-[calc(100vw-2rem)] overflow-hidden rounded-xl border border-surface-border bg-surface-overlay shadow-2xl">
    <div class="flex items-center justify-between border-b border-surface-border-subtle px-4 py-2.5">
      <h3 class="text-sm font-semibold text-white">
        Notifications
      </h3>
      <button
        v-if="store.unreadCount > 0"
        type="button"
        class="text-xs font-medium text-accent transition hover:text-accent-hover"
        @click="store.markAllRead()"
      >
        Mark all read
      </button>
    </div>

    <div class="max-h-[26rem] overflow-y-auto">
      <div
        v-if="store.loading && store.items.length === 0"
        class="px-4 py-10 text-center text-sm text-gray-500"
      >
        Loading...
      </div>
      <div
        v-else-if="store.items.length === 0"
        class="flex flex-col items-center gap-2 px-4 py-12 text-center"
      >
        <Bell class="h-7 w-7 text-gray-600" />
        <p class="text-sm text-gray-400">
          You're all caught up
        </p>
        <p class="text-xs text-gray-600">
          No notifications yet.
        </p>
      </div>

      <ul
        v-else
        class="divide-y divide-surface-border-subtle"
      >
        <li
          v-for="item in store.items"
          :key="item.id"
        >
          <button
            type="button"
            class="flex w-full items-start gap-3 px-4 py-3 text-left transition hover:bg-white/5"
            :class="rowClass(item)"
            @click="select(item)"
          >
            <span
              class="mt-1.5 h-2 w-2 shrink-0 rounded-full"
              :class="severityDot(item.severity, item.status)"
            />
            <span class="min-w-0 flex-1">
              <span
                class="block truncate text-sm"
                :class="item.status === 'unread' ? 'font-semibold text-white' : 'text-gray-300'"
              >{{ item.title }}</span>
              <span class="mt-0.5 block line-clamp-2 text-xs text-gray-500">{{ item.body }}</span>
              <span class="mt-1 block text-[11px] text-gray-600">{{ relativeTime(item.created_at) }}</span>
            </span>
          </button>
        </li>
      </ul>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Bell } from 'lucide-vue-next'
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'

import type { Notification } from '@/api/client'
import { useNotificationsStore } from '@/stores/notifications'
import { relativeTime } from '@/lib/datetime'

const emit = defineEmits<{ (event: 'close'): void }>()

const store = useNotificationsStore()
const router = useRouter()

onMounted(() => {
  void store.fetchItems()
})

function select(item: Notification) {
  void store.markRead(item.id)
  emit('close')
  if (item.link && item.link.startsWith('/')) {
    // Backend links are forge-relative (e.g. /repos/<uuid>); push best-effort.
    void router.push(item.link).catch(() => undefined)
  }
}

// Critical notifications (malware, at minimum) get a red-tinted row, not just
// a dot — priority must survive a flooded inbox.
function rowClass(item: Notification): string {
  if (item.status === 'unread' && (item.severity || '').toLowerCase() === 'critical') {
    return 'border-l-2 border-l-danger bg-danger/10'
  }
  return item.status === 'unread' ? 'border-l-2 border-l-accent bg-accent/[0.04]' : 'border-l-2 border-l-transparent'
}

function severityDot(severity: string | undefined, status: string): string {
  if (status === 'read') {
    return 'bg-gray-600'
  }
  switch ((severity || '').toLowerCase()) {
    case 'critical':
      return 'bg-sev-critical'
    case 'high':
      return 'bg-sev-high'
    case 'medium':
      return 'bg-sev-medium'
    case 'low':
      return 'bg-sev-low'
    default:
      return 'bg-accent'
  }
}
</script>
